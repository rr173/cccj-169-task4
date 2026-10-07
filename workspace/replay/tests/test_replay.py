"""End-to-end invariant tests for the event-replay / risk-disposition service.

Run:  python3 -m unittest tests.test_replay -v
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import guards  # noqa: E402
from app import db as dbmod  # noqa: E402
from app.clock import fit_clock  # noqa: E402
from app.core import ApiError, canonical, sha256_text  # noqa: E402

# 测试用设备时钟：device_ts = 120 + 1.0002 * (server_ts - S0)
S0 = 1_700_000_000.0
OFFSET_TRUE = 120.0
DRIFT = 1.0002  # +200ppm 快钟


def dev_ts(server_ts: float) -> float:
    return OFFSET_TRUE + DRIFT * (server_ts - S0)


def make_events(*, with_anomalies=True, n=120, step=5.0, uid_prefix="e"):
    """构造一批确定性事件：sync 对时 + temp/pressure/material 三路遥测。"""
    events = []
    seq = 0
    # 对时点：每 60s 一个
    t = S0
    while t < S0 + n * step:
        events.append({"uid": f"{uid_prefix}-sync-{seq}", "seq": seq,
                       "ts": dev_ts(t), "kind": "sync", "server_ts": t})
        seq += 1
        t += 60.0
    for i in range(n):
        t = S0 + i * step
        # 缺失区间：跳过 i in [60, 96)（约 3 分钟无数据）
        if with_anomalies and 60 <= i < 96:
            continue
        temp = 235.0
        # 连续超限：i in [20, 25) 五个点全部 > 250°C
        if with_anomalies and 20 <= i < 25:
            temp = 252.0 + i
        events.append({"uid": f"{uid_prefix}-t{i}", "seq": seq,
                       "ts": dev_ts(t), "kind": "temp", "value": temp})
        seq += 1
        events.append({"uid": f"{uid_prefix}-p{i}", "seq": seq,
                       "ts": dev_ts(t), "kind": "pressure", "value": 5.5})
        seq += 1
        material = i * 0.4
        # 计量跳变：i==100 突增 80g；i==110 回退 30g
        if with_anomalies and i == 100:
            material += 80.0
        if with_anomalies and i >= 100:
            material += 80.0
        if with_anomalies and i == 110:
            material -= 30.0
        if with_anomalies and i >= 110:
            material -= 30.0
        events.append({"uid": f"{uid_prefix}-m{i}", "seq": seq,
                       "ts": dev_ts(t), "kind": "material",
                       "value": round(material, 3)})
        seq += 1
    return events


def package_hash(events) -> str:
    return sha256_text(canonical(events))


class ReplayTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        dbmod.DB_PATH = self.path
        self.conn = dbmod.connect()
        dbmod.init_db(self.conn)
        self.dev = guards.create_device(self.conn, {"name": "挤出机-A"})

    def tearDown(self):
        self.conn.close()
        for ext in ("", "-wal", "-shm"):
            p = self.path + ext
            if os.path.exists(p):
                os.remove(p)

    # -- helpers ----------------------------------------------------------
    def upload(self, events, chunk_size=50, device_id=None, skip=(),
               dup_chunks=()):
        """分块上传并提交；返回 (batch_view, commit_result)。"""
        device_id = device_id or self.dev["device_id"]
        chunks = [events[i:i + chunk_size]
                  for i in range(0, len(events), chunk_size)]
        batch = guards.create_batch(self.conn, {
            "device_id": device_id,
            "package_hash": package_hash(events),
            "total_chunks": len(chunks)})
        for i, chunk in enumerate(chunks):
            if i in skip:
                continue
            guards.put_chunk(self.conn, batch["batch_id"], i,
                             {"events": chunk})
            if i in dup_chunks:
                guards.put_chunk(self.conn, batch["batch_id"], i,
                                 {"events": chunk})
        return batch, chunks

    def commit_all(self, batch, chunks):
        for i, chunk in enumerate(chunks):
            guards.put_chunk(self.conn, batch["batch_id"], i,
                             {"events": chunk})
        return guards.commit_batch(self.conn, batch["batch_id"])

    def build_with_anomalies(self):
        events = make_events()
        batch, chunks = self.upload(events)
        self.commit_all(batch, chunks)
        return guards.build_timeline(self.conn, self.dev["device_id"])

    def first_finding(self, ftype):
        rows = guards.list_findings(self.conn,
                                    device_id=self.dev["device_id"])
        for f in rows:
            if f["ftype"] == ftype:
                return f
        self.fail(f"没有 {ftype} 类型的复核项")

    # -- 时钟校正 ----------------------------------------------------------
    def test_01_clock_fit_recovers_offset_and_drift(self):
        pairs = [(dev_ts(t), t) for t in
                 (S0, S0 + 600, S0 + 1200, S0 + 1800)]
        offset, scale = fit_clock(pairs)
        self.assertAlmostEqual(scale, 1.0 / DRIFT, places=9)
        self.assertAlmostEqual(offset, S0 - OFFSET_TRUE / DRIFT, places=3)

    def test_02_corrected_timeline_matches_server_time(self):
        self.build_with_anomalies()
        versions = guards.list_versions(self.conn, self.dev["device_id"])
        tl = guards.get_timeline(self.conn, versions[0]["version_id"])
        for e in tl["events"]:
            # 校正后的时间必须落在真实服务器时间 ±1ms 内
            self.assertAlmostEqual(
                e["corrected_ts"],
                (e["device_ts"] - OFFSET_TRUE) / DRIFT + S0, places=3)

    def test_03_rebuild_is_reproducible(self):
        self.build_with_anomalies()
        v1 = guards.list_versions(self.conn, self.dev["device_id"])[0]
        guards.build_timeline(self.conn, self.dev["device_id"])
        versions = guards.list_versions(self.conn, self.dev["device_id"])
        v2 = [v for v in versions
              if v["version_id"] != v1["version_id"]][0]
        # 同一批原始事件 → 同一组校正参数（可复现）
        self.assertEqual(v1["clock_offset"], v2["clock_offset"])
        self.assertEqual(v1["clock_scale"], v2["clock_scale"])
        e1 = guards.get_timeline(self.conn, v1["version_id"])["events"]
        e2 = guards.get_timeline(self.conn, v2["version_id"])["events"]
        self.assertEqual(
            [(e["event_uid"], e["corrected_ts"]) for e in e1],
            [(e["event_uid"], e["corrected_ts"]) for e in e2])
        # 旧版本被标记 superseded，新版本 active
        self.assertEqual(
            {v["version_id"]: v["status"] for v in versions}[v1["version_id"]],
            "superseded")

    # -- 断点续传 / 幂等 ----------------------------------------------------
    def test_04_resumable_upload(self):
        events = make_events(n=30, with_anomalies=False)
        batch, chunks = self.upload(events, chunk_size=7,
                                    skip=(2, 3))  # 模拟中断：缺两块
        # 缺块时提交 → 409
        with self.assertRaises(ApiError) as cm:
            guards.commit_batch(self.conn, batch["batch_id"])
        self.assertEqual(cm.exception.error, "chunks_missing")
        # 断点续传：查询状态，只补缺失块
        status = guards.batch_status(self.conn, batch["batch_id"])
        self.assertEqual(sorted(status["missing_chunks"]), [2, 3])
        for i in status["missing_chunks"]:
            guards.put_chunk(self.conn, batch["batch_id"], i,
                             {"events": chunks[i]})
        result = guards.commit_batch(self.conn, batch["batch_id"])
        self.assertEqual(result["inserted"], len(events))

    def test_05_duplicate_chunk_replay_is_idempotent(self):
        events = make_events(n=20, with_anomalies=False)
        batch, chunks = self.upload(events, chunk_size=5, dup_chunks=(0, 1))
        result = guards.commit_batch(self.conn, batch["batch_id"])
        self.assertEqual(result["inserted"], len(events))

    def test_05a_same_content_replay_returns_idempotent_success(self):
        events = make_events(n=10, with_anomalies=False)
        chunks = [events[:5], events[5:]]
        batch = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events), "total_chunks": 2})
        first = guards.put_chunk(self.conn, batch["batch_id"], 0,
                                 {"events": chunks[0]})
        self.assertNotIn("idempotent_replay", first)
        # 相同内容重放（键序不同也视为相同：规范化后比较）
        shuffled = [dict(sorted(e.items(), key=lambda kv: kv[0]))
                    for e in chunks[0]]
        replay = guards.put_chunk(self.conn, batch["batch_id"], 0,
                                  {"events": shuffled})
        self.assertTrue(replay["idempotent_replay"])
        row = self.conn.execute(
            "SELECT payload FROM batch_chunks WHERE batch_id = ? "
            "AND chunk_index = 0", (batch["batch_id"],)).fetchone()
        self.assertEqual(row["payload"], canonical(chunks[0]))

    def test_05b_conflicting_chunk_rejected_and_first_kept(self):
        events = make_events(n=10, with_anomalies=False)
        chunks = [events[:5], events[5:]]
        batch = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events), "total_chunks": 2})
        guards.put_chunk(self.conn, batch["batch_id"], 0,
                         {"events": chunks[0]})
        # 同一分块索引收到不同内容 → 409 chunk_conflict
        tampered = [dict(e) for e in chunks[0]]
        tampered[0] = dict(tampered[0], value=999.0)
        with self.assertRaises(ApiError) as cm:
            guards.put_chunk(self.conn, batch["batch_id"], 0,
                             {"events": tampered})
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(cm.exception.error, "chunk_conflict")
        # 首次分块原样保留（payload 与首次一致）
        row = self.conn.execute(
            "SELECT payload, received_at FROM batch_chunks "
            "WHERE batch_id = ? AND chunk_index = 0",
            (batch["batch_id"],)).fetchone()
        self.assertEqual(row["payload"], canonical(chunks[0]))
        # 冲突后相同内容仍幂等成功
        again = guards.put_chunk(self.conn, batch["batch_id"], 0,
                                 {"events": chunks[0]})
        self.assertTrue(again["idempotent_replay"])
        # 状态接口照常给出缺失块，客户端可继续补传
        status = guards.batch_status(self.conn, batch["batch_id"])
        self.assertEqual(status["missing_chunks"], [1])
        guards.put_chunk(self.conn, batch["batch_id"], 1,
                         {"events": chunks[1]})
        result = guards.commit_batch(self.conn, batch["batch_id"])
        # 提交写入的是首块内容：篡改值 999.0 没有混入事件表
        self.assertEqual(result["inserted"], len(events))
        bad = self.conn.execute(
            "SELECT COUNT(*) AS c FROM raw_events WHERE value = 999.0"
        ).fetchone()["c"]
        self.assertEqual(bad, 0)

    def test_05c_conflict_rejected_after_commit_and_process_restart(self):
        events = make_events(n=10, with_anomalies=False)
        chunks = [events[:5], events[5:]]
        batch = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events), "total_chunks": 2})
        guards.put_chunk(self.conn, batch["batch_id"], 0,
                         {"events": chunks[0]})
        guards.put_chunk(self.conn, batch["batch_id"], 1,
                         {"events": chunks[1]})
        guards.commit_batch(self.conn, batch["batch_id"])
        # 提交后重放相同分块 → 幂等成功
        replay = guards.put_chunk(self.conn, batch["batch_id"], 0,
                                  {"events": chunks[0]})
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["status"], "committed")
        # 提交后重放冲突分块 → 同样拒绝
        tampered = [dict(e, value=999.0) for e in chunks[1]]
        with self.assertRaises(ApiError) as cm:
            guards.put_chunk(self.conn, batch["batch_id"], 1,
                             {"events": tampered})
        self.assertEqual(cm.exception.error, "chunk_conflict")
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) AS c FROM raw_events WHERE value = 999.0"
        ).fetchone()["c"], 0)

        # 模拟进程重启：关闭连接、重新打开同一数据库
        self.conn.close()
        self.conn = dbmod.connect()
        dbmod.init_db(self.conn)
        with self.assertRaises(ApiError) as cm:
            guards.put_chunk(self.conn, batch["batch_id"], 1,
                             {"events": tampered})
        self.assertEqual(cm.exception.error, "chunk_conflict")
        # 重启后状态接口仍可指导续传：已提交批次无缺失块
        status = guards.batch_status(self.conn, batch["batch_id"])
        self.assertEqual(status["status"], "committed")
        self.assertEqual(status["missing_chunks"], [])
        # 新批次的上传/补传在重启后正常工作
        events2 = make_events(n=5, with_anomalies=False, uid_prefix="r")
        chunks2 = [events2[:3], events2[3:]]
        b2 = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events2), "total_chunks": 2})
        guards.put_chunk(self.conn, b2["batch_id"], 0,
                         {"events": chunks2[0]})
        st = guards.batch_status(self.conn, b2["batch_id"])
        self.assertEqual(st["missing_chunks"], [1])
        guards.put_chunk(self.conn, b2["batch_id"], 1,
                         {"events": chunks2[1]})
        guards.commit_batch(self.conn, b2["batch_id"])

    def test_05d_chunk_immutability_enforced_by_trigger(self):
        events = make_events(n=5, with_anomalies=False)
        batch = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events), "total_chunks": 1})
        guards.put_chunk(self.conn, batch["batch_id"], 0, {"events": events})
        # 绕过应用层直接改内容 / 删块 —— 触发器兜底拒绝
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE batch_chunks SET payload = ?, payload_sha256 = 'x' "
                "WHERE batch_id = ? AND chunk_index = 0",
                ("[]", batch["batch_id"]))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "DELETE FROM batch_chunks WHERE batch_id = ? "
                "AND chunk_index = 0", (batch["batch_id"],))

    def test_06_duplicate_package_is_idempotent(self):
        events = make_events(n=20, with_anomalies=False)
        batch, chunks = self.upload(events, chunk_size=5)
        first = guards.commit_batch(self.conn, batch["batch_id"])
        # 重复 commit 直接返回首次结果
        again = guards.commit_batch(self.conn, batch["batch_id"])
        self.assertTrue(again["idempotent_replay"])
        self.assertEqual(again["inserted"], first["inserted"])
        # 同一 package_hash 再建批次 → 返回同一批次，不新建
        dup = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events),
            "total_chunks": len(chunks)})
        self.assertTrue(dup["deduplicated"])
        self.assertEqual(dup["batch_id"], batch["batch_id"])
        self.assertEqual(dup["status"], "committed")
        # 换个批次号重传同样的事件 → 事件级去重，不翻倍
        batch2 = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events) + "-resend",
            "total_chunks": len(chunks)})
        for i, chunk in enumerate(chunks):
            guards.put_chunk(self.conn, batch2["batch_id"], i,
                             {"events": chunk})
        result2 = guards.commit_batch(self.conn, batch2["batch_id"])
        self.assertEqual(result2["inserted"], 0)
        self.assertEqual(result2["duplicates_ignored"], len(events))
        count = self.conn.execute(
            "SELECT COUNT(*) AS c FROM raw_events WHERE device_id = ?",
            (self.dev["device_id"],)).fetchone()["c"]
        self.assertEqual(count, len(events))

    # -- 异常识别 -----------------------------------------------------------
    def test_07_detects_all_three_anomaly_types(self):
        self.build_with_anomalies()
        findings = guards.list_findings(self.conn,
                                        device_id=self.dev["device_id"])
        types = {f["ftype"] for f in findings}
        self.assertIn("continuous_overlimit", types)
        self.assertIn("gap", types)
        self.assertIn("meter_jump", types)
        over = self.first_finding("continuous_overlimit")
        self.assertEqual(over["kind"], "temp")
        self.assertEqual(over["detail"]["run_length"], 5)
        self.assertGreater(over["detail"]["max_value"], 250.0)
        gap = self.first_finding("gap")
        self.assertGreater(gap["detail"]["gap_seconds"], 180.0)
        jumps = [f for f in findings if f["ftype"] == "meter_jump"]
        directions = {f["detail"]["direction"] for f in jumps}
        self.assertEqual(directions, {"leap", "rewind"})

    def test_08_clean_timeline_has_no_findings(self):
        events = make_events(with_anomalies=False)
        batch, chunks = self.upload(events)
        self.commit_all(batch, chunks)
        result = guards.build_timeline(self.conn, self.dev["device_id"])
        self.assertEqual(result["finding_count"], 0)

    # -- 复核并发 / 状态机 ----------------------------------------------------
    def test_09_concurrent_review_keeps_exactly_one_result(self):
        self.build_with_anomalies()
        f = self.first_finding("gap")
        # 两个复核人同时基于 review_seq=0 提交
        r1 = guards.review_finding(self.conn, f["finding_id"], {
            "action": "accept", "reviewer": "张三", "review_seq": 0})
        self.assertEqual(r1["status"], "accepted")
        with self.assertRaises(ApiError) as cm:
            guards.review_finding(self.conn, f["finding_id"], {
                "action": "reject", "reviewer": "李四", "review_seq": 0})
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(cm.exception.error, "review_conflict")
        # 只保留一个结果、一条历史
        after = guards.finding_history(self.conn, f["finding_id"])
        self.assertEqual(after["finding"]["status"], "accepted")
        self.assertEqual(after["finding"]["reviewer"], "张三")
        self.assertEqual(len(after["history"]), 1)

    def test_10_stale_review_seq_is_rejected(self):
        self.build_with_anomalies()
        f = self.first_finding("gap")
        with self.assertRaises(ApiError) as cm:
            guards.review_finding(self.conn, f["finding_id"], {
                "action": "accept", "reviewer": "张三", "review_seq": 7})
        self.assertEqual(cm.exception.status, 409)

    def test_11_return_triggers_recompute_into_new_version(self):
        r1 = self.build_with_anomalies()
        f = self.first_finding("continuous_overlimit")
        result = guards.review_finding(self.conn, f["finding_id"], {
            "action": "return", "reviewer": "王五",
            "note": "对时点不足，重算", "review_seq": 0})
        new_version = result["recompute"]["version_id"]
        self.assertNotEqual(new_version, r1["version_id"])
        # 旧 finding 终态 returned；新版本上重新生成了待复核项
        after = guards.finding_history(self.conn, f["finding_id"])
        self.assertEqual(after["finding"]["status"], "returned")
        new_pending = [x for x in guards.list_findings(
            self.conn, device_id=self.dev["device_id"], status="pending")
            if x["version_id"] == new_version]
        self.assertTrue(new_pending)

    def test_12_failed_recompute_rolls_back_everything(self):
        self.build_with_anomalies()
        f = self.first_finding("gap")
        versions_before = self.conn.execute(
            "SELECT COUNT(*) AS c FROM timeline_versions").fetchone()["c"]
        # 注入故障：重算中途抛错 → 状态变更必须一起回滚
        from app import detect
        original = detect.find_anomalies
        detect.find_anomalies = lambda events: (_ for _ in ()).throw(
            RuntimeError("detector exploded"))
        try:
            with self.assertRaises(RuntimeError):
                guards.review_finding(self.conn, f["finding_id"], {
                    "action": "return", "reviewer": "王五",
                    "review_seq": 0})
        finally:
            detect.find_anomalies = original
        after = guards.finding_history(self.conn, f["finding_id"])
        self.assertEqual(after["finding"]["status"], "pending")
        self.assertEqual(len(after["history"]), 0)
        versions_after = self.conn.execute(
            "SELECT COUNT(*) AS c FROM timeline_versions").fetchone()["c"]
        self.assertEqual(versions_before, versions_after)

    # -- 版本不可变 -----------------------------------------------------------
    def test_13_referenced_version_cannot_be_overwritten(self):
        r = self.build_with_anomalies()
        vid = r["version_id"]
        # 版本已被 findings 引用：任何改写校正事件的尝试都被触发器拒绝
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE corrected_events SET corrected_ts = 0 "
                "WHERE version_id = ?", (vid,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "DELETE FROM corrected_events WHERE version_id = ?", (vid,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE timeline_versions SET clock_offset = 0 "
                "WHERE version_id = ?", (vid,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "DELETE FROM timeline_versions WHERE version_id = ?", (vid,))

    def test_14_rebuild_preserves_old_version_content(self):
        r1 = self.build_with_anomalies()
        before = self.conn.execute(
            "SELECT event_uid, corrected_ts FROM corrected_events "
            "WHERE version_id = ? ORDER BY event_uid",
            (r1["version_id"],)).fetchall()
        guards.build_timeline(self.conn, self.dev["device_id"])
        after = self.conn.execute(
            "SELECT event_uid, corrected_ts FROM corrected_events "
            "WHERE version_id = ? ORDER BY event_uid",
            (r1["version_id"],)).fetchall()
        self.assertEqual([tuple(r) for r in before],
                         [tuple(r) for r in after])

    # -- 审计报告 -------------------------------------------------------------
    def test_15_signed_report_roundtrip(self):
        r = self.build_with_anomalies()
        out = guards.export_report(self.conn, {
            "device_id": self.dev["device_id"],
            "version_id": r["version_id"]})
        ok = guards.verify_report(self.conn, {
            "device_id": self.dev["device_id"], "report": out["report"]})
        self.assertTrue(ok["ok"])

    def test_16_tampered_report_is_rejected(self):
        r = self.build_with_anomalies()
        out = guards.export_report(self.conn, {
            "device_id": self.dev["device_id"],
            "version_id": r["version_id"]})
        report = json.loads(json.dumps(out["report"]))  # deep copy
        report["payload"]["findings"] = []  # 篡改：抹掉全部复核项
        with self.assertRaises(ApiError) as cm:
            guards.verify_report(self.conn, {
                "device_id": self.dev["device_id"], "report": report})
        self.assertEqual(cm.exception.status, 403)
        self.assertEqual(cm.exception.error, "signature_mismatch")

    def test_17_cross_device_report_is_rejected(self):
        r = self.build_with_anomalies()
        other = guards.create_device(self.conn, {"name": "挤出机-B"})
        out = guards.export_report(self.conn, {
            "device_id": self.dev["device_id"],
            "version_id": r["version_id"]})
        # 用另一台设备的身份加载 → 拒绝
        with self.assertRaises(ApiError) as cm:
            guards.verify_report(self.conn, {
                "device_id": other["device_id"], "report": out["report"]})
        self.assertEqual(cm.exception.status, 403)
        self.assertEqual(cm.exception.error, "cross_device_report")
        # 把 payload 里的 device_id 改成另一台设备 → 签名同样失效
        report = json.loads(json.dumps(out["report"]))
        report["payload"]["device_id"] = other["device_id"]
        with self.assertRaises(ApiError) as cm:
            guards.verify_report(self.conn, {
                "device_id": other["device_id"], "report": report})
        self.assertEqual(cm.exception.error, "signature_mismatch")


class SealPackageTest(unittest.TestCase):
    """一次性事件封存包：服务端闸门 + 离线 CLI 全链路。"""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        dbmod.DB_PATH = self.path
        self.conn = dbmod.connect()
        dbmod.init_db(self.conn)
        self.dev = guards.create_device(self.conn, {"name": "挤出机-A"})
        self.built = None  # type: ignore[assignment]
        self.seal_dir = tempfile.mkdtemp()

    def tearDown(self):
        self.conn.close()
        for ext in ("", "-wal", "-shm"):
            p = self.path + ext
            if os.path.exists(p):
                os.remove(p)
        import shutil
        shutil.rmtree(self.seal_dir, ignore_errors=True)

    # -- helpers ----------------------------------------------------------
    def build_and_review_all(self, action="accept"):
        self.built = self._build()
        for f in guards.list_findings(self.conn,
                                      device_id=self.dev["device_id"],
                                      status="pending"):
            guards.review_finding(self.conn, f["finding_id"], {
                "action": action, "reviewer": "张三",
                "review_seq": f["review_seq"]})

    def _build(self):
        events = make_events()
        batch, chunks = self._upload(events)
        for i, chunk in enumerate(chunks):
            guards.put_chunk(self.conn, batch["batch_id"], i,
                             {"events": chunk})
        guards.commit_batch(self.conn, batch["batch_id"])
        return guards.build_timeline(self.conn, self.dev["device_id"])

    def _upload(self, events, chunk_size=50):
        chunks = [events[i:i + chunk_size]
                  for i in range(0, len(events), chunk_size)]
        batch = guards.create_batch(self.conn, {
            "device_id": self.dev["device_id"],
            "package_hash": package_hash(events),
            "total_chunks": len(chunks)})
        return batch, chunks

    def make_seal(self, version_id=None):
        out = guards.create_seal(self.conn, {
            "device_id": self.dev["device_id"],
            "version_id": version_id or self.built["version_id"]})
        path = os.path.join(self.seal_dir,
                            f"{out['seal_id']}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out["package"], f, ensure_ascii=False)
        return out, path

    def cli(self, *argv):
        """以子进程方式运行离线 CLI，返回 (returncode, stdout, stderr)。"""
        import subprocess
        cli = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "sealcli.py")
        # 用干净 cwd + 显式空 PYTHONPATH，验证工具不依赖服务代码
        env = dict(os.environ, PYTHONPATH="")
        proc = subprocess.run([sys.executable, cli, *argv],
                              capture_output=True, text=True,
                              cwd=self.seal_dir, env=env)
        return proc.returncode, proc.stdout, proc.stderr

    # -- 服务端闸门 --------------------------------------------------------
    def test_18_seal_blocked_before_review_complete(self):
        self.built = self._build()
        pending = guards.list_findings(self.conn,
                                       device_id=self.dev["device_id"],
                                       status="pending")
        self.assertTrue(pending)
        with self.assertRaises(ApiError) as cm:
            guards.create_seal(self.conn, {
                "device_id": self.dev["device_id"],
                "version_id": self.built["version_id"]})
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(cm.exception.error, "seal_review_incomplete")

    def test_19_seal_blocked_for_superseded_version(self):
        self.build_and_review_all()
        vid = self.built["version_id"]
        # 复核全部完成，原版本可封存
        ok = guards.create_seal(self.conn, {
            "device_id": self.dev["device_id"], "version_id": vid})
        self.assertTrue(ok["seal_id"])
        # 再重建一次 → 原版本翻为 superseded（封存触发器不允许删改内容，
        # 但允许状态位翻转为 superseded）
        guards.build_timeline(self.conn, self.dev["device_id"])
        with self.assertRaises(ApiError) as cm:
            guards.create_seal(self.conn, {
                "device_id": self.dev["device_id"], "version_id": vid})
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(cm.exception.error, "seal_version_stale")

    def test_20_seal_returns_one_time_key_and_self_contained_package(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        with open(path, encoding="utf-8") as f:
            package = json.load(f)
        payload = package["payload"]
        self.assertEqual(package["format"], "event-seal-v1")
        self.assertEqual(payload["device_id"], self.dev["device_id"])
        self.assertEqual(payload["version_status"], "active")
        self.assertEqual(payload["event_count"], len(payload["events"]))
        self.assertEqual(payload["events_sha256"],
                         sha256_text(canonical(payload["events"])))
        # 封存了全部复核结论，且均已处置
        self.assertTrue(payload["findings"])
        self.assertTrue(all(f["status"] in ("accepted", "rejected")
                            for f in payload["findings"]))
        # 一次性密钥为 64 位 hex，且服务端只存其哈希，不存明文
        self.assertEqual(len(out["seal_key"]), 64)
        row = self.conn.execute(
            "SELECT seal_key_hash FROM seals WHERE seal_id = ?",
            (out["seal_id"],)).fetchone()
        self.assertEqual(row["seal_key_hash"],
                         sha256_text(out["seal_key"]))
        self.assertNotIn(out["seal_key"], json.dumps(
            [dict(r) for r in self.conn.execute(
                "SELECT * FROM seals").fetchall()]))

    def test_21_sealed_version_is_immutable_via_trigger(self):
        self.build_and_review_all()
        out, _ = self.make_seal()
        vid = out["package"]["payload"]["version_id"]
        # seals 引用同样受版本不可变触发器保护
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE corrected_events SET corrected_ts = 0 "
                "WHERE version_id = ?", (vid,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "DELETE FROM timeline_versions WHERE version_id = ?", (vid,))

    # -- 离线 CLI：无服务、无数据库 ---------------------------------------
    def test_22_cli_verify_offline_without_service_or_db(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        ledger = os.path.join(self.seal_dir, "ledger.json")
        # 服务进程不存在（没有启动 HTTP）；数据库文件也不暴露给 CLI：
        # 把封存包复制到独立目录，CLI 仅靠文件 + 一次性密钥完成核对。
        iso = os.path.join(self.seal_dir, "isolated")
        os.makedirs(iso, exist_ok=True)
        iso_pkg = os.path.join(iso, "seal.json")
        shutil_copy(path, iso_pkg)
        rc, stdout, stderr = self.cli(
            "verify", iso_pkg, "--device", self.dev["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 0, stderr)
        self.assertIn(out["seal_id"], stdout)
        self.assertIn("事件数量", stdout)
        self.assertIn(payload_event_count(out), stdout)
        self.assertIn("SHA-256", stdout)
        # import 成功并落台账
        rc, stdout, stderr = self.cli(
            "import", iso_pkg, "--device", self.dev["device_id"],
            "--key", out["seal_key"], "--ledger", ledger)
        self.assertEqual(rc, 0, stderr)
        self.assertTrue(os.path.exists(ledger))

    def test_23_cli_rejects_tampered_package(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        # 改动事件数量声明字段（签名覆盖 → 验签失败）
        with open(path, encoding="utf-8") as f:
            package = json.load(f)
        package["payload"]["event_count"] += 1
        bad = path + ".tampered"
        with open(bad, "w", encoding="utf-8") as f:
            json.dump(package, f)
        rc, stdout, stderr = self.cli(
            "verify", bad, "--device", self.dev["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 3)
        self.assertIn("seal_tampered", stderr)
        # 错误密钥同样是篡改
        rc, _, stderr = self.cli(
            "verify", path, "--device", self.dev["device_id"],
            "--key", "0" * 64)
        self.assertEqual(rc, 3)
        self.assertIn("seal_tampered", stderr)

    def test_24_cli_rejects_wrong_device(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        other = guards.create_device(self.conn, {"name": "挤出机-B"})
        rc, _, stderr = self.cli(
            "verify", path, "--device", other["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 4)
        self.assertIn("seal_device_mismatch", stderr)

    def test_25_cli_rejects_stale_version(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        # 构造一份引用已失效版本、但密钥合法的封存包
        # （模拟被新版本取代后仍拿到封存时刻 active 的旧封存包）
        package = out["package"]
        stale_payload = json.loads(json.dumps(package["payload"]))
        stale_payload["version_status"] = "superseded"
        import hashlib
        import hmac as _hmac
        sig = _hmac.new(out["seal_key"].encode(),
                        canonical(stale_payload).encode(),
                        hashlib.sha256).hexdigest()
        stale_pkg = {"format": "event-seal-v1",
                     "payload": stale_payload, "signature": sig}
        stale_path = path + ".stale"
        with open(stale_path, "w", encoding="utf-8") as f:
            json.dump(stale_pkg, f)
        rc, _, stderr = self.cli(
            "verify", stale_path, "--device", self.dev["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 5)
        self.assertIn("seal_version_stale", stderr)

    def test_26_cli_rejects_integrity_mismatch(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        # 签名仍然合法，但事件正文与数量/完整性证明不一致：
        # 篡改事件并同步重算 events_sha256，却忘记改 event_count
        package = json.loads(json.dumps(out["package"]))
        package["payload"]["events"].pop()
        package["payload"]["events_sha256"] = sha256_text(
            canonical(package["payload"]["events"]))
        import hashlib
        import hmac as _hmac
        package["signature"] = _hmac.new(
            out["seal_key"].encode(),
            canonical(package["payload"]).encode(),
            hashlib.sha256).hexdigest()
        bad = path + ".integrity"
        with open(bad, "w", encoding="utf-8") as f:
            json.dump(package, f)
        rc, _, stderr = self.cli(
            "verify", bad, "--device", self.dev["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 6)
        self.assertIn("seal_integrity_failed", stderr)

    def test_27_cli_rejects_duplicate_import(self):
        self.build_and_review_all()
        out, path = self.make_seal()
        ledger = os.path.join(self.seal_dir, "ledger.json")
        args = ("import", path, "--device", self.dev["device_id"],
                "--key", out["seal_key"], "--ledger", ledger)
        rc, _, stderr = self.cli(*args)
        self.assertEqual(rc, 0, stderr)
        # 同一封存包再次导入 → 拒绝（即使复制成另一个文件名）
        dup_path = path + ".copy"
        shutil_copy(path, dup_path)
        rc, _, stderr = self.cli(
            "import", dup_path, "--device", self.dev["device_id"],
            "--key", out["seal_key"], "--ledger", ledger)
        self.assertEqual(rc, 7)
        self.assertIn("seal_already_imported", stderr)
        # verify 不登记、不受台账影响
        rc, _, stderr = self.cli(
            "verify", path, "--device", self.dev["device_id"],
            "--key", out["seal_key"])
        self.assertEqual(rc, 0, stderr)

    def test_28_cli_rejects_malformed_package(self):
        bad = os.path.join(self.seal_dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("{not json")
        rc, _, stderr = self.cli(
            "verify", bad, "--device", self.dev["device_id"],
            "--key", "0" * 64)
        self.assertEqual(rc, 2)
        self.assertIn("seal_malformed", stderr)
        # 结构合法但格式不符
        other = os.path.join(self.seal_dir, "other.json")
        with open(other, "w", encoding="utf-8") as f:
            json.dump({"format": "report-v1", "payload": {},
                       "signature": "x"}, f)
        rc, _, stderr = self.cli(
            "verify", other, "--device", self.dev["device_id"],
            "--key", "0" * 64)
        self.assertEqual(rc, 2)
        self.assertIn("seal_malformed", stderr)


def shutil_copy(src, dst):
    import shutil
    shutil.copy(src, dst)


def payload_event_count(out) -> str:
    return str(out["package"]["payload"]["event_count"])


class HttpSmokeTest(unittest.TestCase):
    """HTTP 层冒烟：上传→提交→重建→复核→导出→验证 全链路。"""

    @classmethod
    def setUpClass(cls):
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(cls.db_path)
        dbmod.DB_PATH = cls.db_path
        from app.server import make_server
        cls.httpd = make_server("127.0.0.1", 0, db_path=cls.db_path)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for ext in ("", "-wal", "-shm"):
            p = cls.db_path + ext
            if os.path.exists(p):
                os.remove(p)

    def api(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_full_flow_over_http(self):
        status, health = self.api("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["ok"])

        status, dev = self.api("POST", "/api/devices",
                               {"name": "HTTP-挤出机"})
        self.assertEqual(status, 200)
        device_id = dev["device_id"]

        events = make_events(n=40)
        chunks = [events[i:i + 16] for i in range(0, len(events), 16)]
        status, batch = self.api("POST", "/api/batches", {
            "device_id": device_id,
            "package_hash": package_hash(events),
            "total_chunks": len(chunks)})
        self.assertEqual(status, 200)
        # 断点续传：先传一半，查状态，再补全
        for i in range(len(chunks) // 2):
            status, _ = self.api(
                "PUT", f"/api/batches/{batch['batch_id']}/chunks/{i}",
                {"events": chunks[i]})
            self.assertEqual(status, 200)
        status, st = self.api("GET", f"/api/batches/{batch['batch_id']}")
        self.assertEqual(status, 200)
        self.assertTrue(st["missing_chunks"])
        for i in st["missing_chunks"]:
            self.api("PUT", f"/api/batches/{batch['batch_id']}/chunks/{i}",
                     {"events": chunks[i]})
        status, commit = self.api(
            "POST", f"/api/batches/{batch['batch_id']}/commit")
        self.assertEqual(status, 200)
        self.assertEqual(commit["inserted"], len(events))

        status, built = self.api(
            "POST", f"/api/devices/{device_id}/timeline/build")
        self.assertEqual(status, 200)
        self.assertGreater(built["finding_count"], 0)

        status, found = self.api(
            "GET", f"/api/findings?device_id={device_id}&status=pending")
        self.assertEqual(status, 200)
        f = found["findings"][0]
        status, reviewed = self.api(
            "POST", f"/api/findings/{f['finding_id']}/review",
            {"action": "accept", "reviewer": "张三",
             "review_seq": f["review_seq"]})
        self.assertEqual(status, 200)
        self.assertEqual(reviewed["status"], "accepted")
        # 并发重放同一复核 → 409
        status, conflict = self.api(
            "POST", f"/api/findings/{f['finding_id']}/review",
            {"action": "reject", "reviewer": "李四",
             "review_seq": f["review_seq"]})
        self.assertEqual(status, 409)

        status, exported = self.api("POST", "/api/reports/export", {
            "device_id": device_id, "version_id": built["version_id"]})
        self.assertEqual(status, 200)
        status, verified = self.api("POST", "/api/reports/verify", {
            "device_id": device_id, "report": exported["report"]})
        self.assertEqual(status, 200)
        self.assertTrue(verified["ok"])
        # 篡改 → 403
        exported["report"]["payload"]["event_count"] = 0
        status, rejected = self.api("POST", "/api/reports/verify", {
            "device_id": device_id, "report": exported["report"]})
        self.assertEqual(status, 403)
        self.assertEqual(rejected["error"], "signature_mismatch")

        # -- 一次性封存包（独立设备：完整事件含多类复核项）---------------
        status, dev2 = self.api("POST", "/api/devices",
                                {"name": "HTTP-封存机"})
        self.assertEqual(status, 200)
        seal_device = dev2["device_id"]
        seal_events = make_events(n=120)
        seal_chunks = [seal_events[i:i + 40]
                       for i in range(0, len(seal_events), 40)]
        status, sb = self.api("POST", "/api/batches", {
            "device_id": seal_device,
            "package_hash": package_hash(seal_events),
            "total_chunks": len(seal_chunks)})
        self.assertEqual(status, 200)
        for i, chunk in enumerate(seal_chunks):
            self.api("PUT", f"/api/batches/{sb['batch_id']}/chunks/{i}",
                     {"events": chunk})
        self.api("POST", f"/api/batches/{sb['batch_id']}/commit")
        status, sbuilt = self.api(
            "POST", f"/api/devices/{seal_device}/timeline/build")
        self.assertEqual(status, 200)
        self.assertGreater(sbuilt["finding_count"], 1)
        # 复核未完成 → 409 seal_review_incomplete
        status, blocked = self.api("POST", "/api/seals", {
            "device_id": seal_device,
            "version_id": sbuilt["version_id"]})
        self.assertEqual(status, 409)
        self.assertEqual(blocked["error"], "seal_review_incomplete")
        # 全部复核完成后封存 → 200，返回一次性密钥与自包含封存包
        status, pending = self.api(
            "GET", f"/api/findings?device_id={seal_device}&status=pending")
        for f in pending["findings"]:
            status, _ = self.api(
                "POST", f"/api/findings/{f['finding_id']}/review",
                {"action": "accept", "reviewer": "李四",
                 "review_seq": f["review_seq"]})
            self.assertEqual(status, 200)
        status, sealed = self.api("POST", "/api/seals", {
            "device_id": seal_device,
            "version_id": sbuilt["version_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(len(sealed["seal_key"]), 64)
        pkg = sealed["package"]
        self.assertEqual(pkg["format"], "event-seal-v1")
        self.assertEqual(pkg["payload"]["device_id"], seal_device)
        self.assertGreater(pkg["payload"]["event_count"], 0)
        self.assertEqual(len(pkg["payload"]["events"]),
                         pkg["payload"]["event_count"])
        # 封存记录可查
        status, ledger = self.api(
            "GET", f"/api/seals?device_id={seal_device}")
        self.assertEqual(status, 200)
        self.assertEqual(len(ledger["seals"]), 1)
        # 离线 CLI 用一次性密钥核对（无服务、无数据库依赖）
        import subprocess
        cli = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "sealcli.py")
        seal_file = os.path.join(tempfile.gettempdir(),
                                 f"{sealed['seal_id']}.json")
        with open(seal_file, "w", encoding="utf-8") as f:
            json.dump(pkg, f)
        ledger_file = os.path.join(tempfile.gettempdir(),
                                   f"{sealed['seal_id']}.ledger.json")
        proc = subprocess.run(
            [sys.executable, cli, "import", seal_file,
             "--device", seal_device, "--key", sealed["seal_key"],
             "--ledger", ledger_file],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("核对通过", proc.stdout)
        # 重复导入 → 7 seal_already_imported
        proc2 = subprocess.run(
            [sys.executable, cli, "import", seal_file,
             "--device", seal_device, "--key", sealed["seal_key"],
             "--ledger", ledger_file],
            capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 7)
        self.assertIn("seal_already_imported", proc2.stderr)
        # 换设备 → 4 seal_device_mismatch
        proc3 = subprocess.run(
            [sys.executable, cli, "verify", seal_file,
             "--device", "DEV-OTHER", "--key", sealed["seal_key"]],
            capture_output=True, text=True)
        self.assertEqual(proc3.returncode, 4)
        self.assertIn("seal_device_mismatch", proc3.stderr)
        # 篡改封存包 → 3 seal_tampered
        pkg_bad = json.loads(json.dumps(pkg))
        pkg_bad["payload"]["event_count"] += 1
        tampered_file = seal_file + ".tampered"
        with open(tampered_file, "w", encoding="utf-8") as f:
            json.dump(pkg_bad, f)
        proc4 = subprocess.run(
            [sys.executable, cli, "verify", tampered_file,
             "--device", seal_device, "--key", sealed["seal_key"]],
            capture_output=True, text=True)
        self.assertEqual(proc4.returncode, 3)
        self.assertIn("seal_tampered", proc4.stderr)
        # 重建后旧版本失效 → 再封存旧版本 409 seal_version_stale
        status, rebuilt = self.api(
            "POST", f"/api/devices/{seal_device}/timeline/build")
        self.assertEqual(status, 200)
        self.assertNotEqual(rebuilt["version_id"], sbuilt["version_id"])
        status, stale = self.api("POST", "/api/seals", {
            "device_id": seal_device,
            "version_id": sbuilt["version_id"]})
        self.assertEqual(status, 409)
        self.assertEqual(stale["error"], "seal_version_stale")
        for tmp in (seal_file, tampered_file, ledger_file):
            if os.path.exists(tmp):
                os.remove(tmp)


if __name__ == "__main__":
    unittest.main()
