"""SQLite persistence layer.

全部状态落在单个 SQLite 库中。状态迁移的原子性由事务保证（见 guards.py，
一律 ``BEGIN IMMEDIATE``）。被引用的校正版本由数据库触发器兜底，禁止
静默覆盖/删除——即使绕过应用层直接写库也会被拒；已收分块（batch_chunks）
同理：内容一旦首次落库即不可改、不可删，冲突上传只能拿到 409。
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("REPLAY_DB", "/workspace/replay/data/replay.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    secret_key  TEXT NOT NULL,          -- 报告签名密钥（每设备一把）
    created_at  TEXT NOT NULL
);

-- 导入批次：按 (device_id, package_hash) 幂等；分块落库支持断点续传
CREATE TABLE IF NOT EXISTS batches (
    batch_id        TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(device_id),
    package_hash    TEXT NOT NULL,
    total_chunks    INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'uploading'
                        CHECK(status IN ('uploading','committed')),
    inserted_count  INTEGER,
    created_at      TEXT NOT NULL,
    committed_at    TEXT,
    UNIQUE(device_id, package_hash)
);

CREATE TABLE IF NOT EXISTS batch_chunks (
    batch_id    TEXT NOT NULL REFERENCES batches(batch_id),
    chunk_index INTEGER NOT NULL,
    payload     TEXT NOT NULL,          -- JSON 数组：本块的事件列表
    payload_sha256 TEXT NOT NULL,       -- 首块内容指纹：冲突检测依据
    received_at TEXT NOT NULL,
    PRIMARY KEY (batch_id, chunk_index)
);

-- 原始事件：只追加，(device_id, event_uid) 幂等去重
CREATE TABLE IF NOT EXISTS raw_events (
    device_id   TEXT NOT NULL,
    event_uid   TEXT NOT NULL,
    batch_id    TEXT NOT NULL,
    device_seq  INTEGER NOT NULL,
    device_ts   REAL NOT NULL,          -- 设备时钟读数（秒）
    kind        TEXT NOT NULL CHECK(kind IN
                    ('temp','pressure','material','sync')),
    value       REAL,
    server_ts   REAL,                   -- sync 事件的服务器对时戳
    PRIMARY KEY (device_id, event_uid)
);

-- 校正时间线版本：内容只插入不修改；被引用后由触发器禁止内容变更
CREATE TABLE IF NOT EXISTS timeline_versions (
    version_id      TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(device_id),
    algo_version    TEXT NOT NULL,
    clock_offset    REAL NOT NULL,      -- corrected = offset + scale * device_ts
    clock_scale     REAL NOT NULL,
    source_events   INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','superseded')),
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS corrected_events (
    version_id      TEXT NOT NULL REFERENCES timeline_versions(version_id),
    event_uid       TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    device_ts       REAL NOT NULL,
    corrected_ts    REAL NOT NULL,
    kind            TEXT NOT NULL,
    value           REAL,
    PRIMARY KEY (version_id, event_uid)
);

-- 待复核项：status 流转 pending -> accepted/rejected/returned
CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT PRIMARY KEY,
    version_id  TEXT NOT NULL REFERENCES timeline_versions(version_id),
    device_id   TEXT NOT NULL,
    ftype       TEXT NOT NULL CHECK(ftype IN
                    ('continuous_overlimit','gap','meter_jump')),
    kind        TEXT NOT NULL,
    start_ts    REAL NOT NULL,
    end_ts      REAL NOT NULL,
    detail      TEXT NOT NULL,          -- JSON：阈值、游程、跳变量等
    status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN
                        ('pending','accepted','rejected','returned')),
    reviewer    TEXT,
    review_note TEXT,
    reviewed_at TEXT,
    review_seq  INTEGER NOT NULL DEFAULT 0,   -- 乐观锁：并发复核只赢一个
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS review_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    reviewer    TEXT,
    note        TEXT,
    created_at  TEXT NOT NULL
);

-- 审计报告：payload 规范化 JSON + 设备密钥 HMAC-SHA256 签名
CREATE TABLE IF NOT EXISTS reports (
    report_id   TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    version_id  TEXT NOT NULL REFERENCES timeline_versions(version_id),
    payload     TEXT NOT NULL,
    signature   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT,
    event_type  TEXT NOT NULL,
    detail      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_device ON raw_events(device_id);
CREATE INDEX IF NOT EXISTS idx_corrected_version ON corrected_events(version_id);
CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_version ON findings(version_id);
CREATE INDEX IF NOT EXISTS idx_history_finding ON review_history(finding_id);

-- 不可变红线：版本一旦被 findings 或 reports 引用，
-- 其校正参数与校正事件一律禁止 UPDATE/DELETE（只能另建新版本）。
CREATE TRIGGER IF NOT EXISTS trg_corrected_no_update
BEFORE UPDATE ON corrected_events
WHEN EXISTS (SELECT 1 FROM findings  WHERE version_id = OLD.version_id)
  OR EXISTS (SELECT 1 FROM reports   WHERE version_id = OLD.version_id)
BEGIN
    SELECT RAISE(ABORT, 'version_referenced_immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_corrected_no_delete
BEFORE DELETE ON corrected_events
WHEN EXISTS (SELECT 1 FROM findings  WHERE version_id = OLD.version_id)
  OR EXISTS (SELECT 1 FROM reports   WHERE version_id = OLD.version_id)
BEGIN
    SELECT RAISE(ABORT, 'version_referenced_immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_version_no_retarget
BEFORE UPDATE OF algo_version, clock_offset, clock_scale, source_events
ON timeline_versions
WHEN EXISTS (SELECT 1 FROM findings  WHERE version_id = OLD.version_id)
  OR EXISTS (SELECT 1 FROM reports   WHERE version_id = OLD.version_id)
BEGIN
    SELECT RAISE(ABORT, 'version_referenced_immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_version_no_delete
BEFORE DELETE ON timeline_versions
WHEN EXISTS (SELECT 1 FROM findings  WHERE version_id = OLD.version_id)
  OR EXISTS (SELECT 1 FROM reports   WHERE version_id = OLD.version_id)
BEGIN
    SELECT RAISE(ABORT, 'version_referenced_immutable');
END;

-- 分块只接受首次内容：同一 (batch_id, chunk_index) 一旦落库，
-- 内容既不能改也不能删。即使绕过应用层直接写库（含进程重启后），
-- 冲突内容也无法替换首块；客户端只能靠状态接口补传缺失块。
CREATE TRIGGER IF NOT EXISTS trg_chunk_no_update
BEFORE UPDATE ON batch_chunks
WHEN NEW.payload_sha256 <> OLD.payload_sha256
BEGIN
    SELECT RAISE(ABORT, 'chunk_conflict_immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_chunk_no_delete
BEFORE DELETE ON batch_chunks
BEGIN
    SELECT RAISE(ABORT, 'chunk_immutable');
END;
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    _migrate(conn)
    conn.executescript(SCHEMA)


def _migrate(conn: sqlite3.Connection) -> None:
    """轻量迁移：老版本库的 batch_chunks 没有 payload_sha256 列，
    补上并用现有 payload 回填指纹，再由 init_db 挂不可变触发器。"""
    cols = {r["name"] for r in
            conn.execute("PRAGMA table_info(batch_chunks)").fetchall()}
    if cols and "payload_sha256" not in cols:
        import hashlib

        conn.execute("ALTER TABLE batch_chunks ADD COLUMN "
                     "payload_sha256 TEXT")
        rows = conn.execute(
            "SELECT rowid, payload FROM batch_chunks").fetchall()
        for r in rows:
            # 历史 payload 以 canonical 形式落库，直接哈希即可
            digest = hashlib.sha256(r["payload"].encode("utf-8")).hexdigest()
            conn.execute(
                "UPDATE batch_chunks SET payload_sha256 = ? WHERE rowid = ?",
                (digest, r["rowid"]))
        # 老触发器（若有）引用旧列定义，统一删后重建
        conn.execute("DROP TRIGGER IF EXISTS trg_chunk_no_update")
        conn.execute("DROP TRIGGER IF EXISTS trg_chunk_no_delete")
