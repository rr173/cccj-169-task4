#!/usr/bin/env python3
"""一次性事件封存包 —— 离线核对 / 导入命令行工具。

在**没有服务进程、没有数据库**的命令行环境中，操作员凭封存包文件与
下载时一次性返回的 ``seal_key`` 核对：设备、时间线版本、事件数量与
完整性证明（SHA-256）。仅依赖 Python 3.11 标准库，不 import 任何
服务端代码，封存包文件自包含全部证据。

用法：

    python3 sealcli.py verify SEAL.json --device DEV-X --key <64位hex>
    python3 sealcli.py import SEAL.json --device DEV-X --key <hex> \\
        [--ledger ledger.json]
    python3 sealcli.py show   SEAL.json

子命令：

    verify   只核对，不登记。成功打印设备/版本/事件数量/完整性证明。
    import   核对通过后登记进本地只追加台账；同一封存包重复导入被拒。
    show     不验签，打印封存包结构（仅供肉眼浏览，不能作为信任依据）。

可区分的拒绝原因（退出码 / 错误代码）：

    2 seal_malformed        文件损坏、JSON/字段结构不合法
    3 seal_tampered         HMAC 验签失败（封存包被改动或密钥不对）
    4 seal_device_mismatch  封存包绑定设备与 --device 不一致（换设备使用）
    5 seal_version_stale    引用的时间线版本已失效（非 active）
    6 seal_integrity_failed 事件数量 / 事件正文 SHA-256 与证明不一致
    7 seal_already_imported 该封存包已在台账中（重复导入）
    8 io_error              文件读写失败
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile

SEAL_FORMAT = "event-seal-v1"
DEFAULT_LEDGER = os.path.join(
    os.path.expanduser("~"), ".event_replay", "seal-imports.json")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_MALFORMED = 2
EXIT_TAMPERED = 3
EXIT_DEVICE_MISMATCH = 4
EXIT_VERSION_STALE = 5
EXIT_INTEGRITY = 6
EXIT_DUPLICATE = 7
EXIT_IO = 8


class SealError(Exception):
    def __init__(self, code: str, message: str, exit_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# 确定性 JSON（与服务端 canonical 相同：排序键、无空白）
# ---------------------------------------------------------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_hmac(key: str, payload: dict, signature: str) -> bool:
    expected = hmac.new(key.encode("utf-8"),
                        canonical(payload).encode("utf-8"),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


# ---------------------------------------------------------------------------
# 载入与核对（纯函数式，便于测试）
# ---------------------------------------------------------------------------

_PAYLOAD_REQUIRED = (
    "format", "seal_id", "device_id", "version_id", "algo_version",
    "version_status", "clock", "created_at", "event_count",
    "events_sha256", "events", "findings",
)


def load_package(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise SealError("io_error", f"无法读取封存包：{e}", EXIT_IO)
    try:
        package = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SealError("seal_malformed",
                        "封存包不是合法 JSON，或文件已损坏", EXIT_MALFORMED)
    if not isinstance(package, dict) \
            or package.get("format") != SEAL_FORMAT \
            or not isinstance(package.get("payload"), dict) \
            or not isinstance(package.get("signature"), str):
        raise SealError(
            "seal_malformed",
            f"封存包结构不合法：缺少 {SEAL_FORMAT} 信封"
            "（format / payload / signature）", EXIT_MALFORMED)
    payload = package["payload"]
    missing = [k for k in _PAYLOAD_REQUIRED if k not in payload]
    if missing:
        raise SealError(
            "seal_malformed",
            f"封存包 payload 缺少字段：{', '.join(missing)}", EXIT_MALFORMED)
    if payload.get("format") != SEAL_FORMAT:
        raise SealError(
            "seal_malformed",
            f"封存格式版本不受支持：{payload.get('format')}", EXIT_MALFORMED)
    return package


def verify_package(path: str, expected_device: str, key: str) -> dict:
    """按固定顺序核对，返回 payload；每类失败给出不同错误代码。"""
    package = load_package(path)
    payload = package["payload"]

    # 1) 完整性签名：任何字段被改 / 密钥不对 → seal_tampered
    if not verify_hmac(key, payload, package["signature"]):
        raise SealError(
            "seal_tampered",
            "HMAC-SHA256 验签失败：封存包内容被改动，或一次性密钥不正确",
            EXIT_TAMPERED)

    # 2) 设备绑定：换设备使用 → seal_device_mismatch
    if payload["device_id"] != expected_device:
        raise SealError(
            "seal_device_mismatch",
            f"封存包绑定设备 {payload['device_id']}，"
            f"与指定设备 {expected_device} 不一致，拒绝在该设备上使用",
            EXIT_DEVICE_MISMATCH)

    # 3) 版本有效性：引用已失效版本 → seal_version_stale
    if payload["version_status"] != "active":
        raise SealError(
            "seal_version_stale",
            f"封存包引用的时间线版本 {payload['version_id']} 已失效"
            f"（{payload['version_status']}），请使用当前有效版本重新封存",
            EXIT_VERSION_STALE)

    # 4) 事件数量与完整性证明（自包含，重新计算事件正文 SHA-256）
    events = payload["events"]
    if not isinstance(events, list):
        raise SealError("seal_malformed", "events 必须是数组",
                        EXIT_MALFORMED)
    actual_hash = sha256_text(canonical(events))
    if payload["event_count"] != len(events) \
            or not hmac.compare_digest(actual_hash, payload["events_sha256"]):
        raise SealError(
            "seal_integrity_failed",
            "完整性证明核对失败：事件数量或事件正文与 SHA-256 证明不一致"
            f"（声明 {payload['event_count']} 条 / 实际 {len(events)} 条）",
            EXIT_INTEGRITY)

    findings = payload["findings"]
    pending = [f for f in findings if isinstance(f, dict)
               and f.get("status") == "pending"]
    return {
        "seal_id": payload["seal_id"],
        "device_id": payload["device_id"],
        "version_id": payload["version_id"],
        "algo_version": payload["algo_version"],
        "version_status": payload["version_status"],
        "drift_ppm": round(
            (float(payload["clock"]["scale"]) - 1.0) * 1e6, 3),
        "created_at": payload["created_at"],
        "event_count": len(events),
        "events_sha256": payload["events_sha256"],
        "finding_total": len(findings),
        "finding_pending": len(pending),
        "package_sha256": sha256_text(canonical(package)),
    }


def render_summary(r: dict) -> str:
    lines = [
        "封存包核对通过",
        f"  封存编号   {r['seal_id']}",
        f"  设备       {r['device_id']}",
        f"  时间线版本 {r['version_id']}（{r['version_status']}，"
        f"{r['algo_version']}，漂移 {r['drift_ppm']} ppm）",
        f"  封存时间   {r['created_at']}",
        f"  事件数量   {r['event_count']}",
        f"  完整性证明 SHA-256 {r['events_sha256']}",
        f"  复核结论   {r['finding_total']} 项，待复核 {r['finding_pending']} 项",
        f"  封存包指纹 SHA-256 {r['package_sha256']}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 本地导入台账：只追加 JSON；同一封存包（按包指纹）只允许导入一次
# ---------------------------------------------------------------------------

def load_ledger(path: str) -> dict:
    if not os.path.exists(path):
        return {"version": 1, "imports": []}
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SealError("io_error", f"台账无法读取：{e}", EXIT_IO)
    if not isinstance(data, dict) or not isinstance(data.get("imports"), list):
        raise SealError("io_error", "台账文件结构不合法，拒绝写入", EXIT_IO)
    return data


def record_import(ledger_path: str, summary: dict) -> None:
    ledger = load_ledger(ledger_path)
    known = {e.get("package_sha256") for e in ledger["imports"]
             if isinstance(e, dict)}
    if summary["package_sha256"] in known:
        raise SealError(
            "seal_already_imported",
            f"封存包 {summary['seal_id']} 已在台账 {ledger_path} 中"
            "（按封存包指纹识别，重命名文件也无法重复导入）",
            EXIT_DUPLICATE)
    ledger["imports"].append({
        "seal_id": summary["seal_id"],
        "device_id": summary["device_id"],
        "version_id": summary["version_id"],
        "event_count": summary["event_count"],
        "events_sha256": summary["events_sha256"],
        "package_sha256": summary["package_sha256"],
        "imported_at": _now_iso(),
    })
    os.makedirs(os.path.dirname(os.path.abspath(ledger_path)),
                exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ledger-", dir=os.path.dirname(
        os.path.abspath(ledger_path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(ledger, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, ledger_path)
    except OSError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise SealError("io_error", f"台账写入失败：{e}", EXIT_IO)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_verify(args) -> int:
    summary = verify_package(args.package, args.device, args.key)
    print(render_summary(summary))
    return EXIT_OK


def cmd_import(args) -> int:
    summary = verify_package(args.package, args.device, args.key)
    ledger = args.ledger or DEFAULT_LEDGER
    record_import(ledger, summary)
    print(render_summary(summary))
    print(f"  导入台账   {ledger}（已登记，重复导入将被拒绝）")
    return EXIT_OK


def cmd_show(args) -> int:
    package = load_package(args.package)
    p = package["payload"]
    print(f"封存编号   {p.get('seal_id')}")
    print(f"设备       {p.get('device_id')}")
    print(f"时间线版本 {p.get('version_id')}（{p.get('version_status')}）")
    print(f"事件数量   {p.get('event_count')}")
    print(f"完整性证明 {p.get('events_sha256')}")
    print(f"复核项     {len(p.get('findings') or [])} 项")
    print("注意：show 不做验签，不能作为信任依据；请使用 verify/import。")
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sealcli.py",
        description="一次性事件封存包离线核对 / 导入工具（无服务、无数据库）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("package", help="封存包 JSON 文件路径")
        sp.add_argument("--device", required=True,
                        help="预期设备编号（换设备使用会被拒绝）")
        sp.add_argument("--key", required=True,
                        help="封存包下载时一次性返回的 64 位十六进制密钥")

    sp_v = sub.add_parser("verify", help="只核对，不登记到台账")
    add_common(sp_v)
    sp_v.set_defaults(func=cmd_verify)

    sp_i = sub.add_parser("import", help="核对通过并登记（重复导入拒绝）")
    add_common(sp_i)
    sp_i.add_argument("--ledger", default=None,
                      help=f"导入台账路径（默认 {DEFAULT_LEDGER}）")
    sp_i.set_defaults(func=cmd_import)

    sp_s = sub.add_parser("show", help="不验签，仅打印封存包结构")
    sp_s.add_argument("package")
    sp_s.set_defaults(func=cmd_show)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SealError as e:
        print(f"拒绝：{e.code} —— {e.message}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
