# 跨设备工艺事件回放与风险处置服务

接收打印机产生的**温度 / 压力 / 耗材计量**事件，按设备时钟漂移校正后重建
**可复现**的生产时间线；从时间线识别**连续超限、缺失区间、计量跳变**三类
异常并生成待复核项；复核人员可**接受 / 驳回 / 退回重算**；网页展示原始事件、
校正版本与处理历史；审计报告**签名导出**，跨设备或被篡改的报告拒绝加载。

仅依赖 Python 3.11 标准库（`http.server` + `sqlite3`），无需安装任何第三方包。

## 快速开始

```bash
cd /workspace/replay
python3 seed.py --reset          # 可选：写入两台演示设备（一台含漂移+三类异常）
python3 -m app 8081              # 启动，浏览器访问 http://localhost:8081
```

测试：

```bash
python3 -m unittest tests.test_replay -v   # 33 个用例（含 HTTP 全链路 + 离线 CLI）
```

## 离线封存包核对（无服务、无数据库）

网页「封存包」标签页选择**当前有效且复核全部完成**的版本，点击封存后：

1. 下载 `SEAL-YYYYMMDD-NNN.json`（自包含：校正事件全量、复核结论、数量与
   SHA-256 完整性证明、版本状态）；
2. 抄下仅显示一次的 64 位一次性密钥；
3. 在任意装有 Python 3.11 的机器上（无需安装任何东西、无需访问服务或数据库）：

```bash
# 只核对，不登记
python3 sealcli.py verify SEAL-....json --device DEV-001 --key <一次性密钥>

# 核对并登记到本地台账（原子写入）；同一封存包再次导入 → 7 seal_already_imported
python3 sealcli.py import SEAL-....json --device DEV-001 --key <一次性密钥> \
    --ledger ./seal-ledger.json

# 不验签，仅浏览结构（不能作为信任依据）
python3 sealcli.py show SEAL-....json
```

核对顺序固定，错误彼此可区分：结构 → 验签（篡改/密钥）→ 设备 → 版本有效性
→ 数量与完整性证明；`import` 在全部通过后再查台账防重。

## 核心不变量（业务红线）

1. **时钟漂移校正、时间线可复现**：设备随包上传 `sync` 对时事件（设备时钟读数 +
   服务器对时戳 `server_ts`），对全部对时点做最小二乘拟合
   `server_ts ≈ offset + scale·device_ts`（`scale-1` 即漂移率，如 +200ppm 快钟）。
   拟合与识别都是纯函数：同一批原始事件重算必然得到同一组参数、同一条时间线
   （`test_01/02/03`）。
2. **断点续传**：批次按分块上传（`PUT /api/batches/{id}/chunks/{n}` 逐块落库），
   中断后 `GET /api/batches/{id}` 返回 `received_chunks/missing_chunks`，
   客户端只补缺失块；未收齐时 commit 返回 `409 chunks_missing`（`test_04`）。
   **分块内容以首次到达为准**：同一分块索引重放，规范化 JSON 一致 → 幂等成功；
   内容不一致 → `409 chunk_conflict` 拒绝且首块绝不被覆盖（`test_05a/05b`）。
   提交批次后、进程重启后冲突同样被拒，冲突内容进不了 `raw_events`
   （`test_05c`）；`batch_chunks` 上的数据库触发器兜底，绕过应用层直接改/删
   已收分块也会失败（`test_05d`）。
3. **重复包幂等**：批次按 `(device_id, package_hash)` 唯一，重复创建返回既有批次；
   重复 commit 幂等返回首次结果；事件按 `(device_id, event_uid)` 去重，
   换批次号重传同样的事件一条不增（`test_05/06`）。
4. **校正版本不可静默覆盖**：每次重建产生**新版本**，旧版本仅翻
   `active→superseded` 状态位；版本一旦被 findings / reports 引用，数据库
   触发器禁止改写/删除其校正参数与校正事件（`test_13/14`）。
5. **重算失败回滚**：复核"退回重算"与状态变更在**同一事务**中执行，重算中途
   失败整体回滚——复核项回到 `pending`、不产生半个新版本（`test_12`）。
6. **并发复核只保留一个结果**：复核是 CAS 更新
   `UPDATE … WHERE status='pending' AND review_seq=?`，并发/过期提交只有
   一个成功，其余 `409 review_conflict`；历史只记一条（`test_09/10`）。
7. **审计报告签名**：报告 payload 规范化 JSON 后用**设备密钥** HMAC-SHA256
   签名，签名覆盖 `device_id` 等全部字段——跨设备加载 `403 cross_device_report`，
   任何字段被改 `403 signature_mismatch`（`test_15/16/17`）。
8. **一次性事件封存包**：复核全部完成后，操作员可对当前有效（active）版本
   生成**自包含**封存包（含全部校正事件、复核结论、事件 SHA-256 完整性证明），
   用**每包一把的一次性密钥** HMAC-SHA256 签名，密钥仅下载时返回一次，服务端
   只存密钥哈希。封存前提不满足分别拒绝：版本已失效 →
   `409 seal_version_stale`，仍有 pending 复核项 →
   `409 seal_review_incomplete`；版本被封存后同样受不可变触发器保护
   （`test_18~21`）。离线命令行工具 `sealcli.py`（**仅标准库，不启动服务、
   不读数据库、不 import 服务代码**）核对设备/版本/事件数量/完整性证明，
   四类拒绝各自返回可区分的退出码与错误代码（`test_22~28`，HTTP 全链路见
   `HttpSmokeTest`）：

   | 退出码 | 错误代码 | 触发场景 |
   |---|---|---|
   | 2 | `seal_malformed` | 封存包文件损坏、JSON/结构不合法 |
   | 3 | `seal_tampered` | 封存包被改动或一次性密钥错误（验签失败） |
   | 4 | `seal_device_mismatch` | 换设备使用（`--device` 与封存设备不一致） |
   | 5 | `seal_version_stale` | 引用已失效（superseded）版本 |
   | 6 | `seal_integrity_failed` | 事件数量/事件正文与 SHA-256 证明不一致 |
   | 7 | `seal_already_imported` | 同一封存包重复导入（按包指纹，改名无效） |

## 事件格式

```json
[{"uid": "e1", "seq": 1, "ts": 1000.0, "kind": "temp", "value": 235.2},
 {"uid": "s1", "seq": 0, "ts": 1000.0, "kind": "sync", "server_ts": 1700000000.0}]
```

- `kind`：`temp`(°C) / `pressure`(bar) / `material`(g，累计读数) / `sync`(对时)
- `ts`：设备时钟读数（秒）；`sync` 事件必须带 `server_ts`（网关/服务器对时戳）
- `uid` 设备内唯一（幂等键），`seq` 设备侧单调序号

## 异常识别规则（`app/detect.py`）

| 类型 | 规则 |
|---|---|
| 连续超限 `continuous_overlimit` | 温度 >250°C 或压力 >8bar，连续 ≥3 个采样点 |
| 缺失区间 `gap` | 相邻事件校正间隔 > max(30s, 4×该流中位间隔) |
| 计量跳变 `meter_jump` | 耗材相邻读数差 <0（回退）或 >50g（突增） |

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/devices` | 注册设备（返回一次性签名密钥） |
| GET | `/api/devices` / `/api/devices/{id}` | 设备列表 / 详情 |
| GET | `/api/devices/{id}/timeline` | 原始事件流 |
| POST | `/api/devices/{id}/timeline/build` | 重建时间线（新版本） |
| GET | `/api/devices/{id}/versions` | 校正版本列表 |
| GET | `/api/versions/{id}/timeline` | 校正事件 ↔ 原始事件对照 |
| POST | `/api/batches` | 开批次（`device_id/package_hash/total_chunks`，幂等） |
| GET | `/api/batches/{id}` | 批次状态（断点续传依据） |
| PUT | `/api/batches/{id}/chunks/{n}` | 上传分块 `{events:[…]}`；相同内容幂等，不同内容 `409 chunk_conflict` 保留首块 |
| POST | `/api/batches/{id}/commit` | 收齐后提交（幂等） |
| GET | `/api/findings?device_id=&status=` | 复核项列表 |
| POST | `/api/findings/{id}/review` | 复核 `{action:accept/reject/return, reviewer, note, review_seq}` |
| GET | `/api/findings/{id}/history` | 处理历史 |
| POST | `/api/reports/export` | 导出签名报告 `{device_id, version_id}` |
| POST | `/api/reports/verify` | 验证并加载 `{device_id, report}` |
| POST | `/api/seals` | 封存当前有效版本（复核须全部完成），返回封存包 + 一次性密钥 |
| GET | `/api/seals?device_id=` | 封存记录台账（仅元数据，不含密钥/事件正文） |

## 网页

- **设备**：台账、注册（返回一次性密钥）
- **批次导入**：粘贴/生成事件 → 分块上传（进度条、断点续传、重复包提示）→ 提交
- **时间线回放**：版本列表（漂移 ppm、状态）→ 曲线图（温度/压力 + 限值线 +
  超限点标红）→ 滑块回放 → 原始/校正对照表
- **风险复核**：按状态过滤，接受/驳回/退回重算（409 自动刷新），处理历史
- **审计报告**：导出签名报告（可下载 JSON）、粘贴验证加载
- **封存包**：按版本封存（显示可封存/待复核/已失效状态）、一次性密钥提示、
  下载封存包、复制离线核对命令、封存记录台账与退出码对照表

## 代码结构

```
app/
  db.py       SQLite schema + 不可变触发器（WAL + busy_timeout + 外键）
  core.py     规范化 JSON、HMAC 签名（设备密钥 + 封存一次性密钥）、ID 生成、ApiError
  clock.py    时钟漂移最小二乘拟合（纯函数）
  detect.py   连续超限 / 缺失区间 / 计量跳变识别（纯函数）
  guards.py   全部状态迁移（每个迁移一个 BEGIN IMMEDIATE 事务）+ 封存包生成
  server.py   stdlib HTTP：JSON API + SPA 静态托管
sealcli.py    离线封存包核对/导入 CLI（独立单文件，仅标准库，无服务无数据库）
tests/        33 个端到端不变量用例（含并发复核、失败回滚、离线 CLI、HTTP 冒烟）
seed.py       演示数据
web/          index.html / styles.css / app.js（原生 JS SPA）
```

数据库位置可用环境变量 `REPLAY_DB` 覆盖。
