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
python3 -m unittest tests.test_replay -v   # 22 个用例（含 HTTP 全链路冒烟）
```

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

## 网页

- **设备**：台账、注册（返回一次性密钥）
- **批次导入**：粘贴/生成事件 → 分块上传（进度条、断点续传、重复包提示）→ 提交
- **时间线回放**：版本列表（漂移 ppm、状态）→ 曲线图（温度/压力 + 限值线 +
  超限点标红）→ 滑块回放 → 原始/校正对照表
- **风险复核**：按状态过滤，接受/驳回/退回重算（409 自动刷新），处理历史
- **审计报告**：导出签名报告（可下载 JSON）、粘贴验证加载

## 代码结构

```
app/
  db.py       SQLite schema + 不可变触发器（WAL + busy_timeout + 外键）
  core.py     规范化 JSON、HMAC 签名、ID 生成、ApiError
  clock.py    时钟漂移最小二乘拟合（纯函数）
  detect.py   连续超限 / 缺失区间 / 计量跳变识别（纯函数）
  guards.py   全部状态迁移（每个迁移一个 BEGIN IMMEDIATE 事务）
  server.py   stdlib HTTP：JSON API + SPA 静态托管
tests/        22 个端到端不变量用例（含并发复核、失败回滚、HTTP 冒烟）
seed.py       演示数据
web/          index.html / styles.css / app.js（原生 JS SPA）
```

数据库位置可用环境变量 `REPLAY_DB` 覆盖。
