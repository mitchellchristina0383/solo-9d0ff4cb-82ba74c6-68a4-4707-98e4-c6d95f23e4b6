# lab.test 主从权威 DNS（Python / FastAPI / SQLite）

网络管理员批量更新 `lab.test` 仪器地址的最小可用主从权威 DNS：

- **主节点**（`dnslab/master_app.py`）：通过 HTTP API（Swagger UI 在 `/docs`）维护 A 记录全集；
  每次发布（单条增删改或整体批量替换）在**一个 SQLite 事务**内完成记录变更、
  SOA 序列号递增（从 1 开始每次 +1）、并落一份带 SHA-256 校验和的**不可变快照**。
- **从节点**（`dnslab/slave_app.py`）：经 HTTP 从主节点拉取整份快照，校验通过且序列号
  严格更新后才生效；以 UDP 回答 `A` / `SOA` 查询，对域内不存在的名字回答 `NXDOMAIN`
  （authority 带本版 SOA），域外查询 `REFUSED`。
- **反射放大监测**（`dnslab/monitor.py`，仅从节点）：把每个 DNS 事务按
  **应答字节 / 请求字节**计算放大倍数，按报文**声称的源 IPv4 /24** 统计最近 60 秒窗口内
  达到倍数门槛的事务；次数达到门槛即开风险事件，持续超标只更新、低于门槛即关闭、
  再次超标另开新事件。

## 一致性保证

| 场景 | 行为 |
|---|---|
| 发布与拉取交错 | 快照是主节点单事务读出的不可变版本；从节点要么整体应用某版本，要么不应用 |
| 并发同步 | 从节点同步串行化；应用前在锁内复查序列号，最终版本一定是见过的最大序列号 |
| 中途断流 / 数据被改 | 传输中断 → 拉取报错；SHA-256 校验失败 → 拒绝；现役版本不受影响 |
| 迟到旧版 | 序列号 ≤ 现役版本的一律拒绝（`applied: false`），不会覆盖新版 |
| 记录与 SOA 同版 | 每条应答都由同一个不可变 `ZoneData` 对象生成，SOA 序列号与记录同属一版 |
| 主节点失联 | 从节点继续用最后一次成功同步的版本应答；`/sync` 报 502 但不影响应答 |
| 从节点重启 | 启动时从 SQLite 恢复最后成功版本，无需先同步即可应答 |
| 初次同步失败 | 没有任何版本时回答 `SERVFAIL`（不可用），绝不凭空应答 |

## 运行

### Docker Compose（推荐）

```bash
docker compose up --build
```

- 主节点 API / 文档： http://localhost:8000/docs
- 从节点 API / 文档： http://localhost:8001/docs
- 从节点 DNS： `dig @127.0.0.1 -p 5353 host1.lab.test A` ／ `dig @127.0.0.1 -p 5353 lab.test SOA`

从节点数据在命名卷 `slave-data` 中，`docker compose restart slave` 后仍用最后版本应答。

### 本地（无 Docker）

```bash
pip install -r requirements.txt
MASTER_DB=/tmp/master.db uvicorn dnslab.master_app:app --port 8000 &
SLAVE_DB=/tmp/slave.db MASTER_URL=http://127.0.0.1:8000 DNS_PORT=5353 \
  uvicorn dnslab.slave_app:app --port 8001 &
```

## 使用（均可在 `/docs` 中操作）

```bash
# 批量发布仪器地址（一次事务、一个新序列号）
curl -X POST http://localhost:8000/records/bulk -H 'Content-Type: application/json' -d '{
  "records": [
    {"name": "host1.lab.test", "ip": "10.0.0.1"},
    {"name": "host2.lab.test", "ip": "10.0.0.2", "ttl": 60}
  ]}'

# 单条增改 / 删除
curl -X PUT  http://localhost:8000/records/host3.lab.test -H 'Content-Type: application/json' -d '{"ip": "10.0.0.3"}'
curl -X DELETE http://localhost:8000/records/host2.lab.test

# 查看主节点现役序列号 / 完整快照
curl http://localhost:8000/zone/serial
curl http://localhost:8000/zone/snapshot

# 从节点：发起同步、查看现役序列号
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
curl http://localhost:8001/status
```

`POST /sync` 可选参数：`{"serial": N}` 拉取指定历史版本（主节点保留最近
`KEEP_VERSIONS=100` 版，主要用于测试迟到旧版）；`{"url": ...}` 覆盖快照来源。
设 `SYNC_INTERVAL=秒数` 可让从节点周期自动同步（默认 0，仅手动）。

## 反射放大风险监测（从节点）

UDP 源地址可以伪造，只作为**声称的来源**；统计一律聚合到源 IPv4 `/24` 网段。

- 每个可解析事务按 `应答线格式字节 / 请求线格式字节` 计算放大倍数；
- 倍数 ≥ `min_factor`（默认 2.0）的事务为“达标事务”，按源 `/24` 计入最近
  `MONITOR_WINDOW_SECONDS`（默认 60）秒滚动窗口；
- 某网段窗口内达标事务数 ≥ `min_events`（默认 5）即**开事件**；持续超标只更新
  同一事件的次数与字节计数；窗口滚动使计数低于门槛即**关闭**；之后再次超标
  **另开新事件**（事件 id 不复用）；
- 2 秒（`MONITOR_DEDUP_SECONDS`）内同一**五元组 + 事务 ID + 问题**的重传只计一次；
- 更改任一门槛：所有在开事件立即关闭，再用窗口内的**原始事务**按新门槛重新判定，
  达标的网段开新事件；
- 事务、事件、门槛都在从节点 SQLite（与区域同库），并发查询由单写线程串行化，
  **进程重启后窗口与事件接续**；
- 监测写入失败时 `/monitor/*` 接口报 **503 不可用**（`/monitor/health` 可查原因），
  写入恢复后自动回到可用；**DNS 应答始终按原规则进行，不受监测故障影响**。

门槛与事件均可在从节点 `/docs` 操作：

```bash
# 查看 / 修改门槛（倍数、次数，可只给一个）
curl http://localhost:8001/monitor/config
curl -X PUT http://localhost:8001/monitor/config \
  -H 'Content-Type: application/json' -d '{"min_factor": 3.0, "min_events": 10}'

# 查看事件（status=open|closed|all）与当前窗口的分网段统计
curl 'http://localhost:8001/monitor/events?status=open'
curl http://localhost:8001/monitor/window
curl http://localhost:8001/monitor/health
```

事件字段：网段 `subnet`、窗口内达标次数 `count`、累计请求/应答字节
`req_bytes`/`resp_bytes`、起 `started_at` / 止 `ended_at` 时刻，以及该事件适用的
`min_factor`/`min_events`。环境变量 `MONITOR_MIN_FACTOR`、`MONITOR_MIN_EVENTS`、
`MONITOR_WINDOW_SECONDS`、`MONITOR_DEDUP_SECONDS` 可改默认值。
`POST /monitor/debug/fault?enabled=true` 仅用于故障注入测试，生产应移除。

## 自测

```bash
python tests/selftest.py    # 需要已安装 requirements.txt
```

脚本拉起真实主从进程，覆盖：初次同步失败报不可用、发布/同步/应答、批量更新原子切换、
迟到旧版拒绝、断流与校验和损坏、并发发布+同步交错（序列号单调、最终内容逐条一致）、
主节点失联、从节点重启、新从节点+主失联、`/docs` 可用性与主恢复后的同步；
以及反射放大监测的 2 秒重传去重、事件开/关/再开、门槛变更后按原始事务重判、
监测写入失败报 503 但 DNS 照常应答、进程重启后窗口与事件接续。

## 目录

```
dnslab/dnsproto.py    最小 DNS 线格式编解码与应答逻辑（仅标准库）
dnslab/master_app.py  主节点 FastAPI 应用
dnslab/slave_app.py   从节点 FastAPI 应用 + UDP DNS 服务 + 监测 API
dnslab/monitor.py     反射放大监测：SQLite 滚动窗口、事件状态机、单写线程服务
tests/selftest.py     端到端自测
Dockerfile / docker-compose.yml
```

## 已知限制

- 仅 UDP、仅 `A`/`SOA`/`ANY` 查询；不支持 TCP、EDNS、IXFR/AXFR、DNSSEC、NOTIFY。
- 序列号比较用简单“严格大于”（本系统序列号从 1 单调 +1，未实现 RFC 1982 回绕比较）。
- 快照为全量传输，适合 lab 规模；超大区域需增量机制。
- 从节点应用快照时的 SQLite 写入在事件循环内完成，记录数极大时会短暂阻塞循环（lab 规模无感）。
- 监测只统计从节点实际应答的 UDP 事务，且仅按 IPv4 源 `/24` 聚合；不可解析的报文、
  TCP/EDNS 流量不在统计内。窗口事务全部保留在 SQLite 中，超高流量场景应加分区/清理策略。
- 主节点 `/debug/snapshot/truncated`、`/debug/snapshot/corrupt` 与从节点
  `/monitor/debug/fault` 仅用于故障注入测试，生产应移除。
