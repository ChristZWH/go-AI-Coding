# go-AI-Coding — Banner 指纹识别系统

基于 Golang 的 Banner 指纹识别系统：接收一批网络扫描原始数据（`ip`、`port`、`banner`），
识别出对应的**协议、软件产品与版本**（并可给出操作系统提示），采用 **client + server** 架构，
以 **Docker Compose 一键启动** 方式交付。

## 功能特性

- `POST /fingerprint` 批量识别 + `GET /health` 健康检查
- 内置识别：SSH（OpenSSH/dropbear 系）、HTTP（nginx/Apache/Jetty/IIS）、MySQL/MariaDB、
  Redis、FTP（ProFTPD/vsFTPd/Pure-FTPd）、TLS 握手
- 识别不出 → `protocol: "unknown"`（正常业务结果）；任何脏数据都不会导致服务报错或崩溃
- **规则与代码完全解耦**：识别规则是 JSON 文件，新增协议只需追加一条规则，无需重新编译
- 生产级容器化：多阶段构建、非 root、只读文件系统、cap_drop ALL、内部网络、真实健康检测

## 架构

```text
┌───────────┐   HTTP POST /fingerprint   ┌──────────────────┐
│  client   │ ─────────────────────────> │      server      │
│ (独立程序) │  [{"ip","port","banner"}]  │  (HTTP + 规则引擎) │
│           │ <───────────────────────── │                  │
│ 读本地JSON │  [{"ip","port","protocol", │  规则文件(JSON)   │
│ 表格化展示  │   "product","version",     │  schema 化，      │
└───────────┘   "os_hint","confidence"}] │  可外部挂载覆盖    │
                                         └──────────────────┘
```

## 快速开始

### 方式一：Docker Compose 一键启动（推荐）

```bash
docker compose up
```

- `server` 启动并通过健康检查后，`client` 自动读取 `testdata/sample_input.json`
  发送到 server 并打印识别结果表格，随后退出（一次性任务，`exit 0` 属预期）。
- server 对外发布 `8080` 端口，可直接验证：

```bash
curl -s http://localhost:8080/health
curl -s -X POST http://localhost:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
       {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}]'
```

### 方式二：本地运行（不依赖 Docker）

```bash
# 终端一：启动 server
go run ./cmd/server

# 终端二：运行 client
go run ./cmd/client -f testdata/sample_input.json --server http://localhost:8080
```

### 方式三：编译独立二进制

```bash
go build -o fp-server ./cmd/server
go build -o fp-client ./cmd/client
./fp-server &                                  # 监听 :8080
./fp-client -f testdata/sample_input.json --server http://localhost:8080
```

## API 文档

### POST /fingerprint（批量识别）

请求体：`[{ip, port, banner}, ...]` 数组。

```json
[{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应：与输入**等长、同序**的结果数组，`ip`/`port` 原样回显；识别不出的条目返回
`protocol: "unknown"`、`confidence: 0`，**不会**因此报错：

```json
[
  {"ip": "1.2.3.4", "port": 22, "protocol": "SSH", "product": "OpenSSH",
   "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95},
  {"ip": "1.2.3.23", "port": 12345, "protocol": "unknown", "product": "",
   "version": "", "os_hint": "", "confidence": 0}
]
```

- 非法 JSON → `400 {"error": "..."}`
- 非 POST → `405`
- 请求体上限 8 MiB（防超大请求拖垮服务）

### GET /health（健康检查）

```json
{"status": "ok"}
```

该接口被 Docker Compose healthcheck 真实调用（非 TCP 探测），
client 容器在 server 变为 `healthy` 之后才启动。

## 识别规则与扩展（规则与代码解耦）

所有识别逻辑由规则文件驱动，程序代码**不硬编码任何协议**。规则文件 schema：

```json
{
  "schema": 1,
  "rules": [
    {
      "name": "ssh",
      "protocol": "SSH",
      "pattern": "^SSH-[\\d.]+-([^\\s_]+)(?:_([^\\s]+))?(?:[\\s-]+(\\S+))?",
      "case_insensitive": true,
      "port_hint": [22],
      "product":  {"group": 1},
      "version":  {"group": 2},
      "os_hint":  {"group": 3, "strip_suffix": "-[0-9]+"},
      "confidence": 0.95
    }
  ]
}
```

字段取值方式：`static`（固定值）或 `group`（正则捕获组，从 1 起），可选
`strip_prefix` / `strip_suffix` 变换；`confidence` 为命中置信度（自动钳位到 0~1）。
规则按数组顺序求值，**首条命中即返回**。`pattern` 为空 + 配置 `port_hint` 的规则
是"端口弱信号"：仅当 banner 为空时按端口给出低置信（0.5）猜测。

### 新增一种协议（以 Elasticsearch 为例）

1. 创建自定义规则文件 `custom-rules.json`（内嵌默认规则见 `internal/engine/rules/default.json`，
   可整体复制后追加）：

   ```json
   {
     "schema": 1,
     "rules": [
       {"name": "elasticsearch", "protocol": "Elasticsearch",
        "pattern": "\"version\"\\s*:\\s*\\{\\s*\"number\"\\s*:\\s*\"([^\"]+)\"",
        "product": {"static": "Elasticsearch"}, "version": {"group": 1},
        "confidence": 0.9}
     ]
   }
   ```

2. 本地验证：

   ```bash
   FP_RULES_FILE=custom-rules.json go run ./cmd/server
   ```

3. Docker 中生效（挂载 + 环境变量，无需重新编译镜像）：

   ```yaml
   server:
     volumes:
       - ./custom-rules.json:/etc/fp/rules.json:ro
     environment:
       FP_RULES_FILE: /etc/fp/rules.json
   ```

规则加载优先级：`FP_RULES_FILE` 外部规则 > 内嵌默认规则（外部加载失败自动回退并告警）。

## 置信度策略

| 场景 | confidence |
|---|---|
| banner 强特征 + 产品 + 版本齐全 | 0.9 ~ 0.95 |
| 有产品无版本（如 `+PONG`、Pure-FTPd） | 0.7 ~ 0.85 |
| 仅协议级特征（无 Server 头的 HTTP、generic 220） | 0.6 |
| banner 为空时的端口弱信号 | 0.5 |
| unknown | 0 |

## 生产化设计说明

- **多阶段构建**：`golang:alpine` 编译（`CGO_ENABLED=0` 静态编译、`-trimpath`、`-s -w`）
  → `alpine` 最小运行镜像，不含编译工具链
- **权限收紧**：容器以非 root 用户运行；`read_only: true` 只读文件系统；
  `cap_drop: [ALL]` 丢弃全部能力；`no-new-privileges: true`
- **访问收敛**：client 与 server 之间仅通过内部网络（`internal: true`，无外网出口）
  以服务名互访；仅 server 对外发布 8080
- **真实健康检测**：healthcheck 调 `GET /health`；client `depends_on: service_healthy`
- **规则解耦**：见上节，规则文件可挂载覆盖

## 测试

```bash
go test ./...        # 单元 + 接口测试（含 20 条示例数据的完整断言）
```

## 目录结构

```text
.
├── cmd/
│   ├── server/main.go      # server 入口（HTTP + 规则加载）
│   └── client/main.go      # client 入口（读文件 → 发请求 → 表格展示）
├── internal/
│   ├── engine/             # 规则引擎（schema 化规则、预编译、零协议硬编码）
│   │   └── rules/default.json  # 内嵌默认识别规则
│   ├── httpserver/         # HTTP 接口层（recover/超时/限体）
│   └── model/              # 输入/输出数据结构
├── testdata/sample_input.json  # 自测数据（20 条）
├── Dockerfile              # 多阶段构建
├── docker-compose.yml      # 一键启动
└── go.mod
```
