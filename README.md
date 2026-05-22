# Akamai SIEM Log Consumer

从 Akamai SIEM API 拉取安全事件日志，经过可配置的字段处理后转发到 Logstash。

## 功能特性

- **两种拉取模式**：基于偏移量（offset）和基于时间范围（time-based）
- **断点续传**：使用 Redis 存储断点，重启后自动从上次位置继续；断点不存在时自动回退为 time-based 模式
- **可配置的事件处理**：丢弃规则、字段转换（URL 解码/字符串替换）、attackData Base64 解码，均通过配置驱动
- **高性能**：预编译处理上下文、流式响应解析、TCP 长连接复用、分批发送
- **运行模式**：单次执行（once）或持续服务（service），支持 SIGTERM/SIGINT 优雅退出
- **环境变量支持**：配置文件中可使用 `${ENV_VAR}` 或 `${ENV_VAR:default}` 引用环境变量

## 项目结构

```
├── main.py                     # 入口文件（编排层）
├── config.yaml                 # 配置文件（YAML 格式）
├── requirements.txt            # Python 依赖
└── akamai_siem/
    ├── __init__.py
    ├── logging_setup.py        # 日志系统（stdout 输出）
    ├── config.py               # 配置加载、验证、命令行解析
    ├── api.py                  # Akamai SIEM API 调用
    ├── processor.py            # 事件字段处理（可配置）
    ├── sender.py               # Logstash 发送（TCP/UDP）
    └── resume.py               # 断点续传（Redis）
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

复制并编辑配置文件：

```bash
cp config.yaml config.yaml.local
```

必须配置的部分：
- `akamai` — API 凭证和 configId
- `logstash` — 目标 Logstash 地址和端口
- `resume.redis` — Redis 连接信息

### 3. 运行

```bash
# 单次运行
python main.py --once --config config.yaml

# 服务模式（持续拉取）
python main.py --service --config config.yaml

# 指定 offset 单次拉取
python main.py --once --offset "your_offset_value"

# 指定时间范围
python main.py --once --mode time-based --from-time "2024-01-01T00:00:00"
```

## 配置说明

### 基本参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `site` | 站点标识，写入每条事件 | `all` |
| `mode` | 拉取模式：`offset` 或 `time-based` | `offset` |
| `limit` | 每次拉取的最大事件数 | `1000` |
| `log_level` | 日志级别：debug/info/warning/error | `info` |

### Akamai API 配置

```yaml
akamai:
  base_url: "https://your-host.luna.akamaiapis.net"
  client_token: "${AKAMAI_CLIENT_TOKEN}"
  client_secret: "${AKAMAI_CLIENT_SECRET}"
  access_token: "${AKAMAI_ACCESS_TOKEN}"
  configId: "12345"
  max_retries: 3        # API 调用失败重试次数
  retry_delay: 5        # 重试初始间隔（秒），指数退避
  api_timeout: 30       # 请求超时（秒）
```

### 断点续传配置

```yaml
resume:
  enabled: true
  fallback_minutes: 30   # 断点不存在时回退的时间窗口
  redis:
    host: "${REDIS_HOST:127.0.0.1}"
    port: 6379
    db: 0
    password: "${REDIS_PASSWORD:}"
    socket_timeout: 5
  key_prefix: "akamai_siem:resume"
  ttl: null              # 可选 TTL（秒），null 表示永不过期
```

### 事件处理配置

`processing` 段为可选配置。不配置时不做任何字段处理，原样转发。

```yaml
processing:
  # 丢弃规则：字段值匹配时整条事件被丢弃
  drop_rules:
    - field: httpMessage.status
      values: [204, "204"]

  # 字段转换：对指定字段依次执行操作链
  field_transforms:
    - field: httpMessage.requestHeaders
      operations:
        - type: url_decode
        - type: replace
          old: "\r\n"
          new: " "

  # attackData 解码
  attack_data_decode:
    enabled: true
    source_field: attackData
    target_field: attackRules
    key_pattern: "^rule"
    remove_decoded_keys: true
```

**支持的转换操作：**

| 操作类型 | 参数 | 说明 |
|----------|------|------|
| `url_decode` | 无 | URL 解码 |
| `replace` | `old`, `new` | 字符串替换 |

**字段路径：** 支持点号分隔的嵌套路径，如 `httpMessage.requestHeaders`。

### 服务模式配置

```yaml
service:
  interval: 5              # 拉取间隔（秒）
  max_consecutive_failures: 10  # 连续失败次数上限，达到后退出
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--config` | 配置文件路径（默认 `config.yaml`） |
| `--mode` | 拉取模式：`offset` / `time-based` |
| `--offset` | 指定偏移量 |
| `--from-time` | 开始时间（ISO 格式或 Unix 时间戳） |
| `--to-time` | 结束时间 |
| `--limit` | 每次拉取数量 |
| `--log-level` | 日志级别 |
| `--service` | 以服务模式运行 |
| `--once` | 只运行一次 |

配置优先级：命令行参数 > 配置文件 > 默认值

## 失败处理策略

| 阶段 | 策略 |
|------|------|
| API 拉取失败 | 指数退避重试（最多 3 次），不更新断点，下次重拉 |
| 事件处理失败 | 单条失败跳过该条，其余正常处理 |
| Logstash 发送失败 | TCP 自动重连一次，失败后不更新断点，下次重拉重发 |
| Redis 断点保存失败 | 记录错误日志，不影响主流程 |

## 环境变量

配置文件中支持环境变量引用：

```yaml
# 完整替换
password: "${REDIS_PASSWORD}"

# 带默认值
host: "${REDIS_HOST:127.0.0.1}"

# 内联替换
url: "https://${API_HOST}/path"
```

## 依赖

- Python 3.8+
- edgegrid-python — Akamai EdgeGrid 认证
- requests — HTTP 客户端
- redis — Redis 客户端
- PyYAML — YAML 配置解析
- ujson（可选）— 高性能 JSON 序列化
