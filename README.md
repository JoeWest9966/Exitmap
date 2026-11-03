# Exitmap

订阅 -> **唯一出口 IP** -> **每个 IP 一个固定本机端口**。

机场按出口 IP 计算额度，但一家机场常常把几个节点塞在同一个出口后面（实测某家机场：200 个候选节点只有 42 个不同的出口 IP）。轮流用"节点"等于把同一份额度花好几遍。exitmap 把这件事翻过来：先探出每个节点真实的**出口 IP**，按 IP 去重，然后给每个唯一 IP 一个稳定的本机端口。

```
127.0.0.1:31005   →  出口 IP 147.5.113.67 (CA)
127.0.0.1:31010   →  出口 IP 140.238.42.170 (JP)
```

端口就是产品：填进客户端，出口就是那个 IP，不随机、不偷换。

## 它做什么

每一轮（默认 5 分钟）：

1. **拉订阅**（默认 30 分钟一次，独立节奏）：用 `v2rayN/6.31` UA 拉取，解 base64 的节点 URI 列表。
2. **起 sing-box 侧车**：每个候选节点一个 socks inbound（`probeBase+i`，只用于探测，不对外），每个出口一个 `mixed` inbound（`portBase+slot`，socks5 + http 同端口）。
3. **穿节点探 IP**：手写 socks5 握手 + 明文 HTTP GET 探针，拿每个节点的真实出口 IP 和延迟。
4. **按 IP 分组**：一个 IP 下挑延迟最低的节点承载它。
5. **对账槽位**：活着的 IP 保留它原来的端口；消失的 IP 释放槽位，新 IP 按延迟补进来（= 换绑，见下）。
6. **仅在路由变化时**重写配置并重启 sing-box（`sing-box check` 通过才切换，配置坏了不会把在跑的打死）。

## 为什么不复用 zen-gate

zen-gate 也按出口 IP 分组，但三件事和这里要的不一样：

- 它是**每请求轮流**选出口，而这里要的是**端口↔IP 固定**；
- 它的 `MaxNodes = 64` 会静默丢掉超出的节点（实际订阅有 228 个，它只看前 64 个）；
- 它只有 socks inbound，这里用 `mixed`，HTTP 和 SOCKS5 都吃。

所以这个项目独立跑，自带订阅解析（`src/subs.rs` 从 zen-gate 的 `internal/subs/parse.go` 移植，MIT，见下方版权）。

## 换绑语义（重要）

你选的是**换绑**：一个 IP 死了，它的端口会交给下一个新 IP。

这有个代价：**客户端不会知道出口换了**。所以本项目的默认行为是"换绑 + 全程可见"：

- 每个端口在面板上永远显示**当前** IP、**从什么时候开始**占这个端口、**换绑过几次**；
- 每次换绑都进变更日志（`旧 IP → 新 IP`，带时间和原因）；
- 需要固定出口时，点「钉住」：钉住的端口绝不换 IP，IP 死了端口直接**关闭**（客户端拿到 connection refused，是明确的失败，不是静默的偷换）；钉住的 IP 回来就自动恢复。

## 面板

`http://127.0.0.1:18790/`（另有 Tailscale 地址，见 `listen`）

三个**真 URL** 的页面，底部 dock 切换（`pushState`，不整页刷新，可收藏、可后退）：

| 路径 | 页面 | 内容 |
|---|---|---|
| `/exits` | 出口端口表 | 端口 / IP / 地区 / 延迟 / 承载节点 / 状态 / 换绑次数；复制地址、钉住/解锁。**左列是订阅管理**（每条订阅一张卡：名字 / 该订阅贡献了多少节点 / 掩码地址 / 删除，底部折叠式「＋ 新增订阅」）。原先独立的 `/subs` 页已并入这里，旧链接会落到 `/exits` |
| `/log` | 换绑日志 | 每次「端口换 IP」的旧值、新值、时间、原因 |
| `/config` | 配置 | 端口 / 探测 / 日志三组旋钮，加一个端口与地址体检 |
| `/api` | API | 端点表（现读 OpenAPI 规范渲染）、密钥管理、限流额度、错误码、字段字典、试一下 |

底部 dock 是 macOS 浮动样式：鼠标靠近哪项哪项放大，tooltip 在项上方，当前页有强调色和圆点。视觉与交互参数照 [workbuddy-manager](https://github.com/ithtelab/workbuddy-manager) 的 `floating-dock`（MIT，Copyright (c) 2026 WorkBuddy Manager contributors），用原生 JS/CSS 重写 —— 本项目的面板没有 React 也没有构建步骤。

未知路径由后端 SPA fallback 兜到同一个 HTML，`/api/*` 仍然老实返回 404。

### API

给外部程序读出口表用的。**面板本身不需要它**，走的是另一条路。

```bash
curl -s -H "Authorization: Bearer exm_…" http://127.0.0.1:18790/api/v1/exits
```

返回里每个出口长这样（`proxies.socks5` 就是能直接填进客户端的地址）：

```json
{
  "port": 31001, "ip": "203.0.113.7", "country": "US", "latencyMs": 519,
  "alive": true, "pinned": false, "rebinds": 3,
  "upSinceMs": 1793628504838, "lastVerifiedMs": 1793631509170,
  "node":  { "name": "美国8", "proto": "hysteria2" },
  "proxies": { "socks5": "socks5://127.0.0.1:31001", "http": "http://127.0.0.1:31001" }
}
```

| 端点 | 说明 |
|---|---|
| `GET /api/v1/exits` | 出口列表。`?country=US,JP` `?alive=true` `?pinned=true` `?sort=latency` `?sort=-ip` `?limit=10` |
| `GET /api/v1/exits/{port}` | 单个出口，端口不存在给 404 |
| `GET /api/v1/meta` | 服务状态：版本、运行时长、上一轮探活时间、出口计数。给客户端自检用 |
| `GET /api/v1/openapi.json` | OpenAPI 3.0 规范。**唯一不需要密钥的端点**，它不泄露任何运行期信息 |

规则：

- **认证**：`Authorization: Bearer exm_…`。没有 `?key=` 形式 —— URL 会漏进日志、referer、shell history。
- **密钥**：面板「API」页新建，明文只显示一次；磁盘上只有 sha256（`/var/lib/exitmap/api-keys.json`，0600）。撤销立即生效。
- **限流**：默认 120 次/分钟/每个密钥，超了 `429` + `Retry-After`。0 = 不限。页面上可改。
- **错误码**：`401 missing_token` / `401 bad_token`（无效、抄错、已撤销三种故意不作区分）/ `404 no_such_port` / `429 rate_limited`。
- **兼容承诺（v1）**：字段只增不改，加字段不算破坏 —— 客户端必须忽略不认识的字段。删字段或改名开 `/api/v2`。

### 文档不会漂

端点表和字段字典**由页面现读 `/api/v1/openapi.json` 渲染**，不是两处手写。另外 `src/api.rs` 里三条单测把规范、DTO 和真实序列化结果三角对账：文档有而响应没有 → 红；响应有而文档没写 → 红。改字段忘了改文档，`cargo test` 直接拦住。

### 为什么不用 OpenAPI 代码生成

`utoipa` 那类 derive 宏能把标注变成规范，代价是给每个 handler 套一层宏和两个依赖。这里只有 4 个端点、1 个响应体，手写规范 + 一条对账测试更小、更直白，而且测试比宏更狠：宏只保证「标注和类型一致」，测试保证「文档和真实字节一致」。

## 配置页

每一项右边都标着**什么时候生效**，别猜：

| 徽标 | 意思 |
|---|---|
| 下一轮 | 只影响调度/判定，下一轮探活自然用上新值，不断连接 |
| 重载 sing-box | 要重写侧车配置并重启它，**现有连接会断一下** |
| 即时 | 按钮类操作，点了就跑 |

`端口段 / 监听地址 / UDP` 这三项变了会弹出二次确认，因为**所有已有客户端都要跟着改**（换端口）或者**协议面变了**（关掉 UDP）。

「体检」按钮做两件事：报出哪些端口正被别的进程占着（占了那个节点本轮会被跳过），以及每个监听地址是不是真的挂在本机上。体检会排除 Exitmap 自己侧车占用的端口 —— 否则它会把整张表报成"全被占"（这个坑真踩过：检测时旧实例还在跑，结果生成了零 inbound 的配置）。

## API

给外部程序读出口表用的。**面板本身不需要它**，走的是另一条路。

```bash
curl -s -H "Authorization: Bearer exm_…" http://127.0.0.1:18790/api/v1/exits
```

返回里每个出口长这样（`proxies.socks5` 就是能直接填进客户端的地址）：

```json
{
  "port": 31001, "ip": "203.0.113.7", "country": "US", "latencyMs": 519,
  "alive": true, "pinned": false, "rebinds": 3,
  "upSinceMs": 1793628504838, "lastVerifiedMs": 1793631509170,
  "node":  { "name": "美国8", "proto": "hysteria2" },
  "proxies": { "socks5": "socks5://127.0.0.1:31001", "http": "http://127.0.0.1:31001" }
}
```

| 端点 | 说明 |
|---|---|
| `GET /api/v1/exits` | 出口列表。`?country=US,JP` `?alive=true` `?pinned=true` `?sort=latency` `?sort=-ip` `?limit=10` |
| `GET /api/v1/exits/{port}` | 单个出口，端口不存在给 404 |
| `GET /api/v1/meta` | 服务状态：版本、运行时长、上一轮探活时间、出口计数。给客户端自检用 |
| `GET /api/v1/openapi.json` | OpenAPI 3.0 规范。**唯一不需要密钥的端点**，它不泄露任何运行期信息 |

规则：

- **认证**：`Authorization: Bearer exm_…`。没有 `?key=` 形式 —— URL 会漏进日志、referer、shell history。
- **密钥**：面板「API」页新建，明文只显示一次；磁盘上只有 sha256（`/var/lib/exitmap/api-keys.json`，0600）。撤销立即生效。
- **限流**：默认 120 次/分钟/每个密钥，超了 `429` + `Retry-After`。0 = 不限。页面上可改。
- **错误码**：`401 missing_token` / `401 bad_token`（无效、抄错、已撤销三种故意不作区分）/ `404 no_such_port` / `429 rate_limited`。
- **兼容承诺（v1）**：字段只增不改，加字段不算破坏 —— 客户端必须忽略不认识的字段。删字段或改名开 `/api/v2`。

### 文档不会漂

端点表和字段字典**由页面现读 `/api/v1/openapi.json` 渲染**，不是两处手写。另外 `src/api.rs` 里三条单测把规范、DTO 和真实序列化结果三角对账：文档有而响应没有 → 红；响应有而文档没写 → 红。改字段忘了改文档，`cargo test` 直接拦住。

### 为什么不用 OpenAPI 代码生成

`utoipa` 那类 derive 宏能把标注变成规范，代价是给每个 handler 套一层宏和两个依赖。这里只有 4 个端点、1 个响应体，手写规范 + 一条对账测试更小、更直白，而且测试比宏更狠：宏只保证「标注和类型一致」，测试保证「文档和真实字节一致」。

## 配置

`/etc/exitmap/config.json`（首次启动自动生成）：

| 键 | 默认 | 说明 |
|---|---|---|
| `listen` | `127.0.0.1:18790` | 面板监听地址 |
| `portBase` | `31001` | 出口端口起点（避开 zen-gate 的 21001+） |
| `probeBase` | `32001` | 探测端口起点（不对外） |
| `maxExits` | `128` | 出口槽位上限 |
| `countrySlots` | `""` | 端口↔国家固定，如 `"JP=31001-31020"`，也可在出口行点「国家」 |
| `maxProbeNodes` | `200` | 每轮最多探多少个节点（0 = 不限，轮转截断） |
| `refreshMinutes` | `5` | 探测轮节奏 |
| `subFetchMinutes` | `30` | 拉订阅节奏（跟机场换节点解耦，别每 5 分钟捶机场一次） |
| `probeUrl` | `http://api.ipify.org` | 探针地址，返回纯 IP |
| `probeConcurrency` | `24` | 探测并发 |
| `singBox` | `/usr/local/bin/sing-box` | 侧车可执行文件 |
| `exitListen` | `["127.0.0.1"]` | 出口端口绑哪些地址（可多条；`0.0.0.0` 通吃） |
| `disableUdp` | `false` | 出口端口只走 TCP |
| `probeFailThreshold` | `2` | 连续失败几次才把节点摘出轮询（1 = 一次就摘） |
| `maxLatencyMs` | `0` | 超时的出口不上表，0 = 不限 |
| `logRetentionDays` | `0` | 换绑日志保留天数，0 = 永久 |

状态落在 `/var/lib/exitmap/`：`sing-box.json`（生成的配置）、`sing-box.log`、`state.json`（槽位与换绑历史，重启不洗牌）。

### 端口固定国家

每个出口行上除了「复制」「钉住」还有一个「国家」按钮：点它选一个国家，这个端口从此只接该国的出口 IP。也可以在配置页直接写 `countrySlots`（按钮写的是同一份数据）：

```json
"countrySlots": "JP=31001-31020, US=31021-31040"
```

规则是**单向**的（`pool::slot_ok` 一个函数，测试盯着）：

- 端口被保留给某国 → 只接该国 IP；
- 没被保留的端口 → 谁都行；
- 该国 IP 全死时，端口就关着（客户端拿到 connection refused），不拿别国顶。

单向是有意的。反向规则（「某国只能用给它的端口」）会让「只给一个端口钉日本」变成「日本被掐到只剩一个端口」，其余日本 IP 全被丢弃。所以保留端口是**下限不是上限**：钉一个口不会限制该国其他出口，它们照常落在普通端口上。

点击按钮时：

- 该口已经是目标国家 → 只加规则，端口不动；
- 该口是别国 → 原来那个出口先让位，再从**高位**普通端口里拉一个目标国家的出口换进来（低位端口尽量不动，客户端钉的多半是 31001 这种）；
- 眼下没有目标国家的空闲出口 → 端口先关着，等下一轮有 IP 了自动补进来，面板提示会说实话。

每次移动都进换绑日志。`pinned` 与之正交：钉住 = 必须是**那一个** IP，它死了端口直接关；固定国家 = 只要是**那个国家**，谁活着都行。

改完立刻生效（会重排那几个端口），不用等下一轮。改 `portBase` 前必须先清空 `countrySlots`，否则段会指到错误的位置（直接 400 拒绝）。

国家码来自 ip-api.com 对新 IP 的查询；**查不到就不缓存、下轮重试**，否则一个 IP 会被永久记成「无国家」而永远匹配不上它的端口。

## 部署

```bash
cargo build --release --target-dir /opt/Exitmap/target
install -m 0644 /opt/Exitmap/deploy/exitmap.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now exitmap
journalctl -u exitmap -f
```

**必须先做的一步**：这台机器的 `net.ipv4.ip_local_port_range` 是 `1024-65535`，也就是任何固定端口都可能被自己的出站连接当成源端口抢走 —— 实测 sing-box 启动时被 crowdsec 的一条回环连接抢掉 32036 直接 fatal。所以端口段要预留：

```bash
# /etc/sysctl.d/90-exitmap-ports.conf
net.ipv4.ip_local_reserved_ports = 18788-18799,21001-21300,31001-31128,32001-32400
```

即便如此，仍可能有进程先占住某个端口，所以 exitmap 每轮会先试探每个端口能否 bind，**被占的那个节点这一轮直接跳过**，不会拖垮整张表。

## 安全边界

面板**没有鉴权**：能看出口表、能增删订阅（URL 回显只露 `?key=***`），只是靠下面两层挡着。
（`/api/v1/*` 是另一回事：那条路**必须**带 API key。「面板不需要 key」是有意的 —— 浏览器里放 key 等于把 key 写进 HTML。）

**API key 泄露不等于代理权限泄露**：出口端口本来就不认证，key 泄出去泄的是**你的出口 IP 清单**（哪些国家、哪些 IP 在跑），不是别人的代理权限。

1. `listen` 默认只绑 `127.0.0.1`；要远程访问才加上 Tailscale 之类的私有地址（不要绑 `0.0.0.0`）；
2. 防火墙只放行该网段（例如 `ufw allow from 100.64.0.0/10 to any port 18790 proto tcp`）。

**不要把它暴露到公网。** 出口端口是无认证的 socks5/http 代理，谁连上谁的流量就从你的机场出口走。
把 `exitListen` 加上局域网/Tailscale 地址等于**把这份额度开放给那个网段的所有人** —— 想让别的设备用才加，加了心里要有数。

## 版权

完整的第三方声明见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。底部 dock 的视觉与交互参数取自 [workbuddy-manager](https://github.com/ithtelab/workbuddy-manager) 的 `web/components/ui/floating-dock.tsx`，MIT，Copyright (c) 2026 WorkBuddy Manager contributors；`assets/index.html` 里是用原生 JS 重写的版本，没有引入 React 或 motion。

`src/subs.rs`（节点 URI 解析）移植自 [zen-gate](https://github.com/LAGcomcom/zen-gate) 的 `internal/subs/parse.go`，MIT，Copyright (c) 2026 LAGcomcom。那些解析上的坑（`*_auto` uTLS 别名、`fp=unsafe` 会让整份配置被 sing-box 拒掉、ss 的三种 base64 形状）是真金白银换来的，所以是移植而不是重写。
