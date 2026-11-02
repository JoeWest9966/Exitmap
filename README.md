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
| `/exits` | 出口端口表 | 端口 / IP / 地区 / 延迟 / 承载节点 / 状态 / 换绑次数；复制地址、钉住/解锁 |
| `/subs` | 订阅 | 新增（URL 只写不显）/ 删除 |
| `/log` | 换绑日志 | 每次「端口换 IP」的旧值、新值、时间、原因 |

底部 dock 是 macOS 浮动样式：鼠标靠近哪项哪项放大，tooltip 在项上方，当前页有强调色和圆点。视觉与交互参数照 [workbuddy-manager](https://github.com/ithtelab/workbuddy-manager) 的 `floating-dock`（MIT，Copyright (c) 2026 WorkBuddy Manager contributors），用原生 JS/CSS 重写 —— 本项目的面板没有 React 也没有构建步骤。

未知路径由后端 SPA fallback 兜到同一个 HTML，`/api/*` 仍然老实返回 404。

## 配置

`/etc/exitmap/config.json`（首次启动自动生成）：

| 键 | 默认 | 说明 |
|---|---|---|
| `listen` | `127.0.0.1:18790` | 面板监听地址 |
| `portBase` | `31001` | 出口端口起点（避开 zen-gate 的 21001+） |
| `probeBase` | `32001` | 探测端口起点（不对外） |
| `maxExits` | `128` | 出口槽位上限 |
| `maxProbeNodes` | `200` | 每轮最多探多少个节点（0 = 不限，轮转截断） |
| `refreshMinutes` | `5` | 探测轮节奏 |
| `subFetchMinutes` | `30` | 拉订阅节奏（跟机场换节点解耦，别每 5 分钟捶机场一次） |
| `probeUrl` | `http://api.ipify.org` | 探针地址，返回纯 IP |
| `probeConcurrency` | `24` | 探测并发 |
| `singBox` | `/usr/local/bin/sing-box` | 侧车可执行文件 |

状态落在 `/var/lib/exitmap/`：`sing-box.json`（生成的配置）、`sing-box.log`、`state.json`（槽位与换绑历史，重启不洗牌）。

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

## 版权

底部 dock 的视觉与交互参数取自 [workbuddy-manager](https://github.com/ithtelab/workbuddy-manager) 的 `web/components/ui/floating-dock.tsx`，MIT，Copyright (c) 2026 WorkBuddy Manager contributors；`assets/index.html` 里是用原生 JS 重写的版本，没有引入 React 或 motion。

`src/subs.rs`（节点 URI 解析）移植自 [zen-gate](https://github.com/LAGcomcom/zen-gate) 的 `internal/subs/parse.go`，MIT，Copyright (c) 2026 LAGcomcom。那些解析上的坑（`*_auto` uTLS 别名、`fp=unsafe` 会让整份配置被 sing-box 拒掉、ss 的三种 base64 形状）是真金白银换来的，所以是移植而不是重写。
