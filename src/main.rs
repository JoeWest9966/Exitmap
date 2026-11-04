// exitmap — subscription -> unique egress IP -> one fixed local port per IP.
//
// Every round: (re)fetch the subscriptions, probe every node through its own
// sing-box socks inbound, group the results by real egress IP, and hand each
// unique IP a stable localhost port. The port is the product: filling
// 127.0.0.1:31005 into a client means "exit from that IP" and nothing else.

mod api;
mod pool;
mod probe;
mod singbox;
mod subs;

use anyhow::Result;
use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use pool::{ExitView, LiveIp, Pool, Rebind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify, RwLock};

const PANEL: &str = include_str!("../assets/index.html");

fn default_clash_api_port() -> u16 {
    18791
}

/// 32 hex chars from /dev/urandom. The control port is loopback-only, but a
/// guessable secret would still let anything on the box re-point your exits.
fn random_secret() -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok();
    if !ok {
        let t = format!("{}-{}", now_ms(), std::process::id());
        b[..8].copy_from_slice(&(t.len() as u64).to_le_bytes());
        b[8..].copy_from_slice(&now_ms().to_le_bytes());
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── config ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Sub {
    id: String,
    name: String,
    url: String,
    enabled: bool,
}

impl Default for Sub {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Config {
    listen: String,
    /// First port handed to an exit. 31001 sits clear of zen-gate's 21001+.
    port_base: u16,
    /// First probe-only inbound. One per candidate node, never exposed.
    probe_base: u16,
    /// Loopback port for sing-box's Clash API. It is how an exit port is
    /// re-pointed at another node without restarting the sidecar.
    #[serde(default = "default_clash_api_port")]
    clash_api_port: u16,
    /// Where exit ports listen. Multiple addresses allowed: loopback plus a
    /// private interface (LAN / tailnet) is the point.
    exit_listen: Vec<String>,
    max_exits: usize,
    /// Country → port reservations, `"JP=31001-31020, US=31021-31040"`.
    /// Empty = every slot is a free-for-all (the pre-feature behaviour).
    country_slots: String,
    /// TCP only on exit ports (UDP is rejected by a route rule).
    disable_udp: bool,
    /// Cap on candidates probed per round. 0 = no cap.
    max_probe_nodes: usize,
    /// A node is dropped from the pool only after this many consecutive failed
    /// probes — one flaky round should not cost you an exit.
    probe_fail_threshold: usize,
    /// Exits slower than this are kept out of the table. 0 = no limit.
    max_latency_ms: u64,
    /// Rebind-log retention. 0 = keep forever.
    log_retention_days: u64,
    refresh_minutes: u64,
    sub_fetch_minutes: u64,
    probe_url: String,
    probe_timeout_ms: u64,
    probe_concurrency: usize,
    sing_box: String,
    data_dir: String,
    /// Public API requests allowed per key per minute. 0 = unlimited.
    api_rate_limit: u32,
    subscriptions: Vec<Sub>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18790".into(),
            port_base: 31001,
            probe_base: 32001,
            clash_api_port: default_clash_api_port(),
            exit_listen: vec!["127.0.0.1".into()],
            max_exits: 128,
            country_slots: String::new(),
            disable_udp: false,
            max_probe_nodes: 200,
            probe_fail_threshold: 2,
            max_latency_ms: 0,
            log_retention_days: 0,
            refresh_minutes: 5,
            sub_fetch_minutes: 30,
            probe_url: "http://api.ipify.org".into(),
            probe_timeout_ms: 8000,
            probe_concurrency: 24,
            sing_box: "/usr/local/bin/sing-box".into(),
            data_dir: "/var/lib/exitmap".into(),
            api_rate_limit: api::DEFAULT_RATE_PER_MIN,
            subscriptions: Vec::new(),
        }
    }
}

fn config_path() -> PathBuf {
    match std::env::var("EXITMAP_CONFIG") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from("/etc/exitmap/config.json"),
    }
}

fn load_config() -> Config {
    let p = config_path();
    match std::fs::read_to_string(&p) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            eprintln!("[exitmap] {} 解析失败({e}),用默认值", p.display());
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

fn save_config(cfg: &Config) -> Result<()> {
    let p = config_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).ok();
    }
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(cfg)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

// ── runtime state ─────────────────────────────────────────────────────────────

/// One subscription's last fetch outcome, so the panel can show which feed is
/// actually contributing instead of an undifferentiated sum.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubStat {
    id: String,
    nodes: usize,
    error: String,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    last_run_ms: i64,
    last_ok_ms: i64,
    next_run_ms: i64,
    round_ms: u64,
    nodes: usize,
    live_ips: usize,
    exits_open: usize,
    probes_ok: usize,
    probes_fail: usize,
    last_sub_fetch_ms: i64,
    last_error: String,
    singbox_alive: bool,
    /// A round is in flight. The panel uses it to refuse a second click instead
    /// of silently queueing a whole extra minute of probing.
    running: bool,
}

#[derive(Default)]
struct Inner {
    pool: Pool,
    nodes: Vec<subs::Node>,
    status: Status,
    /// node id -> consecutive failed probes (cleared by one success).
    node_fails: HashMap<String, usize>,
    /// node id -> last good (egress ip, latency). Lets a node that missed one
    /// probe keep its exit instead of triggering a rebind.
    node_last: HashMap<String, (String, u64)>,
    sub_stats: Vec<SubStat>,
    keys: api::KeyStore,
    limiter: api::Limiter,
}

struct App {
    started_ms: i64,
    cfg: RwLock<Config>,
    inner: RwLock<Inner>,
    sidecar: Mutex<singbox::Sidecar>,
    /// Control channel into the running sidecar. Generated per process: it only
    /// ever listens on loopback, and a restart of exitmap rewrites the config
    /// anyway, so there is nothing to persist.
    clash: singbox::ClashApi,
    wake: Notify,
}

impl App {
    fn singbox_conf(&self, data_dir: &str) -> PathBuf {
        PathBuf::from(data_dir).join("sing-box.json")
    }
    fn singbox_log(&self, data_dir: &str) -> PathBuf {
        PathBuf::from(data_dir).join("sing-box.log")
    }
    fn state_path(data_dir: &str) -> PathBuf {
        PathBuf::from(data_dir).join("state.json")
    }

    fn persist_pool(data_dir: &str, pool: &Pool, last_sub_fetch_ms: i64) -> Result<()> {
        std::fs::create_dir_all(data_dir).ok();
        let p = Self::state_path(data_dir);
        let v = json!({"pool": pool, "lastSubFetchMs": last_sub_fetch_ms});
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&v)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    fn keys_path(data_dir: &str) -> PathBuf {
        PathBuf::from(data_dir).join("api-keys.json")
    }

    /// API keys live in their own 0600 file: they are credentials, not state,
    /// and must never end up in a backup of the pool.
    fn save_keys(data_dir: &str, keys: &api::KeyStore) {
        let p = Self::keys_path(data_dir);
        if let Ok(s) = serde_json::to_string_pretty(keys) {
            let tmp = p.with_extension("json.tmp");
            let _ = std::fs::write(&tmp, s);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            let _ = std::fs::rename(&tmp, &p);
        }
    }

    fn load_keys(data_dir: &str) -> api::KeyStore {
        std::fs::read_to_string(Self::keys_path(data_dir))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn load_pool(data_dir: &str) -> (Pool, i64) {
        let p = Self::state_path(data_dir);
        let s = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(_) => return (Pool::default(), 0),
        };
        let v: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
        let pool: Pool = serde_json::from_value(v.get("pool").cloned().unwrap_or(Value::Null))
            .unwrap_or_default();
        let last = v.get("lastSubFetchMs").and_then(|x| x.as_i64()).unwrap_or(0);
        (pool, last)
    }

    fn build_exit_slots(nodes: &[subs::Node], pool: &Pool) -> Vec<singbox::ExitSlot> {
        let mut out = Vec::new();
        for e in pool.exits.iter() {
            if !e.alive {
                continue; // a dead (or pinned-away) exit closes its port
            }
            if let Some(idx) = nodes.iter().position(|n| n.id == e.node_id) {
                out.push(singbox::ExitSlot {
                    slot: e.slot,
                    port: e.port,
                    node_idx: idx,
                });
            }
        }
        out
    }

    /// Ports currently un-bindable, i.e. squatted by another process. Ports our
    /// own sidecar holds are excluded — it is still running while we plan.
    fn busy_ports(
        nodes: &[subs::Node],
        pool: &Pool,
        probe_base: u16,
        own: &std::collections::HashSet<u16>,
    ) -> std::collections::HashSet<u16> {
        let mut want: Vec<u16> = nodes
            .iter()
            .enumerate()
            .map(|(i, _)| probe_base + i as u16)
            .collect();
        want.extend(pool.exits.iter().map(|e| e.port));
        singbox::free_ports(&want, own)
    }

    /// Rebuild + apply the sing-box config from the current pool.
    /// Returns what the sidecar did: "hot" or "restart".
    async fn apply_config(&self) -> Result<&'static str> {
        let cfg = self.cfg.read().await.clone();
        let nodes = self.inner.read().await.nodes.clone();
        let mut sc = self.sidecar.lock().await;
        let own = sc.ports.clone();
        let (slots, busy) = {
            let inner = self.inner.read().await;
            (
                Self::build_exit_slots(&nodes, &inner.pool),
                Self::busy_ports(&nodes, &inner.pool, cfg.probe_base, &own),
            )
        };
        let conf = singbox::build_config(
            &nodes,
            cfg.probe_base,
            &slots,
            &busy,
            &cfg.exit_listen,
            cfg.disable_udp,
            Some(&self.clash),
        );
        sc.apply(
            &cfg.sing_box,
            &self.singbox_conf(&cfg.data_dir),
            &conf,
            &self.singbox_log(&cfg.data_dir),
            Some(&self.clash),
        )
        .await?;
        Ok(sc.last_action)
    }

    async fn fetch_all(&self, cfg: &Config) -> Result<(Vec<subs::Node>, Vec<SubStat>)> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(45))
            .build()?;
        let mut nodes: Vec<subs::Node> = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        let mut stats: Vec<SubStat> = Vec::new();
        for s in cfg.subscriptions.iter() {
            if !s.enabled {
                stats.push(SubStat {
                    id: s.id.clone(),
                    nodes: 0,
                    error: "已停用".into(),
                });
                continue;
            }
            match subs::fetch(&client, &s.url).await {
                Ok(body) => {
                    let parsed = subs::parse_body(&body);
                    if parsed.is_empty() {
                        errs.push(format!("{}: 解析不出节点", s.name));
                        stats.push(SubStat {
                            id: s.id.clone(),
                            nodes: 0,
                            error: "解析不出节点".into(),
                        });
                    } else {
                        eprintln!("[exitmap] 订阅 {} -> {} 个节点", s.name, parsed.len());
                        stats.push(SubStat {
                            id: s.id.clone(),
                            nodes: parsed.len(),
                            error: String::new(),
                        });
                        nodes.extend(parsed);
                    }
                }
                Err(e) => {
                    errs.push(format!("{}: {e}", s.name));
                    stats.push(SubStat {
                        id: s.id.clone(),
                        nodes: 0,
                        error: e.to_string(),
                    });
                }
            }
        }
        // Dedupe across subscriptions: the same node in two feeds is one exit.
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        nodes.dedup_by(|a, b| a.id == b.id);
        if nodes.is_empty() {
            if errs.is_empty() {
                anyhow::bail!("没有启用的订阅");
            }
            anyhow::bail!("{}", errs.join("; "));
        }
        if errs.len() > 0 {
            eprintln!("[exitmap] 部分订阅失败: {}", errs.join("; "));
        }
        Ok((nodes, stats))
    }

    /// Country codes for IPs we have never seen. ip-api.com's free tier allows
    /// 45 requests/min per source address, and one round only ever needs the
    /// fresh IPs, so a few dozen lookups per round is comfortably inside it.
    /// Country codes for IPs we have never seen. ip-api.com's free tier allows
    /// 45 requests/min per source address, and one round only ever needs the
    /// fresh IPs, so a few dozen lookups per round is comfortably inside it.
    ///
    /// Two rules matter for country port blocks:
    ///   * a failed lookup is NOT cached — caching "" would make the IP
    ///     countryless forever and it could never enter its reserved block;
    ///   * lookups run concurrently, because this sits in front of reconcile
    ///     and 40 sequential 6s timeouts would stall a round for minutes.
    async fn fill_countries(&self, ips: &[String]) {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut todo: Vec<String> = Vec::new();
        {
            let inner = self.inner.read().await;
            for ip in ips {
                if !inner.pool.countries.contains_key(ip) {
                    todo.push(ip.clone());
                }
            }
        }
        todo.truncate(40);
        if todo.is_empty() {
            return;
        }

        let sem = Arc::new(tokio::sync::Semaphore::new(8));
        let mut set = tokio::task::JoinSet::new();
        for ip in todo {
            let client = client.clone();
            let sem = sem.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let url = format!("http://ip-api.com/json/{ip}?fields=status,countryCode");
                let v = client.get(&url).send().await.ok()?.json::<Value>().await.ok()?;
                let cc = v
                    .get("countryCode")
                    .and_then(|c| c.as_str())?
                    .trim()
                    .to_uppercase();
                if cc.is_empty() {
                    return None;
                }
                Some((ip, cc))
            });
        }
        let mut found: Vec<(String, String)> = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Ok(Some(kv)) = r {
                found.push(kv);
            }
        }
        if found.is_empty() {
            return;
        }
        let mut inner = self.inner.write().await;
        for (ip, cc) in found {
            inner.pool.countries.insert(ip, cc);
        }
    }

    async fn cycle(self: &Arc<Self>) {
        let started = Instant::now();
        self.inner.write().await.status.running = true;
        let cfg = self.cfg.read().await.clone();
        let now = now_ms();

        // ── 1. subscriptions (their own, slower cadence) ──────────────────
        // `lastSubFetchMs` is persisted but the node list is not: a process
        // restart must therefore refetch even when the stamp says "just did".
        let (last_sub, nodes_empty) = {
            let inner = self.inner.read().await;
            (inner.status.last_sub_fetch_ms, inner.nodes.is_empty())
        };
        let sub_due = nodes_empty
            || last_sub == 0
            || now - last_sub >= cfg.sub_fetch_minutes as i64 * 60_000;
        if sub_due {
            match self.fetch_all(&cfg).await {
                Ok((mut nodes, stats)) => {
                    if cfg.max_probe_nodes > 0 && nodes.len() > cfg.max_probe_nodes {
                        // Round-robin the cut so no node is permanently ignored.
                        let off = (now / 60_000) as usize % nodes.len();
                        nodes.rotate_left(off);
                        nodes.truncate(cfg.max_probe_nodes);
                    }
                    let n = nodes.len();
                    {
                        let mut inner = self.inner.write().await;
                        inner.nodes = nodes;
                        inner.sub_stats = stats;
                        inner.status.last_sub_fetch_ms = now;
                        inner.status.nodes = n;
                    }
                }
                Err(e) => {
                    self.inner.write().await.status.last_error =
                        format!("拉订阅失败: {e}");
                }
            }
        }
        let nodes = self.inner.read().await.nodes.clone();
        if nodes.is_empty() {
            self.inner.write().await.status.last_error = "还没有节点:先在面板里加一条订阅".into();
            self.inner.write().await.status.running = false;
            return;
        }

        // ── 2. make sure the probe ports exist before probing them ────────
        {
            let mut sc = self.sidecar.lock().await;
            let own = sc.ports.clone();
            let pool = self.inner.read().await.pool.clone();
            let slots = Self::build_exit_slots(&nodes, &pool);
            let busy = Self::busy_ports(&nodes, &pool, cfg.probe_base, &own);
            if !busy.is_empty() {
                eprintln!("[exitmap] {} 个端口被别的进程占着,对应节点本轮跳过", busy.len());
            }
            let conf = singbox::build_config(
                &nodes,
                cfg.probe_base,
                &slots,
                &busy,
                &cfg.exit_listen,
                cfg.disable_udp,
                Some(&self.clash),
            );
            if let Err(e) = sc
                .apply(
                    &cfg.sing_box,
                    &self.singbox_conf(&cfg.data_dir),
                    &conf,
                    &self.singbox_log(&cfg.data_dir),
                    Some(&self.clash),
                )
                .await
            {
                self.inner.write().await.status.last_error = e.to_string();
            }
        }

        // ── 3. probe every node through its own inbound ───────────────────
        let sem = Arc::new(tokio::sync::Semaphore::new(cfg.probe_concurrency.max(1)));
        let timeout = Duration::from_millis(cfg.probe_timeout_ms.max(500));
        let mut handles = Vec::with_capacity(nodes.len());
        for (i, _n) in nodes.iter().enumerate() {
            let sem = sem.clone();
            let url = cfg.probe_url.clone();
            let port = cfg.probe_base + i as u16;
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                probe::egress_ip(port, &url, timeout).await
            }));
        }
        let mut results: Vec<Option<(String, u64)>> = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.await.unwrap_or(None));
        }

        // ── 4. group by egress IP, best node per IP ───────────────────────
        // 失败不再一次就摘:探不通一次只记一笔,连续失败到阈值才真的退出轮询。
        // 阈值内的节点用它上一次探到的出口 IP 顶上 —— 机场抖一下不该付出一次换绑。
        let threshold = cfg.probe_fail_threshold.max(1);
        let mut groups: HashMap<String, Vec<(usize, u64)>> = HashMap::new();
        let mut ok = 0usize;
        {
            let mut inner = self.inner.write().await;
            for (i, r) in results.iter().enumerate() {
                let id = nodes[i].id.clone();
                match r {
                    Some((ip, ms)) => {
                        ok += 1;
                        inner.node_fails.remove(&id);
                        inner.node_last.insert(id.clone(), (ip.clone(), *ms));
                        groups.entry(ip.clone()).or_default().push((i, *ms));
                    }
                    None => {
                        let n = {
                            let c = inner.node_fails.entry(id.clone()).or_insert(0);
                            *c += 1;
                            *c
                        };
                        if n < threshold {
                            if let Some((ip, ms)) = inner.node_last.get(&id).cloned() {
                                groups.entry(ip).or_default().push((i, ms));
                            }
                        }
                    }
                }
            }
        }

        let ip_countries = {
            let inner = self.inner.read().await;
            inner.pool.countries.clone()
        };
        let mut live: Vec<LiveIp> = Vec::new();
        for (ip, mut cands) in groups.into_iter() {
            cands.sort_by_key(|c| c.1);
            let (best_idx, best_ms) = cands[0];
            // Hysteresis: an exit that already rides a node of this IP keeps it
            // unless another node is clearly better. Without this, latency
            // noise rewrites the sing-box config (and restarts it) every round.
            let keep = {
                let inner = self.inner.read().await;
                inner
                    .pool
                    .exits
                    .iter()
                    .find(|e| e.ip == ip)
                    .and_then(|e| {
                        cands
                            .iter()
                            .find(|(idx, _)| nodes[*idx].id == e.node_id)
                            .map(|(idx, ms)| (*idx, *ms))
                    })
                    .filter(|(_, ms)| *ms as f64 <= best_ms as f64 * 1.4)
            };
            let (idx, ms) = keep.unwrap_or((best_idx, best_ms));
            let n = &nodes[idx];
            live.push(LiveIp {
                ip: ip.clone(),
                country: ip_countries.get(&ip).cloned().unwrap_or_default(),
                latency_ms: ms,
                node_id: n.id.clone(),
                node_name: n.name.clone(),
                proto: n.proto.clone(),
            });
        }

        if cfg.max_latency_ms > 0 {
            live.retain(|l| l.latency_ms <= cfg.max_latency_ms);
        }

        // ── 5. countries for IPs we have not seen before ──────────────────
        let ips: Vec<String> = live.iter().map(|l| l.ip.clone()).collect();
        self.fill_countries(&ips).await;
        {
            let inner = self.inner.read().await;
            live.iter_mut().for_each(|l| {
                if let Some(cc) = inner.pool.countries.get(&l.ip) {
                    l.country = cc.clone();
                }
            });
        }

        // ── 6. reconcile: hand each IP a stable port ──────────────────────
        // Blocks are re-parsed every round: the operator can edit them from the
        // panel and the very next round has to honour the change. Validation
        // already ran on save, so a parse error here means a hand-edited config
        // and the safe answer is "no reservations".
        let blocks = pool::parse_country_slots(&cfg.country_slots, cfg.port_base, cfg.max_exits)
            .unwrap_or_default();
        let rec = {
            let mut inner = self.inner.write().await;
            inner
                .pool
                .reconcile(&live, cfg.port_base, cfg.max_exits, &blocks, now)
        };
        let changed = rec.changed;
        if rec.dropped > 0 {
            eprintln!(
                "[exitmap] {} 个出口 IP 没抢到空槽位,本轮不上表",
                rec.dropped
            );
        }

        // ── 7. apply routing changes + book the round ─────────────────────
        if changed {
            if let Err(e) = self.apply_config().await {
                self.inner.write().await.status.last_error = e.to_string();
            }
        }

        if cfg.log_retention_days > 0 {
            let cutoff = now - cfg.log_retention_days as i64 * 86_400_000;
            let mut inner = self.inner.write().await;
            let before = inner.pool.log.len();
            inner.pool.log.retain(|r| r.at_ms >= cutoff);
            let gone = before - inner.pool.log.len();
            if gone > 0 {
                eprintln!("[exitmap] 换绑日志过 {} 天,清掉 {gone} 条", cfg.log_retention_days);
            }
        }

        let mut inner = self.inner.write().await;
        let exits_open = inner.pool.exits.iter().filter(|e| e.alive).count();
        let last_sub_fetch = inner.status.last_sub_fetch_ms;
        {
            let s = &mut inner.status;
            s.last_run_ms = now;
            s.last_ok_ms = if ok > 0 { now } else { s.last_ok_ms };
            s.round_ms = started.elapsed().as_millis() as u64;
            s.nodes = nodes.len();
            s.live_ips = live.len();
            s.exits_open = exits_open;
            s.probes_ok = ok;
            s.probes_fail = nodes.len().saturating_sub(ok);
            s.next_run_ms = now + cfg.refresh_minutes as i64 * 60_000;
            if ok > 0 {
                s.last_error.clear();
            }
        }
        let pool = inner.pool.clone();
        inner.status.singbox_alive = self.sidecar.lock().await.alive();
        drop(inner);
        if let Err(e) = Self::persist_pool(&cfg.data_dir, &pool, last_sub_fetch) {
            eprintln!("[exitmap] 持久化状态失败: {e}");
        }
        eprintln!(
            "[exitmap] 一轮完成: {} 节点 / {} 探活 / {} 出口 IP / {} 端口 / {}ms",
            nodes.len(),
            ok,
            live.len(),
            pool.exits.iter().filter(|e| e.alive).count(),
            started.elapsed().as_millis()
        );
        self.inner.write().await.status.running = false;
    }
}

// ── HTTP API ─────────────────────────────────────────────────────────────────

fn mask_url(u: &str) -> String {
    match url::Url::parse(u) {
        Ok(mut p) => {
            if p.query().is_some() {
                let keys: Vec<String> = p
                    .query_pairs()
                    .map(|(k, _)| format!("{k}=***"))
                    .collect();
                p.set_query(Some(&keys.join("&")));
            }
            p.to_string()
        }
        Err(_) => "***".into(),
    }
}


// ───────────────────────── public v1 API ─────────────────────────
//
// Everything under /api/v1 needs a Bearer key. The panel's own /api/* routes
// stay open: they are loopback/tailnet-trusted and the browser cannot hold a
// key without shipping it in the HTML.

fn api_err(status: StatusCode, code: &str, msg: &str) -> Response {
    (status, Json(json!({"ok": false, "error": code, "message": msg}))).into_response()
}

/// Best address to advertise in `proxies.*`. `0.0.0.0` is not connectable, so
/// it degrades to loopback.
fn advertise_host(cfg: &Config) -> String {
    match cfg.exit_listen.first().map(|s| s.as_str()) {
        Some("0.0.0.0") | Some("::") | None => "127.0.0.1".into(),
        Some(a) => a.to_string(),
    }
}

fn exit_dto(e: &ExitView, host: &str) -> api::ExitDto {
    api::ExitDto {
        port: e.port,
        ip: e.ip.clone(),
        country: e.country.clone(),
        latency_ms: e.latency_ms,
        alive: e.alive,
        pinned: e.pinned,
        rebinds: e.rebinds,
        up_since_ms: e.since_ms,
        last_verified_ms: e.verified_ms,
        node: api::NodeDto {
            name: e.node_name.clone(),
            proto: e.proto.clone(),
        },
        proxies: api::ProxiesDto {
            socks5: format!("socks5://{host}:{}", e.port),
            http: format!("http://{host}:{}", e.port),
        },
    }
}

/// Bearer + key check + rate limit. Returns the key id on success.
async fn api_guard(app: &Arc<App>, headers: &HeaderMap) -> Result<String, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
                .map(|t| t.trim().to_string())
        });
    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "missing_token",
                "缺少 Authorization: Bearer <key>",
            ))
        }
    };
    let limit = app.cfg.read().await.api_rate_limit;
    let now = now_ms();
    let mut inner = app.inner.write().await;
    let id = match inner.keys.verify(&token, now) {
        Some(id) => id,
        None => {
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "bad_token",
                "密钥无效或已撤销",
            ))
        }
    };
    if let Err(retry) = inner.limiter.check(&id, limit, now) {
        drop(inner);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry.to_string())],
            Json(json!({"ok": false, "error": "rate_limited",
                        "message": "超出额度", "retryAfterSeconds": retry})),
        )
            .into_response());
    }
    drop(inner);
    app.inner.write().await.limiter.gc(now);
    Ok(id)
}

async fn api_v1_exits(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    if let Err(r) = api_guard(&app, &headers).await {
        return r;
    }
    let pairs: Vec<(String, String)> = q
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                percent_decode(k),
                percent_decode(&v.replace('+', " ")),
            )
        })
        .collect();
    let query = api::ExitQuery::parse(&pairs);
    let cfg = app.cfg.read().await.clone();
    let host = advertise_host(&cfg);
    let inner = app.inner.read().await;
    let mut rows: Vec<api::ExitDto> = inner
        .pool
        .exits
        .iter()
        .map(|e| exit_dto(e, &host))
        .filter(|e| query.keeps(e))
        .collect();
    query.sort(&mut rows);
    if let Some(n) = query.limit {
        rows.truncate(n);
    }
    Json(api::ExitsResponse {
        api_version: api::API_VERSION.into(),
        generated_at: now_ms(),
        count: rows.len(),
        exits: rows,
    })
    .into_response()
}

async fn api_v1_exit(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(port): Path<u16>,
) -> Response {
    if let Err(r) = api_guard(&app, &headers).await {
        return r;
    }
    let cfg = app.cfg.read().await.clone();
    let host = advertise_host(&cfg);
    let inner = app.inner.read().await;
    match inner.pool.exits.iter().find(|e| e.port == port) {
        Some(e) => Json(exit_dto(e, &host)).into_response(),
        None => api_err(
            StatusCode::NOT_FOUND,
            "no_such_port",
            &format!("{port} 不是当前出口端口"),
        ),
    }
}

async fn api_v1_meta(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if let Err(r) = api_guard(&app, &headers).await {
        return r;
    }
    let cfg = app.cfg.read().await.clone();
    let inner = app.inner.read().await;
    let alive = app.sidecar.lock().await.alive();
    Json(json!({
        "apiVersion": api::API_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "nowMs": now_ms(),
        "uptimeMs": now_ms() - app.started_ms,
        "exits": {
            "open": inner.pool.exits.iter().filter(|e| e.alive).count(),
            "total": inner.pool.exits.len(),
            "pinned": inner.pool.exits.iter().filter(|e| e.pinned).count(),
        },
        "lastProbeMs": inner.status.last_run_ms,
        "lastProbeOkMs": inner.status.last_ok_ms,
        "nextProbeMs": inner.status.next_run_ms,
        "lastProbeRoundMs": inner.status.round_ms,
        "lastSubFetchMs": inner.status.last_sub_fetch_ms,
        "probeIntervalMinutes": cfg.refresh_minutes,
        "subFetchIntervalMinutes": cfg.sub_fetch_minutes,
        "rateLimitPerMin": cfg.api_rate_limit,
        "singBoxAlive": alive,
    }))
    .into_response()
}

// The only unauthenticated endpoint: it leaks nothing about this instance.
async fn api_v1_openapi() -> Json<Value> {
    Json(api::openapi())
}

// ───────────────────────── key management (panel) ─────────────────────────

async fn api_list_keys(State(app): State<Arc<App>>) -> Json<Value> {
    let data_dir = app.cfg.read().await.data_dir.clone();
    let inner = app.inner.read().await;
    Json(json!({
        "keys": inner.keys.list(),
        "rateLimitPerMin": app.cfg.try_read().map(|c| c.api_rate_limit).unwrap_or(0),
        "dataDir": data_dir,
    }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct NewKey {
    name: String,
}

async fn api_create_key(State(app): State<Arc<App>>, Json(body): Json<NewKey>) -> Json<Value> {
    let data_dir = app.cfg.read().await.data_dir.clone();
    let (plain, k) = {
        let mut inner = app.inner.write().await;
        let r = inner.keys.create(&body.name, now_ms());
        App::save_keys(&data_dir, &inner.keys);
        r
    };
    Json(json!({
        "ok": true,
        "key": plain,
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "note": "这串明文只显示这一次,关掉就再也拿不到了",
    }))
}

async fn api_revoke_key(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let data_dir = app.cfg.read().await.data_dir.clone();
    let ok = {
        let mut inner = app.inner.write().await;
        let ok = inner.keys.revoke(&id);
        if ok {
            App::save_keys(&data_dir, &inner.keys);
        }
        ok
    };
    if ok {
        Json(json!({"ok": true})).into_response()
    } else {
        api_err(StatusCode::NOT_FOUND, "no_such_key", "没有这个密钥")
    }
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

async fn api_state(State(app): State<Arc<App>>) -> Json<Value> {
    let cfg = app.cfg.read().await.clone();
    let inner = app.inner.read().await;
    let alive = app.sidecar.lock().await.alive();
    let mut status = inner.status.clone();
    status.singbox_alive = alive;
    let subs: Vec<Value> = cfg
        .subscriptions
        .iter()
        .map(|s| {
            let st = inner.sub_stats.iter().find(|x| x.id == s.id);
            json!({
                "id": s.id,
                "name": s.name,
                "urlMasked": mask_url(&s.url),
                "enabled": s.enabled,
                "nodes": st.map(|x| x.nodes).unwrap_or(0),
                "error": st.map(|x| x.error.clone()).unwrap_or_default(),
            })
        })
        .collect();
    let exits: Vec<Value> = {
        // `slotCountry` is derived, not stored: the pin lives in `countrySlots`,
        // so there is exactly one source of truth and no state migration.
        let blocks = pool::parse_country_slots(&cfg.country_slots, cfg.port_base, cfg.max_exits)
            .unwrap_or_default();
        let mut rows: Vec<Value> = inner
            .pool
            .exits
            .iter()
            .map(|e| {
                let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
                if let Some(o) = v.as_object_mut() {
                    o.insert(
                        "slotCountry".into(),
                        json!(pool::block_cc(&blocks, e.slot).unwrap_or("")),
                    );
                    o.insert("placeholder".into(), json!(false));
                }
                v
            })
            .collect();
        // Reserved ports with nothing on them still belong in the table: a pin
        // that visibly vanished for two rounds reads as a bug, and "31001 是
        // US" is a contract about the port, not about whatever IP happens to
        // be alive right now.
        for (port, slot, cc, rebinds) in
            inner.pool.reserved_placeholders(&blocks, cfg.port_base, cfg.max_exits)
        {
            rows.push(json!({
                "slot": slot,
                "port": port,
                "ip": "",
                "country": "",
                "latencyMs": 0,
                "nodeId": "",
                "nodeName": format!("等待 {cc} 出口"),
                "proto": "",
                "sinceMs": 0,
                "verifiedMs": 0,
                "rebinds": rebinds,
                "pinned": false,
                "alive": false,
                "slotCountry": cc,
                "placeholder": true,
            }));
        }
        rows.sort_by_key(|v| v.get("port").and_then(|p| p.as_u64()).unwrap_or(0));
        rows
    };
    let log: Vec<&Rebind> = inner.pool.log.iter().take(60).collect();
    Json(json!({
        "status": status,
        "exits": exits,
        "log": log,
        "subscriptions": subs,
        "portBase": cfg.port_base,
        "maxExits": cfg.max_exits,
        "refreshMinutes": cfg.refresh_minutes,
        "subFetchMinutes": cfg.sub_fetch_minutes,
    }))
}

#[derive(Deserialize)]
struct AddSub {
    name: String,
    url: String,
}

async fn api_add_sub(State(app): State<Arc<App>>, Json(body): Json<AddSub>) -> Response {
    let url = body.url.trim().to_string();
    let name = body.name.trim().to_string();
    if url.is_empty() || !url.contains("://") {
        return (StatusCode::BAD_REQUEST, "订阅 URL 不合法").into_response();
    }
    let name = if name.is_empty() {
        url.split("://").nth(1).unwrap_or("订阅").to_string()
    } else {
        name
    };
    {
        let mut cfg = app.cfg.write().await;
        let id = format!("sub-{}", now_ms());
        cfg.subscriptions.push(Sub {
            id,
            name,
            url,
            enabled: true,
        });
        if let Err(e) = save_config(&cfg) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("写配置失败: {e}")).into_response();
        }
    }
    app.wake.notify_one();
    (StatusCode::OK, "ok").into_response()
}

async fn api_del_sub(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let mut cfg = app.cfg.write().await;
    let before = cfg.subscriptions.len();
    cfg.subscriptions.retain(|s| s.id != id);
    if cfg.subscriptions.len() == before {
        return (StatusCode::NOT_FOUND, "没有这条订阅").into_response();
    }
    if let Err(e) = save_config(&cfg) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("写配置失败: {e}")).into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

#[derive(Deserialize)]
struct PinBody {
    pinned: bool,
}

async fn api_pin(State(app): State<Arc<App>>, Path(slot): Path<usize>, Json(body): Json<PinBody>) -> Response {
    let ok = {
        let mut inner = app.inner.write().await;
        inner.pool.set_pinned(slot, body.pinned)
    };
    if !ok {
        return (StatusCode::NOT_FOUND, "没有这个槽位").into_response();
    }
    if let Err(e) = app.apply_config().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    (StatusCode::OK, "ok").into_response()
}

/// Manual latency check for one exit. Deliberately does *not* touch the pool: a
/// click must not nudge `latency_ms`, `lat_ema` or trigger a re-sort — ranking
/// moves on its own schedule, not on how often you press a button.
async fn api_ping(State(app): State<Arc<App>>, Path(port): Path<u16>) -> Response {
    let (probe_url, timeout_ms, cur_ip) = {
        let inner = app.inner.read().await;
        let cfg = app.cfg.read().await;
        match inner.pool.exits.iter().find(|e| e.port == port) {
            None => return (StatusCode::NOT_FOUND, "这个端口上没有出口").into_response(),
            Some(e) if !e.alive => {
                return (StatusCode::CONFLICT, "这个端口现在是关着的").into_response()
            }
            Some(e) => (cfg.probe_url.clone(), cfg.probe_timeout_ms, e.ip.clone()),
        }
    };
    let timeout = Duration::from_millis(timeout_ms.clamp(1000, 20_000));
    let started = Instant::now();
    match probe::egress_ip(port, &probe_url, timeout).await {
        Some((ip, _)) => Json(json!({
            "ok": true,
            // timed from here, not from inside egress_ip: the question the
            // button answers is "how long until I get an answer".
            "ms": started.elapsed().as_millis() as u64,
            "ip": ip,
            "changed": ip != cur_ip,
        }))
        .into_response(),
        None => (
            StatusCode::GATEWAY_TIMEOUT,
            "超时：这个出口没在时限内回应",
        )
            .into_response(),
    }
}

async fn api_refresh(State(app): State<Arc<App>>) -> Response {
    // Refuse while a round is in flight. The wake permit is sticky, so a click
    // during a round costs a whole extra minute of probing for nothing — that
    // is the double-round people hit by clicking twice at an empty table.
    if app.inner.read().await.status.running {
        return (
            StatusCode::CONFLICT,
            "一轮正在跑（约 1 分钟），跑完再点",
        )
            .into_response();
    }
    // Clearing the stamp is what forces the refetch: `cycle` only calls
    // `fetch_all` when this is zero or 30 minutes old. The old node list is
    // kept until the new fetch actually succeeds, so a dead airport does not
    // empty the table.
    app.inner.write().await.status.last_sub_fetch_ms = 0;
    app.wake.notify_one();
    Json(json!({"ok": true, "note": "已排队：重拉订阅 + 重探一轮，约 1 分钟"})).into_response()
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct CountryPin {
    country: String,
}

/// Per-port country pin. Writes the same `countrySlots` string the range editor
/// writes, so the button and the textarea can never disagree.
async fn api_pin_country(
    State(app): State<Arc<App>>,
    Path(port): Path<u16>,
    Json(body): Json<CountryPin>,
) -> Response {
    let cfg = app.cfg.read().await.clone();
    let cc = body.country.trim().to_ascii_uppercase();
    let slots = match pool::set_slot_country(&cfg.country_slots, port, &cc, cfg.port_base, cfg.max_exits)
    {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let blocks = pool::parse_country_slots(&slots, cfg.port_base, cfg.max_exits).unwrap_or_default();
    let slot = (port - cfg.port_base) as usize;

    // Config first: the worker re-reads it, and save_config must not fail after
    // we have already moved rows around in memory.
    {
        let mut c = app.cfg.write().await;
        eprintln!(
            "[exitmap] 端口 {port} 国家固定: {} -> {}",
            if c.country_slots.trim().is_empty() { "（无）" } else { c.country_slots.trim() },
            if slots.trim().is_empty() { "（无）" } else { slots.trim() },
        );
        c.country_slots = slots.clone();
        if let Err(e) = save_config(&c) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("写配置失败: {e}")).into_response();
        }
    }

    let (closed, filled) = {
        let mut inner = app.inner.write().await;
        let closed = inner.pool.drop_ineligible(&blocks, now_ms());
        let filled = inner.pool.fill_slot(slot, &cc, &blocks, cfg.port_base, now_ms());
        (closed, filled)
    };
    let note = if !cc.is_empty() {
        match (filled, closed) {
            (Some(ip), _) => format!("{port} 现在固定 {cc}，已把 {ip} 换进来"),
            (None, 0) => format!("{port} 现在固定 {cc}"),
            (None, _) => format!("{port} 现在固定 {cc}，眼下没有空闲的 {cc} 出口，端口暂时关着"),
        }
    } else {
        format!("{port} 已取消国家固定")
    };

    // Something left its port and something else may need one: let the worker
    // re-place the orphan now instead of in five minutes.
    app.wake.notify_one();
    if let Err(e) = app.apply_config().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("已保存，但 sing-box 重新加载失败: {e}"),
        )
            .into_response();
    }
    Json(json!({"ok": true, "countrySlots": slots, "note": note})).into_response()
}

// ── 配置面 ──────────────────────────────────────────────────────────────────

/// Anything the panel may change. Deliberately a separate shape from Config:
/// `subscriptions` holds the URL-as-credential and has its own endpoints, so it
/// never leaks through this one.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct ConfigPatch {
    port_base: Option<u16>,
    exit_listen: Option<Vec<String>>,
    max_exits: Option<usize>,
    country_slots: Option<String>,
    disable_udp: Option<bool>,
    refresh_minutes: Option<u64>,
    sub_fetch_minutes: Option<u64>,
    probe_url: Option<String>,
    probe_timeout_ms: Option<u64>,
    probe_concurrency: Option<usize>,
    max_probe_nodes: Option<usize>,
    probe_fail_threshold: Option<usize>,
    max_latency_ms: Option<u64>,
    log_retention_days: Option<u64>,
    api_rate_limit: Option<u32>,
}

fn public_config(c: &Config) -> Value {
    json!({
        "portBase": c.port_base,
        "probeBase": c.probe_base,
        "exitListen": c.exit_listen,
        "maxExits": c.max_exits,
        "countrySlots": c.country_slots,
        "disableUdp": c.disable_udp,
        "refreshMinutes": c.refresh_minutes,
        "subFetchMinutes": c.sub_fetch_minutes,
        "probeUrl": c.probe_url,
        "probeTimeoutMs": c.probe_timeout_ms,
        "probeConcurrency": c.probe_concurrency,
        "maxProbeNodes": c.max_probe_nodes,
        "probeFailThreshold": c.probe_fail_threshold,
        "maxLatencyMs": c.max_latency_ms,
        "logRetentionDays": c.log_retention_days,
        "apiRateLimit": c.api_rate_limit,
        "singBox": c.sing_box,
        "dataDir": c.data_dir,
    })
}

/// Range checks. Everything here exists because a bad value takes the whole
/// table down rather than one row: overlapping port ranges, a probe URL our
/// plaintext-only probe cannot fetch, a zero-length pool.
fn validate_config(c: &Config) -> Result<(), String> {
    if c.port_base < 1024 {
        return Err("出口端口起始号要 ≥ 1024".into());
    }
    if c.max_exits == 0 || c.max_exits > 512 {
        return Err("出口槽位要在 1–512 之间".into());
    }
    let exit_end = c.port_base as u32 + c.max_exits as u32;
    if exit_end > 65536 {
        return Err(format!(
            "端口段越界: {} + {} 个槽位 超过 65535",
            c.port_base, c.max_exits
        ));
    }
    // Country reservations must live inside the exit range and not overlap: a
    // bad block would strand slots or, worse, point at someone else's ports.
    pool::parse_country_slots(&c.country_slots, c.port_base, c.max_exits)
        .map_err(|e| format!("国家端口段: {e}"))?;
    let probe_end = c.probe_base as u32 + c.max_probe_nodes.max(1) as u32;
    let exit_start = c.port_base as u32;
    if exit_start < probe_end && (c.probe_base as u32) < exit_end {
        return Err(format!(
            "出口端口段 {}-{} 与探测端口段 {}-{} 重叠",
            c.port_base,
            exit_end - 1,
            c.probe_base,
            probe_end - 1
        ));
    }
    if c.api_rate_limit > 100_000 {
        return Err("API 限流额度太大(>100000/分钟),填 0 表示不限".into());
    }
    if c.refresh_minutes < 1 || c.refresh_minutes > 1440 {
        return Err("探活周期要在 1–1440 分钟之间".into());
    }
    if c.sub_fetch_minutes < 1 || c.sub_fetch_minutes > 1440 {
        return Err("拉订阅周期要在 1–1440 分钟之间".into());
    }
    if !c.probe_url.starts_with("http://") {
        return Err("探针地址必须是 http:// —— 探针是从节点里裸跑 socks5 + 明文 HTTP,没有 TLS".into());
    }
    if url::Url::parse(&c.probe_url).map(|u| u.host_str().is_none()).unwrap_or(true) {
        return Err("探针地址不是一个合法的 URL".into());
    }
    if c.probe_timeout_ms < 500 || c.probe_timeout_ms > 30000 {
        return Err("探测超时要在 500–30000 毫秒之间".into());
    }
    if c.probe_concurrency < 1 || c.probe_concurrency > 128 {
        return Err("探测并发要在 1–128 之间".into());
    }
    if c.max_probe_nodes > 1000 {
        return Err("每轮探测节点上限最多 1000".into());
    }
    if c.probe_fail_threshold < 1 || c.probe_fail_threshold > 10 {
        return Err("连续失败阈值要在 1–10 之间".into());
    }
    if c.max_latency_ms > 20000 {
        return Err("延迟上限最多 20000 毫秒".into());
    }
    if c.log_retention_days > 3650 {
        return Err("日志保留最多 3650 天".into());
    }
    for a in &c.exit_listen {
        if a.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("监听地址 {a} 不是合法 IP"));
        }
    }
    Ok(())
}

async fn api_config(State(app): State<Arc<App>>) -> Json<Value> {
    Json(public_config(&app.cfg.read().await.clone()))
}

async fn api_patch_config(
    State(app): State<Arc<App>>,
    Json(p): Json<ConfigPatch>,
) -> Response {
    let old = app.cfg.read().await.clone();
    let mut c = old.clone();
    if let Some(v) = p.port_base {
        c.port_base = v;
    }
    if let Some(v) = p.exit_listen {
        c.exit_listen = singbox::normalize_listen(&v);
    }
    if let Some(v) = p.max_exits {
        c.max_exits = v;
    }
    if let Some(v) = p.country_slots {
        c.country_slots = v.trim().to_string();
    }
    if let Some(v) = p.disable_udp {
        c.disable_udp = v;
    }
    if let Some(v) = p.refresh_minutes {
        c.refresh_minutes = v;
    }
    if let Some(v) = p.sub_fetch_minutes {
        c.sub_fetch_minutes = v;
    }
    if let Some(v) = p.probe_url {
        c.probe_url = v.trim().to_string();
    }
    if let Some(v) = p.probe_timeout_ms {
        c.probe_timeout_ms = v;
    }
    if let Some(v) = p.probe_concurrency {
        c.probe_concurrency = v;
    }
    if let Some(v) = p.max_probe_nodes {
        c.max_probe_nodes = v;
    }
    if let Some(v) = p.probe_fail_threshold {
        c.probe_fail_threshold = v;
    }
    if let Some(v) = p.max_latency_ms {
        c.max_latency_ms = v;
    }
    if let Some(v) = p.log_retention_days {
        c.log_retention_days = v;
    }
    if let Some(v) = p.api_rate_limit {
        c.api_rate_limit = v;
    }

    if let Err(e) = validate_config(&c) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // Absolute port blocks and a moving portBase cannot both win: shifting the
    // base would leave every block pointing at the wrong ports. Clearing the
    // blocks first is the only sane order.
    if c.port_base != old.port_base && !c.country_slots.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "改端口段起点前先清空国家端口段,否则段会指到错误的位置",
        )
            .into_response();
    }

    let ports_moved = c.port_base != old.port_base;
    let slots_changed = c.country_slots != old.country_slots;
    let needs_singbox = ports_moved
        || slots_changed
        || c.exit_listen != old.exit_listen
        || c.disable_udp != old.disable_udp
        || c.max_exits != old.max_exits;

    *app.cfg.write().await = c.clone();
    if ports_moved {
        app.inner.write().await.pool.rebase(c.port_base);
    }
    if slots_changed {
        eprintln!(
            "[exitmap] 国家端口段: {} -> {}",
            if old.country_slots.trim().is_empty() { "（无）" } else { old.country_slots.trim() },
            if c.country_slots.trim().is_empty() { "（无）" } else { c.country_slots.trim() },
        );
        // Free every exit that the new blocks make illegal, then wake the
        // worker so it re-places those IPs now instead of in five minutes.
        let blocks = pool::parse_country_slots(&c.country_slots, c.port_base, c.max_exits)
            .unwrap_or_default();
        let closed = app.inner.write().await.pool.drop_ineligible(&blocks, now_ms());
        if closed > 0 {
            eprintln!("[exitmap] 国家端口段变了,{closed} 个端口先关掉,马上重新分配");
        }
        app.wake.notify_one();
    }
    if let Err(e) = save_config(&c) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("写配置失败: {e}")).into_response();
    }
    let mut restarted = false;
    let mut hot = false;
    if needs_singbox {
        match app.apply_config().await {
            Ok(action) => {
                restarted = true;
                hot = action == "hot";
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("配置已保存,但 sing-box 重新加载失败: {e}"),
                )
                    .into_response();
            }
        }
    }
    let note = if ports_moved {
        "端口段变了:所有客户端需要换成新端口"
    } else if hot {
        "已热切换:现有连接不断,新连接走新出口"
    } else if restarted {
        "已重载 sing-box(现有连接会断一下)"
    } else {
        "下一轮生效"
    };
    Json(json!({"ok": true, "singBoxReloaded": restarted, "note": note})).into_response()
}

/// Port footprint: who is squatting what, and is each listen address actually
/// local. Read-only, safe to hit any time.
async fn api_diag_ports(State(app): State<Arc<App>>) -> Json<Value> {
    let cfg = app.cfg.read().await.clone();
    let (node_count, exit_ports) = {
        let inner = app.inner.read().await;
        (
            inner.nodes.len(),
            inner
                .pool
                .exits
                .iter()
                .filter(|e| e.alive)
                .map(|e| e.port)
                .collect::<Vec<_>>(),
        )
    };
    let probe_ports: Vec<u16> = (0..node_count)
        .map(|i| cfg.probe_base.wrapping_add(i as u16))
        .collect();
    let mut all: Vec<u16> = probe_ports.clone();
    all.extend(exit_ports.iter().copied());
    let own = app.sidecar.lock().await.ports.clone();
    let busy = singbox::free_ports(&all, &own);
    let listen: Vec<Value> = cfg
        .exit_listen
        .iter()
        .map(|addr| match addr.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let ok = std::net::TcpListener::bind((ip, 0)).is_ok();
                json!({"addr": addr, "ok": ok,
                       "note": if ok { "" } else { "该地址不是本机地址(绑不上)" }})
            }
            Err(_) => json!({"addr": addr, "ok": false, "note": "不是合法 IP"}),
        })
        .collect();
    Json(json!({
        "busyProbe": probe_ports.iter().filter(|p| busy.contains(p)).collect::<Vec<_>>(),
        "busyExit": exit_ports.iter().filter(|p| busy.contains(p)).collect::<Vec<_>>(),
        "checkedProbe": probe_ports.len(),
        "checkedExit": exit_ports.len(),
        "listen": listen,
    }))
}

async fn index() -> Html<&'static str> {
    Html(PANEL)
}

/// The panel is one file with three routes (/exits, /subs, /log) so a page can
/// be bookmarked and the back button works. Every non-API path serves that same
/// file; the router on the client picks the page.
async fn spa_fallback(uri: axum::http::Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return (StatusCode::NOT_FOUND, "没有这个 API").into_response();
    }
    index().await.into_response()
}

// ── boot ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = load_config();
    if cfg.subscriptions.is_empty() {
        eprintln!("[exitmap] 配置里没有订阅:打开面板加一条,或用 EXITMAP_URL 环境变量");
        if let Ok(u) = std::env::var("EXITMAP_URL") {
            if u.contains("://") {
                cfg.subscriptions.push(Sub {
                    id: format!("sub-{}", now_ms()),
                    name: "订阅".into(),
                    url: u,
                    enabled: true,
                });
            }
        }
    }
    if let Err(e) = save_config(&cfg) {
        eprintln!("[exitmap] 保存配置失败({e}),继续用内存里的");
    }
    std::fs::create_dir_all(&cfg.data_dir).ok();
    let (pool, last_sub_fetch) = App::load_pool(&cfg.data_dir);
    let clash = singbox::ClashApi {
        controller: format!("127.0.0.1:{}", cfg.clash_api_port),
        secret: random_secret(),
    };

    let listen = cfg.listen.clone();
    let refresh = cfg.refresh_minutes.max(1);
    let keys = App::load_keys(&cfg.data_dir);
    let app = Arc::new(App {
        started_ms: now_ms(),
        cfg: RwLock::new(cfg),
        inner: RwLock::new(Inner {
            pool,
            nodes: Vec::new(),
            status: Status {
                last_sub_fetch_ms: last_sub_fetch,
                ..Default::default()
            },
            node_fails: HashMap::new(),
            node_last: HashMap::new(),
            sub_stats: Vec::new(),
            keys,
            limiter: api::Limiter::default(),
        }),
        sidecar: Mutex::new(singbox::Sidecar::default()),
        clash,
        wake: Notify::new(),
    });

    {
        let data_dir = app.cfg.read().await.data_dir.clone();
        let conf = app.singbox_conf(&data_dir);
        singbox::Sidecar::kill_strays(&conf);
    }

    // Worker: first cycle immediately, then on the configured cadence or when
    // the panel pokes it.
    {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                app.cycle().await;
                let wake = app.wake.notified();
                let tick = tokio::time::sleep(Duration::from_secs(refresh * 60));
                tokio::pin!(wake);
                tokio::pin!(tick);
                tokio::select! {
                    _ = wake => { eprintln!("[exitmap] 面板触发刷新"); }
                    _ = tick => {}
                }
            }
        });
    }

    let router = Router::new()
        .route("/", get(index))
        .route("/exits", get(index))
        .route("/log", get(index))
        .route("/config", get(index))
        .route("/api", get(index))
        .fallback(spa_fallback)
        .route("/api/state", get(api_state))
        .route("/api/subscriptions", post(api_add_sub))
        .route("/api/subscriptions/{id}", delete(api_del_sub))
        .route("/api/exits/{slot}/pin", post(api_pin))
        .route("/api/exits/{port}/country", post(api_pin_country))
        .route("/api/exits/{port}/ping", post(api_ping))
        .route("/api/refresh", post(api_refresh))
        .route("/api/config", get(api_config).patch(api_patch_config))
        .route("/api/diag/ports", post(api_diag_ports))
        .route("/api/keys", get(api_list_keys).post(api_create_key))
        .route("/api/keys/{id}", delete(api_revoke_key))
        .route("/api/v1/exits", get(api_v1_exits))
        .route("/api/v1/exits/{port}", get(api_v1_exit))
        .route("/api/v1/meta", get(api_v1_meta))
        .route("/api/v1/openapi.json", get(api_v1_openapi))
        .with_state(app);

    // `listen` may be a comma-separated list: loopback for local tools, the
    // Tailscale address for the browser. Binding only loopback is why the
    // remote panel looked dead — there was simply nothing on that address.
    let addrs: Vec<String> = listen
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut bound: Vec<(String, tokio::net::TcpListener)> = Vec::new();
    for a in &addrs {
        match tokio::net::TcpListener::bind(a).await {
            Ok(l) => bound.push((a.clone(), l)),
            Err(e) => eprintln!("[exitmap] {a} 绑不上: {e}"),
        }
    }
    if bound.is_empty() {
        return Err(anyhow::anyhow!("一个监听地址都绑不上: {listen}"));
    }
    for (a, l) in bound {
        let r = router.clone();
        eprintln!("[exitmap] 面板在 http://{a}/");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(l, r).await {
                eprintln!("[exitmap] {a} 服务结束: {e}");
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}
