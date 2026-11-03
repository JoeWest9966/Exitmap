// sing-box sidecar: one socks inbound per candidate node (probe ports) and one
// mixed inbound per exposed exit (the ports the user actually fills in).
//
// The inbound->outbound pinning is the whole trick: dialing 127.0.0.1:31005
// can only ever leave through the node routed to it, so a port is an address
// for an egress IP rather than a suggestion.

use crate::subs::Node;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};

pub struct Sidecar {
    child: Option<Child>,
    pub last_err: String,
    pub config_hash: u64,
    /// Same config minus which node each exit rides. Unchanged means the
    /// process can keep running and the ports can be re-pointed over the API.
    structural_hash: u64,
    /// What each selector was last told to ride, so a round that changes
    /// nothing costs zero HTTP calls.
    mapping: std::collections::HashMap<String, String>,
    /// Ports the currently running config binds, so the squat check can tell
    /// "someone else has it" from "we have it".
    pub ports: std::collections::HashSet<u16>,
    /// What the last apply() actually did: "hot" (ports re-pointed over the
    /// control API, nothing restarted) or "restart" (the process was replaced,
    /// so every connection on every port died).
    pub last_action: &'static str,
}

impl Default for Sidecar {
    fn default() -> Self {
        Self {
            child: None,
            last_err: String::new(),
            config_hash: 0,
            structural_hash: 0,
            mapping: std::collections::HashMap::new(),
            ports: std::collections::HashSet::new(),
            last_action: "",
        }
    }
}

/// The sidecar's control surface. sing-box has no config reload, but a
/// selector's choice *is* hot-swappable over the Clash API — that is the only
/// way to change which node a port rides without killing every connection on
/// every port.
pub struct ClashApi {
    /// host:port of `experimental.clash_api.external_controller`, loopback only.
    pub controller: String,
    pub secret: String,
}

/// One exposed exit: which local port, and which node it currently rides.
pub struct ExitSlot {
    pub slot: usize,
    pub port: u16,
    pub node_idx: usize,
}

/// Ports we can actually bind right now. A fixed port can be squatted by an
/// unrelated process (found in the wild: crowdsec loop-connecting to its own
/// :8083 and burning 32036 as a source port), and one squatted number must not
/// take the whole rotation down with it — the node behind it is simply skipped
/// for this round.
pub fn free_ports(
    ports: &[u16],
    ignore: &std::collections::HashSet<u16>,
) -> std::collections::HashSet<u16> {
    let mut busy = std::collections::HashSet::new();
    for p in ports {
        // Ports our own sidecar is holding are not "squatted": the check runs
        // while the old instance is still up, and counting those would declare
        // the whole table busy and emit an empty config (it did — every port
        // looked taken by ourselves).
        if ignore.contains(p) {
            continue;
        }
        if std::net::TcpListener::bind(("127.0.0.1", *p)).is_err() {
            busy.insert(*p);
        }
    }
    busy
}

/// The ports a generated config actually binds.
pub fn config_ports(conf: &Value) -> std::collections::HashSet<u16> {
    conf.get("inbounds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|i| i.get("listen_port").and_then(|p| p.as_u64()))
                .map(|p| p as u16)
                .collect()
        })
        .unwrap_or_default()
}

/// Normalize the exit listener list: empties dropped, duplicates removed, and
/// an all-interfaces address wins outright (binding 0.0.0.0 plus 127.0.0.1 for
/// the same port is an EADDRINUSE, not a wider listener).
pub fn normalize_listen(listen: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for a in listen {
        let a = a.trim().to_string();
        if a.is_empty() {
            continue;
        }
        if a == "0.0.0.0" || a == "::" {
            return vec![a];
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        out.push("127.0.0.1".into());
    }
    out
}

pub fn build_config(
    nodes: &[Node],
    probe_base: u16,
    exits: &[ExitSlot],
    busy: &std::collections::HashSet<u16>,
    exit_listen: &[String],
    disable_udp: bool,
    api: Option<&ClashApi>,
) -> Value {
    let mut inbounds: Vec<Value> = Vec::new();
    let mut outbounds: Vec<Value> = Vec::new();
    let mut rules: Vec<Value> = Vec::new();

    for (i, n) in nodes.iter().enumerate() {
        let mut ob = n.outbound.clone();
        ob["tag"] = json!(format!("o{i}"));
        outbounds.push(ob);
        if busy.contains(&(probe_base + i as u16)) {
            continue; // port squatted: this node sits this round out
        }
        inbounds.push(json!({
            "type": "socks",
            "tag": format!("p{i}"),
            "listen": "127.0.0.1",
            "listen_port": probe_base as u32 + i as u32,
        }));
        rules.push(json!({"inbound": [format!("p{i}")], "outbound": format!("o{i}")}));
    }

    // Exposed exits come last so their tags read separately in the file.
    // One inbound per (exit, listen address): the same port on two addresses is
    // legal and is exactly how "also reachable on the LAN/tailnet" is built.
    let listen = normalize_listen(exit_listen);
    let mut exit_tags: Vec<String> = Vec::new();
    let mut routed: Vec<&ExitSlot> = Vec::new();
    for e in exits {
        if e.node_idx >= nodes.len() || busy.contains(&e.port) {
            continue;
        }
        // Ports route to a *selector*, not straight to a node. The selector
        // starts out riding the node the pool picked, and can be re-pointed
        // later without restarting anything.
        rules.push(json!({
            "inbound": exit_tags_placeholder(e.slot, listen.len()),
            "outbound": format!("s{}", e.slot),
        }));
        routed.push(e);
        for (ai, addr) in listen.iter().enumerate() {
            let tag = if ai == 0 {
                format!("x{}", e.slot)
            } else {
                format!("x{}_{ai}", e.slot)
            };
            inbounds.push(json!({
                "type": "mixed", // socks5 + http on one port: every client speaks one of them
                "tag": tag,
                "listen": addr,
                "listen_port": e.port as u32,
            }));
            exit_tags.push(tag);
        }
    }

    // UDP off: one reject rule ahead of the route rules. In sing-box 1.11+ the
    // inbound no longer carries `udp`/`network` (removed in 1.13 — writing them
    // makes `sing-box check` refuse the whole config), so this is the supported
    // way to keep exit ports TCP-only.
    if disable_udp && !exit_tags.is_empty() {
        rules.insert(0, json!({
            "inbound": exit_tags,
            "network": ["udp"],
            "action": "reject",
        }));
    }

    // One selector per live exit: every node is a candidate, the current pick
    // is the default. `interrupt_exist_connections: false` is the whole point —
    // a re-point must not tear down traffic that is already flowing.
    let node_tags: Vec<String> = (0..nodes.len()).map(|i| format!("o{i}")).collect();
    for e in routed {
        outbounds.push(json!({
            "type": "selector",
            "tag": format!("s{}", e.slot),
            "outbounds": node_tags,
            "default": format!("o{}", e.node_idx),
            "interrupt_exist_connections": false,
        }));
    }

    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    let mut conf = json!({
        "log": {"level": "warn", "timestamp": true},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    });
    if let Some(api) = api {
        conf["experimental"] = json!({
            "clash_api": {
                "external_controller": api.controller,
                "secret": api.secret,
            }
        });
    }
    conf
}

/// (selector tag, node tag) for every exit port in a built config.
pub fn mapping_of(conf: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = conf.get("outbounds").and_then(|v| v.as_array()) {
        for o in arr {
            if o.get("type").and_then(|t| t.as_str()) != Some("selector") {
                continue;
            }
            let (Some(tag), Some(def)) = (
                o.get("tag").and_then(|t| t.as_str()),
                o.get("default").and_then(|d| d.as_str()),
            ) else {
                continue;
            };
            out.push((tag.to_string(), def.to_string()));
        }
    }
    out
}

/// The config with every selector's pick neutralised. Two configs with the same
/// structural hash describe the same process — only the port→node assignment
/// differs, which the control API can fix in place.
pub fn structural_hash(conf: &Value) -> u64 {
    let mut c = conf.clone();
    if let Some(arr) = c.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
        for o in arr.iter_mut() {
            if o.get("type").and_then(|t| t.as_str()) == Some("selector") {
                o["default"] = json!("");
            }
        }
    }
    hash_of(&serde_json::to_string(&c).unwrap_or_default())
}

/// Tags for one exit's inbound set, in the same order build_config emits them.
fn exit_tags_placeholder(slot: usize, addrs: usize) -> Vec<String> {
    (0..addrs)
        .map(|ai| {
            if ai == 0 {
                format!("x{slot}")
            } else {
                format!("x{slot}_{ai}")
            }
        })
        .collect()
}

/// Write the config atomically. Used by both paths: a hot swap still keeps the
/// file truthful, or a later restart would resurrect the old assignment.
fn write_config(config_path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let tmp: PathBuf = config_path.with_extension("json.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("写 {tmp:?}"))?;
    std::fs::rename(&tmp, config_path)?;
    Ok(())
}

fn hash_of(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

impl Sidecar {
    pub fn alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Write the config and restart sing-box if the hash changed (or it died).
    /// `check` runs first: a config sing-box refuses must never take down a
    /// working sidecar.
    pub async fn apply(
        &mut self,
        bin: &str,
        config_path: &Path,
        cfg: &Value,
        log_path: &Path,
        api: Option<&ClashApi>,
    ) -> Result<bool> {
        if cfg
            .get("inbounds")
            .and_then(|v| v.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            self.last_err = "生成的配置里一个 inbound 都没有,拒绝启动".into();
            return Err(anyhow!(self.last_err.clone()));
        }
        let text = serde_json::to_string_pretty(cfg)?;
        let h = hash_of(&text);
        if h == self.config_hash && self.alive() {
            return Ok(false);
        }
        let sh = structural_hash(cfg);
        let want = mapping_of(cfg);

        // Same process, only the port→node assignment moved: re-point the
        // selectors over the control API. Nothing is killed, so established
        // connections keep flowing through the node they started on.
        // Why is the config different at all? Worth saying out loud: a
        // restart drops every connection on every port.
        let why = if !self.alive() {
            "sing-box 已经死了"
        } else if sh != self.structural_hash {
            "结构变了(端口开合/节点表变了)"
        } else {
            "只有指向变了"
        };
        eprintln!("[exitmap] 配置要变: {why}");

        if sh == self.structural_hash && self.alive() && !want.is_empty() {
            if let Some(api) = api {
                // Disk first: if the API call dies halfway, the restart path
                // must load the *new* assignment, not the old one.
                if let Err(e) = write_config(config_path, &text) {
                    self.last_err = format!("写配置失败: {e}");
                } else {
                    match self.hot_swap(api, &want).await {
                        Ok(n) => {
                            self.config_hash = h;
                            self.mapping = want.into_iter().collect();
                            self.last_err.clear();
                            self.last_action = "hot";
                            eprintln!("[exitmap] {n} 个出口热切换,没重启 sing-box");
                            return Ok(true);
                        }
                        Err(e) => {
                            self.last_err = format!("热切换失败,回退到重启: {e}");
                            eprintln!("[exitmap] {} · {}", self.last_err, "所有端口会断一次");
                        }
                    }
                }
            }
        }

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let tmp: PathBuf = config_path.with_extension("json.tmp");
        std::fs::write(&tmp, &text).with_context(|| format!("写 {tmp:?}"))?;

        // Validate before swapping anything.
        let check = tokio::process::Command::new(bin)
            .arg("check")
            .arg("-c")
            .arg(&tmp)
            .output()
            .await;
        match check {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let msg = String::from_utf8_lossy(&o.stderr).to_string();
                self.last_err = format!("sing-box check 拒绝生成的配置: {}", tail(&msg, 400));
                let _ = std::fs::remove_file(&tmp);
                return Err(anyhow!(self.last_err.clone()));
            }
            Err(e) => {
                self.last_err = format!("跑不动 {bin}: {e}");
                let _ = std::fs::remove_file(&tmp);
                return Err(anyhow!(self.last_err.clone()));
            }
        }
        std::fs::rename(&tmp, config_path)?;

        self.stop();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .ok();
        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .arg("-c")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        match log {
            Some(f) => {
                cmd.stderr(Stdio::from(f));
            }
            None => {
                cmd.stderr(Stdio::null());
            }
        }
        // A bind failure can be a lost race against our own outbound traffic
        // grabbing that port as a source port (this box reserves nothing by
        // default: ip_local_port_range is 1024-65535). One retry after the
        // racing connection has been reaped settles it.
        let mut child = cmd.spawn().map_err(|e| anyhow!("启动 sing-box 失败: {e}"))?;
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        if !matches!(child.try_wait(), Ok(None)) {
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            let mut cmd = Command::new(bin);
            cmd.arg("run")
                .arg("-c")
                .arg(config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            child = cmd.spawn().map_err(|e| anyhow!("重试启动 sing-box 失败: {e}"))?;
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }
        self.child = Some(child);
        self.last_action = "restart";
        self.config_hash = h;
        self.structural_hash = sh;
        self.mapping = want.into_iter().collect();
        self.ports = config_ports(cfg);
        self.last_err.clear();
        if !self.alive() {
            self.last_err = "sing-box 启动后立刻退出,看 sing-box.log".to_string();
            return Err(anyhow!(self.last_err.clone()));
        }
        Ok(true)
    }

    /// Kill sing-box processes still running *our* config file. A manual run
    /// that got SIGKILLed leaves one behind (PPID 1), and it holds the ports
    /// forever — found exactly that in testing: an orphan from two hours
    /// earlier was squatting 31001-31044.
    pub fn kill_strays(config_path: &std::path::Path) {
        let pat = format!("sing-box run -c {}", config_path.display());
        let out = std::process::Command::new("pgrep").arg("-f").arg(&pat).output();
        if let Ok(o) = out {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
                }
            }
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
            let _ = std::thread::spawn(move || {
                let _ = c.try_wait();
            });
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        self.config_hash = 0;
        self.structural_hash = 0;
        self.mapping.clear();
    }

    /// Re-point each selector at most once, and only for the ports that
    /// actually changed. Any failure is fatal for the hot path: the caller
    /// falls back to a restart, which always lands on the config on disk.
    async fn hot_swap(&mut self, api: &ClashApi, want: &[(String, String)]) -> Result<usize> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()?;
        let mut n = 0usize;
        for (sel, target) in want {
            if self.mapping.get(sel) == Some(target) {
                continue;
            }
            let url = format!("http://{}/proxies/{}", api.controller, sel);
            let mut last = String::from("没有响应");
            let mut done = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                match client
                    .put(&url)
                    .bearer_auth(&api.secret)
                    .json(&serde_json::json!({"name": target}))
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {
                        done = true;
                        break;
                    }
                    Ok(r) => {
                        let code = r.status();
                        let body = r.text().await.unwrap_or_default();
                        last = format!("HTTP {code} {}", tail(&body, 160));
                        if code.is_client_error() {
                            break; // 4xx will not get better by asking again
                        }
                    }
                    Err(e) => last = e.to_string(),
                }
            }
            if !done {
                anyhow::bail!("{sel} -> {target}: {last}");
            }
            n += 1;
        }
        Ok(n)
    }
}

fn tail(s: &str, n: usize) -> String {
    let s = s.trim();
    if s.len() <= n {
        return s.to_string();
    }
    let start = s.len() - n;
    let start = (0..=start).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
    format!("…{}", &s[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str) -> Node {
        Node {
            id: id.into(),
            name: id.into(),
            proto: "socks".into(),
            outbound: json!({"type": "socks", "server": "127.0.0.1", "server_port": 1080}),
            raw: String::new(),
        }
    }

    fn slot(s: usize, port: u16, node_idx: usize) -> ExitSlot {
        ExitSlot { slot: s, port, node_idx }
    }

    fn build(nodes: &[Node], exits: &[ExitSlot]) -> Value {
        build_config(
            nodes,
            32001,
            exits,
            &std::collections::HashSet::new(),
            &["127.0.0.1".into()],
            true,
            None,
        )
    }

    #[test]
    fn exit_ports_ride_a_selector_that_starts_on_the_chosen_node() {
        let nodes = vec![node("a"), node("b"), node("c")];
        let conf = build(&nodes, &[slot(3, 31004, 1)]);
        let rules = conf["route"]["rules"].as_array().unwrap();
        let rule = rules
            .iter()
            .find(|r| r["outbound"] == json!("s3"))
            .expect("出口应该走 selector,不是直接走节点");
        assert_eq!(rule["inbound"], json!(["x3"]));
        let sel = conf["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == json!("s3"))
            .unwrap();
        assert_eq!(sel["type"], json!("selector"));
        assert_eq!(sel["default"], json!("o1"));
        assert_eq!(sel["outbounds"].as_array().unwrap().len(), 3);
        // 换指向不能掐断已经在跑的连接 —— 热切换的全部意义在这一个开关上。
        assert_eq!(sel["interrupt_exist_connections"], json!(false));
    }

    #[test]
    fn moving_an_exit_between_nodes_is_not_a_structural_change() {
        let nodes = vec![node("a"), node("b"), node("c")];
        let one = build(&nodes, &[slot(0, 31001, 0)]);
        let two = build(&nodes, &[slot(0, 31001, 2)]);
        assert_eq!(
            mapping_of(&one),
            vec![("s0".to_string(), "o0".to_string())]
        );
        assert_eq!(
            mapping_of(&two),
            vec![("s0".to_string(), "o2".to_string())]
        );
        assert_ne!(hash_of(&one.to_string()), hash_of(&two.to_string()));
        assert_eq!(
            structural_hash(&one),
            structural_hash(&two),
            "只有指向变了,进程不用重启"
        );
    }

    #[test]
    fn opening_or_closing_a_port_is_structural() {
        let nodes = vec![node("a")];
        let one = build(&nodes, &[slot(0, 31001, 0)]);
        let two = build(&nodes, &[slot(0, 31001, 0), slot(1, 31002, 0)]);
        assert_ne!(structural_hash(&one), structural_hash(&two));
    }

    #[test]
    fn the_control_plane_is_only_emitted_when_asked() {
        let nodes = vec![node("a")];
        let exits = vec![slot(0, 31001, 0)];
        assert!(build(&nodes, &exits).get("experimental").is_none());
        let api = ClashApi {
            controller: "127.0.0.1:18791".into(),
            secret: "abcd".into(),
        };
        let conf = build_config(
            &nodes,
            32001,
            &exits,
            &std::collections::HashSet::new(),
            &["127.0.0.1".into()],
            true,
            Some(&api),
        );
        assert_eq!(
            conf["experimental"]["clash_api"]["external_controller"],
            json!("127.0.0.1:18791")
        );
        assert_eq!(conf["experimental"]["clash_api"]["secret"], json!("abcd"));
    }
}
