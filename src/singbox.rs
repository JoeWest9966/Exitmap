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
    /// Ports the currently running config binds, so the squat check can tell
    /// "someone else has it" from "we have it".
    pub ports: std::collections::HashSet<u16>,
}

impl Default for Sidecar {
    fn default() -> Self {
        Self {
            child: None,
            last_err: String::new(),
            config_hash: 0,
            ports: std::collections::HashSet::new(),
        }
    }
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
    for e in exits {
        if e.node_idx >= nodes.len() || busy.contains(&e.port) {
            continue;
        }
        rules.push(json!({
            "inbound": exit_tags_placeholder(e.slot, listen.len()),
            "outbound": format!("o{}", e.node_idx),
        }));
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

    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    json!({
        "log": {"level": "warn", "timestamp": true},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    })
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
        self.config_hash = h;
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
