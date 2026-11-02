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
}

impl Default for Sidecar {
    fn default() -> Self {
        Self {
            child: None,
            last_err: String::new(),
            config_hash: 0,
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
pub fn free_ports(ports: &[u16]) -> std::collections::HashSet<u16> {
    let mut busy = std::collections::HashSet::new();
    for p in ports {
        if std::net::TcpListener::bind(("127.0.0.1", *p)).is_err() {
            busy.insert(*p);
        }
    }
    busy
}

pub fn build_config(
    nodes: &[Node],
    probe_base: u16,
    exits: &[ExitSlot],
    busy: &std::collections::HashSet<u16>,
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
    for e in exits {
        if e.node_idx >= nodes.len() || busy.contains(&e.port) {
            continue;
        }
        inbounds.push(json!({
            "type": "mixed", // socks5 + http on one port: every client speaks one of them
            "tag": format!("x{}", e.slot),
            "listen": "127.0.0.1",
            "listen_port": e.port as u32,
        }));
        rules.push(json!({
            "inbound": [format!("x{}", e.slot)],
            "outbound": format!("o{}", e.node_idx),
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
        self.last_err.clear();
        if !self.alive() {
            self.last_err = "sing-box 启动后立刻退出,看 sing-box.log".to_string();
            return Err(anyhow!(self.last_err.clone()));
        }
        Ok(true)
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
