// The exit pool: unique egress IP -> one stable local port.
//
// Slot policy (换绑, as chosen — not strict pinning):
//   * an IP that is still alive keeps the slot it had -> ports stay stable for
//     as long as the IP is;
//   * an IP that vanished frees its slot and the next new IP takes it -> the
//     port keeps working, but the exit behind it changed. That swap is a
//     REBIND and it is logged, because a client that silently starts exiting
//     from another IP is the one failure mode this whole project exists to
//     make visible;
//   * a *pinned* slot never changes IP: if its IP dies the port simply closes
//     (connection refused = an honest failure instead of a silent swap).
//
// Per-slot history (last IP + rebind count) is persisted so a process restart
// does not make every rebind look like the first one.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitView {
    pub slot: usize,
    pub port: u16,
    pub ip: String,
    pub country: String,
    pub latency_ms: u64,
    pub node_id: String,
    pub node_name: String,
    pub proto: String,
    /// When the current IP took this slot (ms epoch).
    pub since_ms: i64,
    /// Last time a probe confirmed this exit (ms epoch).
    pub verified_ms: i64,
    /// How many times this slot changed IP.
    pub rebinds: u32,
    /// Pinned slots keep their IP or close; they are never rebound.
    pub pinned: bool,
    /// False = the IP is gone and the port is closed, but pinned slots keep
    /// their number reserved.
    pub alive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rebind {
    pub at_ms: i64,
    pub slot: usize,
    pub port: u16,
    pub from_ip: Option<String>,
    pub to_ip: Option<String>,
    pub reason: String,
}

/// One live egress IP with the node chosen to ride it.
#[derive(Clone, Debug)]
pub struct LiveIp {
    pub ip: String,
    pub country: String,
    pub latency_ms: u64,
    pub node_id: String,
    pub node_name: String,
    pub proto: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pool {
    pub exits: Vec<ExitView>,
    #[serde(default)]
    pub log: Vec<Rebind>,
    /// slot -> last IP that occupied it (survives the exit's removal).
    #[serde(default)]
    pub slot_last: HashMap<usize, String>,
    #[serde(default)]
    pub slot_rebinds: HashMap<usize, u32>,
    /// ip -> country code. Country does not change for an IP, so it is looked
    /// up once and kept forever instead of once per round.
    #[serde(default)]
    pub countries: HashMap<String, String>,
}

/// Hard bound on memory only — the real retention policy is time-based
/// (`logRetentionDays`), so this is deliberately far above any sane day count.
const LOG_CAP: usize = 20_000;

impl Pool {
    pub fn slot_port(port_base: u16, slot: usize) -> u16 {
        port_base + slot as u16
    }

    pub fn set_pinned(&mut self, slot: usize, pinned: bool) -> bool {
        match self.exits.iter_mut().find(|e| e.slot == slot) {
            Some(e) => {
                e.pinned = pinned;
                true
            }
            None => false,
        }
    }

    /// Re-point every port after the port range moved. The slot stays, so the
    /// only thing a client sees is that its port number changed.
    pub fn rebase(&mut self, port_base: u16) {
        for e in self.exits.iter_mut() {
            e.port = Self::slot_port(port_base, e.slot);
        }
        for r in self.log.iter_mut() {
            r.port = Self::slot_port(port_base, r.slot);
        }
    }

    fn note(&mut self, r: Rebind) {
        self.log.insert(0, r);
        self.log.truncate(LOG_CAP);
    }

    /// Reconcile the pool against this round's live IPs.
    /// Returns true when routing changed (port->IP->node), i.e. when sing-box
    /// has to be reconfigured.
    pub fn reconcile(&mut self, live: &[LiveIp], port_base: u16, max_exits: usize, now: i64) -> bool {
        let max_exits = max_exits.max(1);
        let mut changed = false;
        let mut events: Vec<Rebind> = Vec::new();

        // ── ① Slots we already hold: refresh the live ones, evict the dead ──
        let mut kept: Vec<ExitView> = Vec::new();
        for mut e in std::mem::take(&mut self.exits) {
            match live.iter().find(|l| l.ip == e.ip) {
                Some(l) => {
                    if e.node_id != l.node_id {
                        changed = true; // same IP, better node -> reroute
                    }
                    e.country = l.country.clone();
                    e.latency_ms = l.latency_ms;
                    e.node_name = l.node_name.clone();
                    e.proto = l.proto.clone();
                    e.node_id = l.node_id.clone();
                    e.verified_ms = now;
                    e.alive = true;
                    kept.push(e);
                }
                None if e.pinned => {
                    if e.alive {
                        e.alive = false;
                        changed = true;
                        events.push(Rebind {
                            at_ms: now,
                            slot: e.slot,
                            port: e.port,
                            from_ip: Some(e.ip.clone()),
                            to_ip: None,
                            reason: "钉住的 IP 消失,端口关闭".into(),
                        });
                    }
                    kept.push(e);
                }
                None => {
                    changed = true;
                    events.push(Rebind {
                        at_ms: now,
                        slot: e.slot,
                        port: e.port,
                        from_ip: Some(e.ip.clone()),
                        to_ip: None,
                        reason: "IP 消失,槽位释放".into(),
                    });
                }
            }
        }
        self.exits = kept;

        // ── ② Free slots get the new IPs, fastest first ──
        // Sorting by latency means a pool narrower than the number of live IPs
        // keeps its quickest exits instead of whatever the vendor listed first.
        let mut fresh: Vec<LiveIp> = live
            .iter()
            .filter(|l| !self.exits.iter().any(|e| e.ip == l.ip))
            .cloned()
            .collect();
        fresh.sort_by_key(|l| l.latency_ms);

        for l in fresh {
            let slot = match self.free_slot(max_exits) {
                Some(s) => s,
                None => break, // pool is full: keep the exits we already have
            };
            let prev = self.slot_last.get(&slot).cloned();
            let ip_changed_before = prev.is_some();
            let rebinds = if ip_changed_before {
                let n = self.slot_rebinds.get(&slot).copied().unwrap_or(0) + 1;
                self.slot_rebinds.insert(slot, n);
                n
            } else {
                0
            };
            events.push(Rebind {
                at_ms: now,
                slot,
                port: Self::slot_port(port_base, slot),
                from_ip: prev.clone(),
                to_ip: Some(l.ip.clone()),
                reason: if ip_changed_before {
                    "换绑到新 IP".into()
                } else {
                    "新 IP 占槽".into()
                },
            });
            self.slot_last.insert(slot, l.ip.clone());
            self.exits.push(ExitView {
                slot,
                port: Self::slot_port(port_base, slot),
                ip: l.ip,
                country: l.country,
                latency_ms: l.latency_ms,
                node_id: l.node_id,
                node_name: l.node_name,
                proto: l.proto,
                since_ms: now,
                verified_ms: now,
                rebinds,
                pinned: false,
                alive: true,
            });
            changed = true;
        }

        self.exits.sort_by_key(|e| e.slot);
        for e in self.exits.iter_mut() {
            e.port = Self::slot_port(port_base, e.slot);
        }
        for ev in events {
            self.note(ev);
        }
        changed
    }

    /// Lowest slot in 0..max that is not occupied by a live or pinned exit.
    fn free_slot(&self, max_exits: usize) -> Option<usize> {
        (0..max_exits).find(|s| !self.exits.iter().any(|e| e.slot == *s))
    }
}
