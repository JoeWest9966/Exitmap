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

/// A reserved block of slots for one country, e.g. JP -> ports 31001..=31020.
///
/// Slots are stored 0-based (relative to `portBase`) so `rebase()` cannot leave
/// a block pointing at the wrong numbers: the port is always recomputed as
/// `port_base + slot`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountryBlock {
    pub cc: String,
    pub from_slot: usize,
    pub to_slot: usize,
}

impl CountryBlock {
    pub fn contains(&self, slot: usize) -> bool {
        self.from_slot <= slot && slot <= self.to_slot
    }
}

/// What a reconcile pass did, so the caller can log a drop instead of silently
/// returning a shorter table.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReconcileOutcome {
    pub changed: bool,
    /// Live IPs that found no legal slot this round (their country's block is
    /// full, or every general slot is taken).
    pub dropped: usize,
}

/// Parse `"JP=31001-31020, US=31021-31040"` into slot blocks.
///
/// Absolute port numbers are what the operator types; slots are what the pool
/// allocates. The conversion happens here once, and the rest of the code never
/// has to subtract `portBase` again. `CC=31001` is accepted as a one-slot block.
pub fn parse_country_slots(
    s: &str,
    port_base: u16,
    max_exits: usize,
) -> Result<Vec<CountryBlock>, String> {
    let mut out: Vec<CountryBlock> = Vec::new();
    if s.trim().is_empty() {
        return Ok(out);
    }
    let first = port_base as u32;
    let last = first + max_exits.max(1) as u32 - 1;
    for raw in s.split([',', ';', '\n']) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (cc, range) = raw
            .split_once('=')
            .ok_or_else(|| format!("`{raw}` 不是 CC=起-止 的形状"))?;
        let cc = cc.trim().to_ascii_uppercase();
        if cc.len() < 2 || cc.len() > 3 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(format!("`{cc}` 不是两位国家码"));
        }
        let (a, b) = match range.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (range.trim(), range.trim()),
        };
        let from: u32 = a
            .parse()
            .map_err(|_| format!("`{raw}` 的起始端口不是数字"))?;
        let to: u32 = b
            .parse()
            .map_err(|_| format!("`{raw}` 的结束端口不是数字"))?;
        if from > to {
            return Err(format!("`{raw}` 起止反了"));
        }
        if from < first || to > last {
            return Err(format!("`{raw}` 超出端口段 {first}–{last}"));
        }
        let block = CountryBlock {
            cc: cc.clone(),
            from_slot: (from - first) as usize,
            to_slot: (to - first) as usize,
        };
        // A country may legitimately own several blocks (pin one port out of a
        // bigger block and you get JP=…, US=x, JP=…). Overlap is still fatal.
        if out
            .iter()
            .any(|b| block.from_slot <= b.to_slot && b.from_slot <= block.to_slot)
        {
            return Err(format!("`{raw}` 和别的段重叠"));
        }
        out.push(block);
    }
    Ok(out)
}

/// Which country a slot is reserved for, if any.
pub fn block_cc<'a>(blocks: &'a [CountryBlock], slot: usize) -> Option<&'a str> {
    blocks.iter().find(|b| b.contains(slot)).map(|b| b.cc.as_str())
}

/// Render blocks back into the `"JP=31001-31020"` form the config stores.
pub fn render_country_slots(blocks: &[CountryBlock], port_base: u16) -> String {
    let mut b = blocks.to_vec();
    b.sort_by_key(|x| x.from_slot);
    b.iter()
        .map(|x| {
            let from = port_base as usize + x.from_slot;
            let to = port_base as usize + x.to_slot;
            if from == to {
                format!("{}={from}", x.cc)
            } else {
                format!("{}={from}-{to}", x.cc)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Join touching blocks of the same country, so clearing a pin in the middle of
/// a range does not leave the config full of one-port fragments.
fn merge_adjacent(mut blocks: Vec<CountryBlock>) -> Vec<CountryBlock> {
    blocks.sort_by_key(|b| (b.cc.clone(), b.from_slot));
    let mut out: Vec<CountryBlock> = Vec::new();
    for b in blocks {
        match out.last_mut() {
            Some(last) if last.cc == b.cc && last.to_slot + 1 == b.from_slot => {
                last.to_slot = b.to_slot;
            }
            _ => out.push(b),
        }
    }
    out.sort_by_key(|b| b.from_slot);
    out
}

/// Pin one port to one country (or clear it with `cc == ""`), returning the new
/// config string. This is what the per-port 国家 button writes; the range
/// editor writes the same string, so there is only one source of truth.
pub fn set_slot_country(
    slots: &str,
    port: u16,
    cc: &str,
    port_base: u16,
    max_exits: usize,
) -> Result<String, String> {
    let mut blocks = parse_country_slots(slots, port_base, max_exits)?;
    let cc = cc.trim().to_ascii_uppercase();
    if !cc.is_empty()
        && (cc.len() < 2 || cc.len() > 3 || !cc.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Err(format!("`{cc}` 不是两位国家码"));
    }
    let max_exits = max_exits.max(1);
    if port < port_base || (port - port_base) as usize >= max_exits {
        return Err(format!("{port} 不在出口端口段里"));
    }
    let slot = (port - port_base) as usize;

    // Cut the slot out of whatever block holds it, splitting in the middle.
    let mut cut: Vec<CountryBlock> = Vec::new();
    for b in blocks.drain(..) {
        if !b.contains(slot) {
            cut.push(b);
            continue;
        }
        if b.from_slot < slot {
            cut.push(CountryBlock {
                cc: b.cc.clone(),
                from_slot: b.from_slot,
                to_slot: slot - 1,
            });
        }
        if slot < b.to_slot {
            cut.push(CountryBlock {
                cc: b.cc,
                from_slot: slot + 1,
                to_slot: b.to_slot,
            });
        }
    }
    if !cc.is_empty() {
        cut.push(CountryBlock {
            cc,
            from_slot: slot,
            to_slot: slot,
        });
    }
    Ok(render_country_slots(&merge_adjacent(cut), port_base))
}

/// Is this slot legal for an IP of country `cc` under the current blocks?
///
/// One-directional on purpose: a slot reserved for C accepts only C, and a slot
/// nobody reserved accepts anything. The other direction ("C may only use its
/// own slots") would turn a single pinned JP port into a one-port cap for the
/// whole country, which is not what pinning one port means.
fn slot_ok(cc: &str, slot: usize, blocks: &[CountryBlock]) -> bool {
    match block_cc(blocks, slot) {
        Some(c) => c == cc,
        None => true,
    }
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
    ///
    /// `blocks` carves the slot space into per-country reservations: an IP may
    /// only take a slot inside its own country's block, and a country without a
    /// block may only take slots outside every block. A live IP that does not
    /// fit is dropped for this round — spilling JP into a non-reserved port
    /// would silently break the "this port is always JP" promise the feature
    /// exists to make.
    pub fn reconcile(
        &mut self,
        live: &[LiveIp],
        port_base: u16,
        max_exits: usize,
        blocks: &[CountryBlock],
        now: i64,
    ) -> ReconcileOutcome {
        let max_exits = max_exits.max(1);
        let mut changed = false;
        let mut dropped = 0usize;
        let mut events: Vec<Rebind> = Vec::new();

        // ── ① Slots we already hold: refresh the live ones, evict the dead ──
        let mut kept: Vec<ExitView> = Vec::new();
        for mut e in std::mem::take(&mut self.exits) {
            match live.iter().find(|l| l.ip == e.ip) {
                Some(l) => {
                    // A block added (or edited) after this exit was placed can
                    // leave it on a slot it is no longer allowed to hold. Free
                    // it here so ② puts it where the config says it belongs.
                    if !slot_ok(&l.country, e.slot, blocks) {
                        changed = true;
                        events.push(Rebind {
                            at_ms: now,
                            slot: e.slot,
                            port: e.port,
                            from_ip: Some(e.ip.clone()),
                            to_ip: None,
                            reason: "国家端口段调整,槽位释放".into(),
                        });
                        continue;
                    }
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
            let slot = match self.slot_for(&l.country, max_exits, blocks) {
                Some(s) => s,
                None => {
                    // This country's block is full (or the general pool is):
                    // the IP sits this round out. `continue`, not `break` — a
                    // full JP block must not stop US from being placed.
                    dropped += 1;
                    continue;
                }
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

        // Flush ①/② before ③: `note` inserts at the front, so writing the
        // release/placement batch first and the fill on top keeps the log in
        // the order things actually happened (newest first, reading down).
        for ev in events {
            self.note(ev);
        }

        // ── ③ Reserved ports outlive the IP that held them ────────────────
        // ①/② never move a live, legal exit, so a reserved port whose IP died
        // would sit closed while a matching exit idles one slot over. The
        // promise is "this port keeps serving that country", not "that IP":
        // pull a same-country exit in instead of leaving the port dark.
        let mut reserved: Vec<usize> = blocks
            .iter()
            .flat_map(|b| b.from_slot..=b.to_slot)
            .filter(|s| *s < max_exits)
            .collect();
        reserved.sort_unstable();
        reserved.dedup();
        for slot in reserved {
            if self.exits.iter().any(|e| e.slot == slot) {
                continue;
            }
            let cc = block_cc(blocks, slot).unwrap_or("").to_string();
            if cc.is_empty() {
                continue;
            }
            if self.fill_slot(slot, &cc, blocks, port_base, now).is_some() {
                changed = true;
            }
        }

        self.exits.sort_by_key(|e| e.slot);
        for e in self.exits.iter_mut() {
            e.port = Self::slot_port(port_base, e.slot);
        }
        ReconcileOutcome { changed, dropped }
    }

    /// Reserved ports with nothing on them, so the panel can keep showing the
    /// row instead of letting a pinned port vanish for a few minutes.
    ///
    /// "31001 是 US" is a contract, not a row that comes and goes: an empty
    /// reserved port is still a fact about the table, and hiding it is what
    /// makes people think the pin broke.
    pub fn reserved_placeholders(
        &self,
        blocks: &[CountryBlock],
        port_base: u16,
        max_exits: usize,
    ) -> Vec<(u16, usize, String, u32)> {
        let mut out: Vec<(u16, usize, String, u32)> = blocks
            .iter()
            .flat_map(|b| {
                (b.from_slot..=b.to_slot).map(move |s| (s, b.cc.clone()))
            })
            .filter(|(s, _)| *s < max_exits)
            .filter(|(s, _)| !self.exits.iter().any(|e| e.slot == *s))
            .map(|(s, cc)| {
                (
                    Self::slot_port(port_base, s),
                    s,
                    cc,
                    self.slot_rebinds.get(&s).copied().unwrap_or(0),
                )
            })
            .collect();
        out.sort_by_key(|(port, _, _, _)| *port);
        out
    }

    /// Drop every exit whose slot is illegal under `blocks`, so the caller can
    /// apply the new sing-box config and let the next round re-place it. Used
    /// when a port gets pinned to a country: leaving the old row in place would
    /// keep a "JP port" serving a US IP until that IP happened to die.
    pub fn drop_ineligible(&mut self, blocks: &[CountryBlock], now: i64) -> usize {
        let exits = std::mem::take(&mut self.exits);
        let mut keep: Vec<ExitView> = Vec::with_capacity(exits.len());
        let mut n = 0usize;
        for e in exits {
            if slot_ok(&e.country, e.slot, blocks) {
                keep.push(e);
            } else {
                n += 1;
                self.note(Rebind {
                    at_ms: now,
                    slot: e.slot,
                    port: e.port,
                    from_ip: Some(e.ip.clone()),
                    to_ip: None,
                    reason: "国家端口段调整,槽位释放".into(),
                });
            }
        }
        self.exits = keep;
        n
    }

    /// Lowest free slot this country should take: its own reserved ports first
    /// (so a pinned port actually gets used), then any unpinned slot. Spilling
    /// out of the reserved set is deliberate — a country must never be capped
    /// at the number of ports reserved for it.
    fn slot_for(&self, cc: &str, max_exits: usize, blocks: &[CountryBlock]) -> Option<usize> {
        if !cc.is_empty() {
            if let Some(s) = blocks
                .iter()
                .filter(|b| b.cc == cc)
                .flat_map(|b| b.from_slot..=b.to_slot)
                .filter(|s| *s < max_exits)
                .find(|s| self.slot_free(*s))
            {
                return Some(s);
            }
        }
        (0..max_exits).find(|s| self.slot_free(*s) && block_cc(blocks, *s).is_none())
    }

    fn slot_free(&self, slot: usize) -> bool {
        !self.exits.iter().any(|e| e.slot == slot)
    }

    /// Move one exit to another slot, keeping port/rebind bookkeeping honest.
    fn move_exit(&mut self, idx: usize, new_slot: usize, port_base: u16, now: i64, reason: &str) -> bool {
        if self.exits[idx].slot == new_slot {
            return false;
        }
        let ip = self.exits[idx].ip.clone();
        let old_slot = self.exits[idx].slot;
        let old_port = self.exits[idx].port;
        let prev = self.slot_last.get(&new_slot).cloned();
        let n = self.slot_rebinds.get(&new_slot).copied().unwrap_or(0) + 1;
        self.slot_rebinds.insert(new_slot, n);
        self.slot_last.insert(new_slot, ip.clone());
        let e = &mut self.exits[idx];
        e.slot = new_slot;
        e.port = Self::slot_port(port_base, new_slot);
        e.since_ms = now;
        e.rebinds = n;
        let (slot, port) = (e.slot, e.port);
        // Log the vacated port too. Without it a port can go empty with nothing
        // in the log explaining where its exit went — which is exactly the
        // "31001 消失了" report this had to be debugged from.
        self.note(Rebind {
            at_ms: now,
            slot: old_slot,
            port: old_port,
            from_ip: Some(ip.clone()),
            to_ip: None,
            reason: format!("{reason}（原端口让出，出口搬到 {port}）"),
        });
        self.note(Rebind {
            at_ms: now,
            slot,
            port,
            from_ip: prev,
            to_ip: Some(ip),
            reason: reason.into(),
        });
        true
    }

    /// Pull an exit of country `cc` into an empty slot. Used right after a port
    /// is pinned: without this the port would sit closed while matching exits
    /// idle on other ports, which reads as "the button did nothing".
    pub fn fill_slot(
        &mut self,
        slot: usize,
        cc: &str,
        blocks: &[CountryBlock],
        port_base: u16,
        now: i64,
    ) -> Option<String> {
        if cc.is_empty() || self.exits.iter().any(|e| e.slot == slot) {
            return None;
        }
        // Highest unpinned slot first: it keeps the low ports (the ones a
        // client is most likely to have hardcoded) exactly where they are.
        let donor = self
            .exits
            .iter()
            .enumerate()
            .filter(|(_, e)| e.country == cc && block_cc(blocks, e.slot).is_none())
            .max_by_key(|(_, e)| e.slot)
            .map(|(i, _)| i)?;
        let ip = self.exits[donor].ip.clone();
        self.move_exit(donor, slot, port_base, now, "国家端口固定,换到这个端口");
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(ip: &str, cc: &str, ms: u64) -> LiveIp {
        LiveIp {
            ip: ip.into(),
            country: cc.into(),
            latency_ms: ms,
            node_id: format!("n-{ip}"),
            node_name: format!("node {ip}"),
            proto: "socks5".into(),
        }
    }

    fn blocks(s: &str, base: u16, max: usize) -> Vec<CountryBlock> {
        parse_country_slots(s, base, max).unwrap()
    }

    fn ports(p: &Pool) -> Vec<(u16, String)> {
        let mut v: Vec<(u16, String)> = p.exits.iter().map(|e| (e.port, e.ip.clone())).collect();
        v.sort();
        v
    }

    #[test]
    fn parse_accepts_ports_and_normalises_country() {
        let b = parse_country_slots("JP=31001-31020, us=31021-31040\nDE=31041", 31001, 128).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].cc, "JP");
        assert_eq!((b[0].from_slot, b[0].to_slot), (0, 19));
        assert_eq!(b[1].cc, "US");
        assert_eq!((b[1].from_slot, b[1].to_slot), (20, 39));
        assert_eq!(b[2].cc, "DE");
        assert_eq!((b[2].from_slot, b[2].to_slot), (40, 40));
    }

    #[test]
    fn parse_rejects_the_ways_it_can_be_wrong() {
        let base = 31001u16;
        let max = 20usize;
        // out of range
        assert!(parse_country_slots("JP=31001-31021", base, max).is_err());
        assert!(parse_country_slots("JP=31000", base, max).is_err());
        // reversed
        assert!(parse_country_slots("JP=31005-31001", base, max).is_err());
        // overlap
        assert!(parse_country_slots("JP=31001-31010, US=31010-31020", base, max).is_err());
        // a country may own several blocks (pinning one port out of a range)
        assert!(parse_country_slots("JP=31001-31002, JP=31003-31004", base, max).is_ok());
        // garbage
        assert!(parse_country_slots("JP", base, max).is_err());
        assert!(parse_country_slots("JP=a-b", base, max).is_err());
        assert!(parse_country_slots("JAPAN=31001-31002", base, max).is_err());
        // empty is fine (feature off)
        assert!(parse_country_slots("  ", base, max).unwrap().is_empty());
    }

    #[test]
    fn a_reserved_port_only_accepts_its_country_but_caps_nobody() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("JP=31001-31003", base, max); // slots 0..=2
        let mut p = Pool::default();
        p.reconcile(
            &[live("1.1.1.1", "US", 10), live("2.2.2.2", "JP", 20), live("3.3.3.3", "DE", 30)],
            base,
            max,
            &b,
            1,
        );
        // US is fastest but 31001 is reserved for JP, so JP takes it and US is
        // pushed to the first unpinned slot.
        assert_eq!(
            ports(&p),
            vec![
                (31001, "2.2.2.2".into()),
                (31004, "1.1.1.1".into()),
                (31005, "3.3.3.3".into()),
            ]
        );
    }

    #[test]
    fn reserved_slots_are_never_given_to_unlisted_countries() {
        let base = 31001u16;
        let max = 4usize;
        let b = blocks("JP=31001-31002", base, max); // slots 0..=1
        let mut p = Pool::default();
        p.reconcile(
            &[live("1.1.1.1", "US", 10), live("2.2.2.2", "US", 20)],
            base,
            max,
            &b,
            1,
        );
        // Only the two unreserved slots (31003/31004) exist for US.
        assert_eq!(ports(&p), vec![(31003, "1.1.1.1".into()), (31004, "2.2.2.2".into())]);
    }

    #[test]
    fn extra_ips_of_a_pinned_country_spill_to_free_slots() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("JP=31001-31001", base, max); // exactly one JP port
        let mut p = Pool::default();
        let out = p.reconcile(
            &[live("1.1.1.1", "JP", 10), live("2.2.2.2", "JP", 20)],
            base,
            max,
            &b,
            1,
        );
        // Pinning one port must not cap the whole country: the second JP IP
        // keeps a port, it just does not get the reserved one.
        assert_eq!(out.dropped, 0);
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())]
        );
        assert_eq!(block_cc(&b, 0), Some("JP"));
    }

    #[test]
    fn set_slot_country_splits_and_remerges() {
        let base = 31001u16;
        let max = 20usize;
        // cut US out of the middle of the JP block
        let s = set_slot_country("JP=31001-31005", 31003, "US", base, max).unwrap();
        assert_eq!(s, "JP=31001-31002, US=31003, JP=31004-31005");
        // hand it back to JP and the three pieces collapse again
        let s = set_slot_country(&s, 31003, "jp", base, max).unwrap();
        assert_eq!(s, "JP=31001-31005");
        // clearing a pin in the middle does not merge across the hole
        let s = set_slot_country(&s, 31003, "", base, max).unwrap();
        assert_eq!(s, "JP=31001-31002, JP=31004-31005");
        // out of range / bad country code
        assert!(set_slot_country("", 39999, "JP", base, max).is_err());
        assert!(set_slot_country("", 31001, "J", base, max).is_err());
    }

    #[test]
    fn fill_slot_pulls_a_matching_exit_into_an_empty_port() {
        let base = 31001u16;
        let max = 8usize;
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "JP", 10), live("2.2.2.2", "JP", 20)], base, max, &[], 1);
        let b = blocks("JP=31003", base, max); // port 31003 pinned to JP, empty
        // occupant of the pinned slot? none, so nothing to evict
        assert_eq!(p.drop_ineligible(&b, 2), 0);
        assert_eq!(p.fill_slot(2, "JP", &b, base, 3).as_deref(), Some("2.2.2.2"));
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31003, "2.2.2.2".into())]
        );
        assert!(p.log.iter().any(|r| r.reason.contains("国家端口固定")));
    }

    #[test]
    fn a_reserved_port_is_refilled_after_its_ip_dies() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("JP=31001", base, max); // one reserved JP port
        let mut p = Pool::default();
        // Round 1: A takes the reserved port, B lands on a general one.
        p.reconcile(&[live("1.1.1.1", "JP", 10), live("2.2.2.2", "JP", 20)], base, max, &b, 1);
        assert_eq!(ports(&p), vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())]);

        // Round 2: A died. B is still alive and legal where it sits, so ①/②
        // leave it alone — ③ is what keeps 31001 serving JP instead of going
        // dark while a JP exit idles on 31002.
        let out = p.reconcile(&[live("2.2.2.2", "JP", 20)], base, max, &b, 2);
        assert!(out.changed);
        assert_eq!(ports(&p), vec![(31001, "2.2.2.2".into())]);
        assert!(p.log.iter().any(|r| r.reason.contains("国家端口固定")));
        // Both ends of the move are on the record: 31002 gave the exit up and
        // 31001 received it, so a port never goes empty unaccounted for.
        assert!(p
            .log
            .iter()
            .any(|r| r.port == 31002 && r.to_ip.is_none() && r.reason.contains("原端口让出")));
        assert!(p.log.iter().any(|r| r.port == 31001 && r.to_ip.as_deref() == Some("2.2.2.2")));
    }

    #[test]
    fn a_reserved_port_stays_closed_when_no_matching_country_exists() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("JP=31001", base, max);
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 10)], base, max, &b, 1);
        // US may not take the JP port and there is no JP exit to pull in: the
        // reserved port stays empty rather than serving the wrong country.
        assert_eq!(ports(&p), vec![(31002, "1.1.1.1".into())]);
        assert!(!p.exits.iter().any(|e| e.slot == 0));
    }

    #[test]
    fn empty_reserved_ports_are_still_reported() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("JP=31001-31003", base, max);
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "JP", 10)], base, max, &b, 1);
        // 31001 is taken; 31002/31003 are reserved but empty and must still be
        // listed, so a pinned port cannot silently disappear from the table.
        let holes = p.reserved_placeholders(&b, base, max);
        assert_eq!(
            holes,
            vec![(31002, 1, "JP".to_string(), 0), (31003, 2, "JP".to_string(), 0)]
        );
        // Nothing is invented for ports nobody reserved.
        assert!(holes.iter().all(|(port, _, _, _)| *port >= 31002));
    }

    #[test]
    fn pinning_a_port_evicts_the_wrong_country_occupant() {
        let base = 31001u16;
        let max = 8usize;
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 10)], base, max, &[], 1);
        let b = blocks("JP=31001", base, max);
        assert_eq!(p.drop_ineligible(&b, 2), 1, "US must leave a JP-pinned port");
        assert!(p.exits.is_empty());
    }

    #[test]
    fn editing_blocks_moves_exits_that_are_now_illegal() {
        let base = 31001u16;
        let max = 8usize;
        let mut p = Pool::default();
        // No blocks yet: US takes slot 0, JP slot 1.
        p.reconcile(&[live("1.1.1.1", "US", 10), live("2.2.2.2", "JP", 20)], base, max, &[], 1);
        assert_eq!(ports(&p), vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())]);

        // Now reserve 31001-31002 for JP: the US exit is illegal where it sits.
        let b = blocks("JP=31001-31002", base, max);
        let out = p.reconcile(&[live("1.1.1.1", "US", 10), live("2.2.2.2", "JP", 20)], base, max, &b, 2);
        assert!(out.changed);
        // JP keeps a reserved slot; US is pushed to the first general slot.
        // JP stays on 31002: ③ only pulls exits out of *general* slots, it does
        // not shuffle a country between two of its own reserved ports (that
        // would cost a client a port and buy nothing). 31001 self-heals when
        // the next JP IP shows up, because reserved slots are tried first.
        assert_eq!(ports(&p), vec![(31002, "2.2.2.2".into()), (31003, "1.1.1.1".into())]);
        // The move is logged, not silent.
        assert!(p.log.iter().any(|r| r.reason.contains("国家端口段")));
    }

    #[test]
    fn drop_ineligible_clears_the_port_immediately() {
        let base = 31001u16;
        let max = 8usize;
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 10), live("2.2.2.2", "JP", 20)], base, max, &[], 1);
        let b = blocks("JP=31001-31002", base, max);
        assert_eq!(p.drop_ineligible(&b, 2), 1);
        assert_eq!(ports(&p), vec![(31002, "2.2.2.2".into())]);
        assert!(p.log.iter().any(|r| r.reason.contains("槽位释放")));
    }

    #[test]
    fn pinned_exit_still_closes_instead_of_rebinding() {
        let base = 31001u16;
        let max = 8usize;
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "JP", 10)], base, max, &[], 1);
        assert!(p.set_pinned(0, true));
        let out = p.reconcile(&[], base, max, &[], 2);
        assert!(out.changed);
        assert_eq!(p.exits.len(), 1);
        assert!(!p.exits[0].alive, "pinned + dead must close the port");
    }
}
