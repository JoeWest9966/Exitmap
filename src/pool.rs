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
    /// Smoothed latency, used for ordering only. One probe sample is far too
    /// noisy to rank ports with; `latency_ms` stays the raw last reading that
    /// the table shows.
    #[serde(default)]
    pub lat_ema: u64,
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
    /// Last time a latency re-sort ran. Persisted so a restart cannot trigger
    /// a re-sort storm; the whole point of the cooldown is that ports stay put.
    #[serde(default)]
    pub last_sort_ms: i64,
    /// ip -> country code. Country does not change for an IP, so it is looked
    /// up once and kept forever instead of once per round.
    #[serde(default)]
    pub countries: HashMap<String, String>,
}

/// Hard bound on memory only — the real retention policy is time-based
/// (`logRetentionDays`), so this is deliberately far above any sane day count.
const LOG_CAP: usize = 20_000;

/// A re-sort must clear both bars: 25% faster AND 80ms faster. Re-ranking
/// means moving an exit to another port, and moving a port means restarting
/// sing-box, which drops *every* client connection, not just the two that
/// traded places. Cheap-to-trigger sorting is therefore a feature that makes
/// the product worse.
const SORT_MIN_GAIN_PCT: u64 = 25;
const SORT_MIN_GAIN_MS: u64 = 80;
/// At most one re-sort event per hour, across all countries.
const SORT_COOLDOWN_MS: i64 = 3_600_000;

/// α≈0.3 integer EMA. First sample seeds it.
fn ema(prev: u64, sample: u64) -> u64 {
    if prev == 0 {
        sample
    } else {
        (prev * 7 + sample * 3) / 10
    }
}

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
                    e.lat_ema = ema(e.lat_ema, l.latency_ms);
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
                lat_ema: l.latency_ms,
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

        // ── ④ Latency order inside a country group ─────────────────────
        // "31001 is the fastest US exit" is only true if something maintains
        // it: placement is latency-ordered, but a faster IP showing up later
        // lands on whatever slot is free. Re-rank, but only when the existing
        // order is *clearly* wrong, and at most once an hour — every re-rank
        // restarts sing-box and drops every connection.
        if self.sort_country_groups(blocks, port_base, now) {
            changed = true;
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

    /// Re-rank every country group whose port order is clearly wrong.
    /// Returns true when anything moved.
    fn sort_country_groups(&mut self, blocks: &[CountryBlock], port_base: u16, now: i64) -> bool {
        // `last_sort_ms == 0` means "never sorted" — a fresh pool must be
        // allowed to find its order immediately, the cooldown only applies to
        // the second re-rank onwards.
        if blocks.is_empty()
            || (self.last_sort_ms > 0 && now - self.last_sort_ms < SORT_COOLDOWN_MS)
        {
            return false;
        }
        let mut ccs: Vec<String> = blocks.iter().map(|b| b.cc.clone()).collect();
        ccs.sort();
        ccs.dedup();
        let mut moved = false;
        for cc in ccs {
            if self.sort_one_group(&cc, blocks, port_base, now) {
                moved = true;
            }
        }
        if moved {
            self.last_sort_ms = now;
        }
        moved
    }

    /// One country: put its fastest exit on its lowest port.
    ///
    /// IP-pinned exits are excluded and their slots are not sortable — a pin
    /// means "this exact IP on this port", so latency does not get a vote.
    fn sort_one_group(
        &mut self,
        cc: &str,
        blocks: &[CountryBlock],
        port_base: u16,
        now: i64,
    ) -> bool {
        let mut slots: Vec<usize> = blocks
            .iter()
            .filter(|b| b.cc == cc)
            .flat_map(|b| b.from_slot..=b.to_slot)
            .collect();
        slots.sort_unstable();
        slots.dedup();
        slots.retain(|s| !self.exits.iter().any(|e| e.slot == *s && e.pinned));
        if slots.is_empty() {
            return false;
        }

        let members: Vec<usize> = self
            .exits
            .iter()
            .enumerate()
            .filter(|(_, e)| e.country == cc && !e.pinned)
            .map(|(i, _)| i)
            .collect();
        if members.len() < 2 {
            return false;
        }

        let key = |e: &ExitView| if e.lat_ema > 0 { e.lat_ema } else { e.latency_ms };
        // Position order = block ports ascending, then everything outside the
        // block. "Behind" means "sitting on a worse port".
        let mut by_pos: Vec<usize> = Vec::with_capacity(members.len());
        for pass in [true, false] {
            let mut side: Vec<usize> = members
                .iter()
                .copied()
                .filter(|i| (block_cc(blocks, self.exits[*i].slot) == Some(cc)) == pass)
                .collect();
            side.sort_by_key(|i| self.exits[*i].slot);
            by_pos.extend(side);
        }

        // Every pair, not just neighbours. Three ports at 1000/800/640 are
        // 20% apart step by step — an adjacent-only check calls that fine while
        // the first port is 36% slower than the third. The whole point is
        // "lowest port = lowest latency", so compare every position to every
        // later one. n is tiny (one country's ports).
        let mut clearly_inverted = false;
        'pairs: for i in 0..by_pos.len() {
            for j in (i + 1)..by_pos.len() {
                let ahead = key(&self.exits[by_pos[i]]);
                let behind = key(&self.exits[by_pos[j]]);
                if behind < ahead * (100 - SORT_MIN_GAIN_PCT) / 100
                    && ahead.saturating_sub(behind) >= SORT_MIN_GAIN_MS
                {
                    clearly_inverted = true;
                    break 'pairs;
                }
            }
        }
        if !clearly_inverted {
            return false;
        }

        let k = members.len().min(slots.len());
        let mut by_lat = members.clone();
        by_lat.sort_by_key(|i| key(&self.exits[*i]));
        let top: Vec<usize> = by_lat[..k].to_vec();

        let in_block: Vec<usize> = by_pos
            .iter()
            .copied()
            .filter(|i| block_cc(blocks, self.exits[*i].slot) == Some(cc))
            .collect();
        let wanted_outside: Vec<usize> = top.iter().copied().filter(|i| !in_block.contains(i)).collect();
        let unwanted_in_block: Vec<usize> = in_block.iter().copied().filter(|i| !top.contains(i)).collect();

        // Fastest takes the lowest port; a member pushed out of a full group
        // inherits the slot of the one that displaced it (that slot is always a
        // general one, so the swap is legal both ways).
        let mut targets: Vec<(usize, usize)> = Vec::new();
        for (i, &m) in top.iter().enumerate() {
            targets.push((m, slots[i]));
        }
        for (j, &m) in unwanted_in_block.iter().enumerate() {
            if let Some(&give) = wanted_outside.get(j) {
                targets.push((m, self.exits[give].slot));
            }
        }

        let mut moved = false;
        for (idx, target) in targets {
            if self.exits[idx].slot != target {
                self.move_exit(idx, target, port_base, now, "延迟重排");
                moved = true;
            }
        }
        moved
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
        // Highest donor slot first: it keeps the low ports (the ones a client is
        // most likely to have hardcoded) exactly where they are. A donor may sit
        // on a general slot, or on a *higher* reserved slot of the same country —
        // that second case is compaction: leaving 31001 dark while a JP exit
        // idles on 31002 is exactly the "pinned port vanished" bug.
        let donor = self
            .exits
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.country == cc && (block_cc(blocks, e.slot).is_none() || e.slot > slot)
            })
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
    fn a_group_is_reranked_when_a_later_exit_is_clearly_faster() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31003", base, max);
        let mut p = Pool::default();
        // Round 1: placement is latency-ordered, so this is already sorted.
        p.reconcile(
            &[live("1.1.1.1", "US", 300), live("2.2.2.2", "US", 400), live("3.3.3.3", "US", 500)],
            base,
            max,
            &b,
            1,
        );
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into()), (31003, "3.3.3.3".into())]
        );

        // Round 2: the slow one became fast and the fast one became slow. EMA
        // values end up ~380 / ~810 / ~820, so 31001 and 31003 are inverted by
        // far more than the threshold.
        p.reconcile(
            &[live("1.1.1.1", "US", 2000), live("2.2.2.2", "US", 1800), live("3.3.3.3", "US", 100)],
            base,
            max,
            &b,
            2,
        );
        // EMA after round 2: 3.3.3.3 ≈380, 1.1.1.1 ≈810, 2.2.2.2 ≈820.
        assert_eq!(
            ports(&p),
            vec![(31001, "3.3.3.3".into()), (31002, "1.1.1.1".into()), (31003, "2.2.2.2".into())]
        );
        assert!(p.log.iter().any(|r| r.reason.contains("延迟重排")));
    }

    #[test]
    fn a_small_inversion_is_not_worth_dropping_all_connections() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31002", base, max);
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 300), live("2.2.2.2", "US", 320)], base, max, &b, 1);
        // 320 vs 300 is 6% — noise, not a reason to restart sing-box.
        p.reconcile(&[live("1.1.1.1", "US", 330), live("2.2.2.2", "US", 300)], base, max, &b, 2);
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())]
        );
    }

    #[test]
    fn one_rerank_per_hour() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31002", base, max);
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 300), live("2.2.2.2", "US", 500)], base, max, &b, 1);
        // Clear inversion (EMA ≈1110 vs ≈380), re-rank allowed.
        p.reconcile(&[live("1.1.1.1", "US", 3000), live("2.2.2.2", "US", 100)], base, max, &b, 2);
        assert_eq!(ports(&p), vec![(31001, "2.2.2.2".into()), (31002, "1.1.1.1".into())]);
        // Invert hard again 16 minutes later: the order is clearly wrong but
        // the cooldown must refuse to restart sing-box for it.
        p.reconcile(&[live("1.1.1.1", "US", 100), live("2.2.2.2", "US", 3000)], base, max, &b, 1_000_000);
        assert!(
            ports(&p).iter().any(|(port, ip)| *port == 31001 && ip == "2.2.2.2"),
            "cooldown ignored"
        );
        // An hour later it may move again.
        p.reconcile(&[live("1.1.1.1", "US", 100), live("2.2.2.2", "US", 3000)], base, max, &b, 4_000_000);
        assert_eq!(ports(&p), vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())]);
    }

    #[test]
    fn an_ip_pinned_exit_is_never_reordered() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31002", base, max);
        let mut p = Pool::default();
        p.reconcile(&[live("1.1.1.1", "US", 300), live("2.2.2.2", "US", 900)], base, max, &b, 1);
        assert!(p.set_pinned(0, true));
        // The pinned one is now the slow one; a re-rank would love to move it.
        p.reconcile(&[live("1.1.1.1", "US", 900), live("2.2.2.2", "US", 200)], base, max, &b, 2);
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into())],
            "a pinned exit keeps its port"
        );
    }

    #[test]
    fn sorting_only_touches_country_groups() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31002", base, max);
        let mut p = Pool::default();
        // JP lives outside the block and must not be dragged into it.
        p.reconcile(&[live("2.2.2.2", "JP", 100), live("1.1.1.1", "US", 900)], base, max, &b, 1);
        p.reconcile(&[live("2.2.2.2", "JP", 100), live("1.1.1.1", "US", 950)], base, max, &b, 2);
        assert_eq!(p.exits.iter().filter(|e| e.country == "JP").count(), 1);
        assert_eq!(
            p.exits.iter().find(|e| e.country == "JP").unwrap().port,
            31003,
            "an unrelated country never gets promoted into a US port"
        );
    }

    #[test]
    fn a_far_apart_inversion_is_caught_too() {
        let base = 31001u16;
        let max = 8usize;
        let b = blocks("US=31001-31003", base, max);
        let mut p = Pool::default();
        p.reconcile(
            &[live("1.1.1.1", "US", 300), live("2.2.2.2", "US", 250), live("3.3.3.3", "US", 200)],
            base,
            max,
            &b,
            1,
        );
        // Force a spread-out inversion: 31001=1000, 31002=800, 31003=640. Each
        // adjacent step is 20%, so an adjacent-only check would call this fine,
        // while 31001 is 36% slower than 31003.
        for e in p.exits.iter_mut() {
            e.lat_ema = match e.ip.as_str() {
                "3.3.3.3" => 1000,
                "2.2.2.2" => 800,
                _ => 640,
            };
            e.latency_ms = e.lat_ema;
        }
        // Feed the same values back so the EMA update is an identity.
        p.reconcile(
            &[live("3.3.3.3", "US", 1000), live("2.2.2.2", "US", 800), live("1.1.1.1", "US", 640)],
            base,
            max,
            &b,
            2,
        );
        assert_eq!(
            ports(&p),
            vec![(31001, "1.1.1.1".into()), (31002, "2.2.2.2".into()), (31003, "3.3.3.3".into())],
            "a 36% inversion two positions apart must be re-ranked"
        );
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
        // ③ compacts JP down into 31001: a reserved low port must not sit empty
        // while a same-country exit idles on a higher reserved port.
        assert_eq!(ports(&p), vec![(31001, "2.2.2.2".into()), (31003, "1.1.1.1".into())]);
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
