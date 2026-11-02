//! Public v1 API: API keys, rate limiting, and the *stable* response shapes.
//!
//! Everything in here is deliberately free of `App`/axum types so it can be
//! unit-tested without spinning a server. The handlers in `main.rs` only map
//! `ExitView` onto these DTOs — which is the whole point: the panel can be
//! refactored freely while `/api/v1/*` stays put.
//!
//! Compatibility promise (v1): fields are only ever *added*. A client must
//! ignore unknown fields. Removing or renaming one is a `/api/v2`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const API_VERSION: &str = "v1";
pub const DEFAULT_RATE_PER_MIN: u32 = 120;

// ───────────────────────────── keys ─────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    /// First characters of the plaintext, so a human can tell keys apart in a
    /// list without ever being able to reproduce one.
    pub prefix: String,
    /// sha256 of the plaintext. The plaintext itself is never stored.
    pub hash: String,
    pub created_ms: i64,
    #[serde(default)]
    pub last_used_ms: i64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyStore {
    pub keys: Vec<ApiKey>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// `/dev/urandom` when it exists (always, on any box that can run this).
fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut v = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut v).is_ok() {
            return v;
        }
    }
    // Last resort: never leave a key of all zeros behind.
    let mut s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for b in v.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
    v
}

/// Length-independent comparison, so a wrong key cannot be found byte by byte.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl KeyStore {
    /// Returns the plaintext (shown once, never again) plus the stored record.
    pub fn create(&mut self, name: &str, now: i64) -> (String, ApiKey) {
        let plain = format!("exm_{}", hex(&random_bytes(24)));
        let name = name.trim();
        let k = ApiKey {
            id: format!("k-{}", hex(&random_bytes(4))),
            name: if name.is_empty() { "未命名".into() } else { name.into() },
            prefix: plain.chars().take(12).collect(),
            hash: sha256_hex(&plain),
            created_ms: now,
            last_used_ms: 0,
            hits: 0,
            revoked: false,
        };
        self.keys.push(k.clone());
        (plain, k)
    }

    /// `Some(key id)` when the token is live; bumps usage counters as a side
    /// effect. Revoked or unknown tokens look identical from the outside.
    pub fn verify(&mut self, token: &str, now: i64) -> Option<String> {
        if !token.starts_with("exm_") {
            return None;
        }
        let hash = sha256_hex(token);
        let k = self
            .keys
            .iter_mut()
            .find(|k| !k.revoked && ct_eq(&k.hash, &hash))?;
        k.hits += 1;
        k.last_used_ms = now;
        Some(k.id.clone())
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        match self.keys.iter_mut().find(|k| k.id == id) {
            Some(k) => {
                k.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Public view: hashes never leave the process.
    pub fn list(&self) -> Value {
        Value::Array(
            self.keys
                .iter()
                .map(|k| {
                    json!({
                        "id": k.id,
                        "name": k.name,
                        "prefix": k.prefix,
                        "createdMs": k.created_ms,
                        "lastUsedMs": k.last_used_ms,
                        "hits": k.hits,
                        "revoked": k.revoked,
                    })
                })
                .collect(),
        )
    }
}

// ─────────────────────────── rate limit ───────────────────────────

#[derive(Default)]
pub struct Limiter {
    /// key id -> (window start ms, count in that window)
    hits: HashMap<String, (i64, u32)>,
}

impl Limiter {
    /// Fixed one-minute window per key. Returns remaining quota, or how many
    /// seconds to wait.
    pub fn check(&mut self, key_id: &str, limit: u32, now: i64) -> Result<u32, u64> {
        if limit == 0 {
            return Ok(0); // 0 = unlimited
        }
        let win = now - now.rem_euclid(60_000);
        let e = self.hits.entry(key_id.to_string()).or_insert((win, 0));
        if e.0 != win {
            *e = (win, 0);
        }
        if e.1 >= limit {
            return Err(((win + 60_000 - now) as u64 / 1000).max(1));
        }
        e.1 += 1;
        Ok(limit - e.1)
    }

    /// Keep the map from growing with dead keys.
    pub fn gc(&mut self, now: i64) {
        self.hits.retain(|_, (w, _)| now - *w < 300_000);
    }
}

// ─────────────────────────── response shapes ───────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NodeDto {
    pub name: String,
    pub proto: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProxiesDto {
    pub socks5: String,
    pub http: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExitDto {
    pub port: u16,
    pub ip: String,
    pub country: String,
    pub latency_ms: u64,
    pub alive: bool,
    pub pinned: bool,
    pub rebinds: u32,
    /// When this IP took the port (ms epoch). Reset on every rebind.
    pub up_since_ms: i64,
    pub last_verified_ms: i64,
    pub node: NodeDto,
    pub proxies: ProxiesDto,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExitsResponse {
    pub api_version: String,
    pub generated_at: i64,
    pub count: usize,
    pub exits: Vec<ExitDto>,
}

// ─────────────────────────── the spec ───────────────────────────

/// Field dictionary, used to build the OpenAPI property list *and* asserted
/// against a real serialized response in the tests below. One source, so the
/// docs cannot drift from the wire.
pub const EXIT_FIELDS: &[(&str, &str)] = &[
    ("port", "本机端口号。填进客户端就是「从 ip 那个出口出去」。"),
    ("ip", "这个端口当前的出口 IP（探针实测，不是节点域名）。"),
    ("country", "出口 IP 的两位国家码，如 US / DE / JP。"),
    ("latencyMs", "最近一次探活的往返毫秒数。"),
    ("alive", "端口当前是否开着。false = IP 已失效且未钉住，端口已关闭。"),
    ("pinned", "是否被钉住。钉住后 IP 死了端口就关，绝不悄悄换成别的 IP。"),
    ("rebinds", "这个槽位历史换绑次数。"),
    ("upSinceMs", "当前 IP 占住这个槽位的时刻（毫秒时间戳）。每换绑一次重置。"),
    ("lastVerifiedMs", "最近一次探活确认这个出口的时刻（毫秒时间戳）。"),
    ("node.name", "承载节点名（订阅里怎么写的就怎么给）。"),
    ("node.proto", "承载节点协议，如 hysteria2 / vless / trojan。"),
    ("proxies.socks5", "可直接用的 socks5 地址。"),
    ("proxies.http", "可直接用的 http 代理地址（同一个端口）。"),
];

fn field_schema(desc: &str, ty: &str) -> Value {
    json!({ "description": desc, "type": ty })
}

pub fn openapi() -> Value {
    let props = |names: &[(&str, &str)], types: &[&str]| -> Value {
        let mut m = serde_json::Map::new();
        for ((n, d), t) in names.iter().zip(types.iter()) {
            let key = n.rsplit('.').next().unwrap_or(n);
            m.insert(key.to_string(), field_schema(d, t));
        }
        Value::Object(m)
    };
    let exit_props = {
        let mut m = serde_json::Map::new();
        for (name, desc) in EXIT_FIELDS.iter().copied() {
            let (head, tail): (&str, Option<&str>) = match name.split_once('.') {
                Some((h, t)) => (h, Some(t)),
                None => (name, None),
            };
            let ty = match head {
                "port" => "integer",
                "latencyMs" | "rebinds" => "integer",
                "upSinceMs" | "lastVerifiedMs" => "integer",
                "alive" | "pinned" => "boolean",
                "node" => "object",
                "proxies" => "object",
                _ => "string",
            };
            match tail {
                None => {
                    m.insert(head.to_string(), field_schema(desc, ty));
                }
                Some(t) => {
                    let entry = m
                        .entry(head.to_string())
                        .or_insert_with(|| json!({"type":"object","properties":{}}));
                    entry["properties"][t] = field_schema(desc, "string");
                }
            }
        }
        Value::Object(m)
    };
    let _ = props; // keep helper around for future schemas
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Exitmap API",
            "version": API_VERSION,
            "description": "出口 IP ⇄ 本机固定端口。每个 {port} 就是一个固定出口。"
        },
        "servers": [{ "url": "/" }],
        "components": {
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer",
                            "description": "Authorization: Bearer exm_…  密钥在面板「API」页创建。" }
            },
            "schemas": {
                "Exit": { "type": "object", "properties": exit_props },
                "ExitsResponse": {
                    "type": "object",
                    "properties": {
                        "apiVersion": { "type": "string", "enum": [API_VERSION] },
                        "generatedAt": { "type": "integer", "description": "响应生成时刻（毫秒时间戳）。" },
                        "count": { "type": "integer", "description": "exits 数组长度。" },
                        "exits": { "type": "array", "items": { "$ref": "#/components/schemas/Exit" } }
                    }
                }
            }
        },
        "security": [{ "bearer": [] }],
        "paths": {
            "/api/v1/exits": {
                "get": {
                    "summary": "出口列表",
                    "description": "按端口排序返回全部出口。可过滤、可排序、可限量。",
                    "parameters": [
                        { "name": "country", "in": "query", "schema": { "type": "string" },
                          "description": "两位国家码过滤，可重复/逗号分隔，如 US,JP。" },
                        { "name": "alive", "in": "query", "schema": { "type": "boolean" },
                          "description": "true 只要活着的，false 只要关掉的，不填全都给。" },
                        { "name": "pinned", "in": "query", "schema": { "type": "boolean" },
                          "description": "同上，按是否钉住过滤。" },
                        { "name": "sort", "in": "query", "schema": { "type": "string", "enum": ["port", "latency", "ip", "country"] },
                          "description": "排序字段，默认 port。-latency 表示反向。" },
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "maximum": 512 },
                          "description": "最多返回几条。" }
                    ],
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ExitsResponse" } } } },
                        "401": { "description": "缺少或无效的密钥" },
                        "429": { "description": "超出限流额度，看 Retry-After" }
                    }
                }
            },
            "/api/v1/exits/{port}": {
                "get": {
                    "summary": "单个出口",
                    "parameters": [{ "name": "port", "in": "path", "required": true, "schema": { "type": "integer" } }],
                    "responses": {
                        "200": { "description": "OK", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Exit" } } } },
                        "404": { "description": "没有这个端口" }
                    }
                }
            },
            "/api/v1/meta": {
                "get": {
                    "summary": "服务状态",
                    "description": "给客户端做健康检查和自检用。不含任何出口信息。",
                    "responses": { "200": { "description": "OK" } }
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "summary": "本文件",
                    "description": "唯一不需要密钥的端点：不泄露任何运行期信息。",
                    "security": [],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    })
}

/// Query knobs for `/api/v1/exits`.
#[derive(Debug, Default)]
pub struct ExitQuery {
    pub countries: Vec<String>,
    pub alive: Option<bool>,
    pub pinned: Option<bool>,
    pub sort: String,
    pub desc: bool,
    pub limit: Option<usize>,
}

impl ExitQuery {
    pub fn parse(pairs: &[(String, String)]) -> Self {
        let mut q = ExitQuery::default();
        for (k, v) in pairs {
            match k.as_str() {
                "country" => {
                    for c in v.split(',') {
                        let c = c.trim().to_uppercase();
                        if !c.is_empty() {
                            q.countries.push(c);
                        }
                    }
                }
                "alive" => q.alive = parse_bool(v),
                "pinned" => q.pinned = parse_bool(v),
                "sort" => {
                    let (field, desc) = match v.strip_prefix('-') {
                        Some(f) => (f, true),
                        None => (v.as_str(), false),
                    };
                    q.sort = field.to_lowercase();
                    q.desc = desc;
                }
                "limit" => q.limit = v.parse::<usize>().ok().filter(|n| *n <= 512),
                _ => {}
            }
        }
        q
    }

    pub fn keeps(&self, e: &ExitDto) -> bool {
        if !self.countries.is_empty() && !self.countries.iter().any(|c| *c == e.country) {
            return false;
        }
        if let Some(a) = self.alive {
            if a != e.alive {
                return false;
            }
        }
        if let Some(p) = self.pinned {
            if p != e.pinned {
                return false;
            }
        }
        true
    }

    pub fn sort(&self, rows: &mut [ExitDto]) {
        match self.sort.as_str() {
            "latency" => rows.sort_by_key(|e| e.latency_ms),
            "ip" => rows.sort_by(|a, b| a.ip.cmp(&b.ip)),
            "country" => rows.sort_by(|a, b| a.country.cmp(&b.country)),
            _ => rows.sort_by_key(|e| e.port),
        }
        if self.desc {
            rows.reverse();
        }
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

// ─────────────────────────── tests ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExitsResponse {
        ExitsResponse {
            api_version: API_VERSION.into(),
            generated_at: 1_793_600_000_000,
            count: 1,
            exits: vec![ExitDto {
                port: 31001,
                ip: "203.0.113.7".into(),
                country: "US".into(),
                latency_ms: 480,
                alive: true,
                pinned: false,
                rebinds: 2,
                up_since_ms: 1_793_500_000_000,
                last_verified_ms: 1_793_600_000_000,
                node: NodeDto {
                    name: "美国1".into(),
                    proto: "hysteria2".into(),
                },
                proxies: ProxiesDto {
                    socks5: "socks5://127.0.0.1:31001".into(),
                    http: "http://127.0.0.1:31001".into(),
                },
            }],
        }
    }

    /// The docs page and the OpenAPI spec are generated from `EXIT_FIELDS`; if a
    /// field is renamed in the DTO without touching the docs, this fails.
    #[test]
    fn documented_fields_exist() {
        let v = serde_json::to_value(sample()).unwrap();
        let exit = &v["exits"][0];
        for (name, _) in EXIT_FIELDS {
            let mut cur = exit;
            for part in name.split('.') {
                cur = &cur[part];
                assert!(!cur.is_null(), "文档里有 {}，实际响应里没有", name);
            }
        }
    }

    /// And the other direction: no field sneaks onto the wire undocumented.
    #[test]
    fn wire_fields_are_documented() {
        let v = serde_json::to_value(sample()).unwrap();
        let mut known: Vec<String> = EXIT_FIELDS
            .iter()
            .map(|(n, _)| n.split('.').next().unwrap().to_string())
            .collect();
        known.sort();
        known.dedup();
        for k in v["exits"][0].as_object().unwrap().keys() {
            assert!(known.contains(k), "响应里有未记录的字段 {k}");
        }
        // nested objects too
        for parent in ["node", "proxies"] {
            for k in v["exits"][0][parent].as_object().unwrap().keys() {
                assert!(
                    EXIT_FIELDS.iter().any(|(n, _)| *n == format!("{parent}.{k}")),
                    "{parent}.{k} 没写进文档"
                );
            }
        }
        for k in ["apiVersion", "generatedAt", "count", "exits"] {
            assert!(!v[k].is_null(), "顶层缺 {k}");
        }
    }

    #[test]
    fn spec_is_valid_json_and_lists_every_field() {
        let spec = openapi();
        assert_eq!(spec["openapi"], "3.0.3");
        let props = spec["components"]["schemas"]["Exit"]["properties"].as_object().unwrap();
        for (name, _) in EXIT_FIELDS {
            let head = name.split('.').next().unwrap();
            assert!(props.contains_key(head), "spec 里缺 {head}");
        }
    }

    #[test]
    fn keys_are_hashed_and_revocable() {
        let mut ks = KeyStore::default();
        let (plain, k) = ks.create("ci", 1000);
        assert!(plain.starts_with("exm_") && plain.len() == 52);
        assert!(!serde_json::to_string(&ks.list()).unwrap().contains(&plain));
        assert_eq!(ks.verify(&plain, 2000).as_deref(), Some(k.id.as_str()));
        assert_eq!(ks.keys[0].hits, 1);
        assert_eq!(ks.verify("exm_deadbeef", 2000), None);
        assert!(ks.revoke(&k.id));
        assert_eq!(ks.verify(&plain, 3000), None, "撤销后必须失效");
    }

    #[test]
    fn rate_limit_window_resets() {
        let mut l = Limiter::default();
        assert_eq!(l.check("k", 2, 1_000), Ok(1));
        assert_eq!(l.check("k", 2, 1_500), Ok(0));
        assert_eq!(l.check("k", 2, 1_900), Err(58), "窗口 0-60000,还剩 58 秒");
        assert_eq!(l.check("k", 0, 1_900), Ok(0), "0 表示不限流");
        assert_eq!(l.check("k", 2, 60_100), Ok(1), "新窗口重新计数");
    }

    #[test]
    fn query_filters_and_sorts() {
        let q = ExitQuery::parse(&[("country".into(), "us, JP".into()), ("sort".into(), "-latency".into())]);
        assert_eq!(q.countries, vec!["US", "JP"]);
        assert!(q.desc && q.sort == "latency");
        let mut rows = sample().exits;
        assert!(q.keeps(&rows[0]));
        let q2 = ExitQuery::parse(&[("country".into(), "DE".into())]);
        assert!(!q2.keeps(&rows[0]));
        let q3 = ExitQuery::parse(&[("alive".into(), "false".into())]);
        assert!(!q3.keeps(&rows[0]));
        q.sort(&mut rows);
        assert_eq!(rows[0].port, 31001);
    }
}
