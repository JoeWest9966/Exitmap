// Subscription body -> node URIs -> sing-box outbound objects.
//
// Ported from zen-gate's internal/subs/parse.go (MIT, Copyright (c) 2026
// LAGcomcom). The parsing quirks there were paid for in production, so this is
// a deliberate port rather than a fresh rewrite: the "*_auto" uTLS aliases,
// the unsafe-fingerprint refusal (#124), the ss legacy base64 shape, and the
// base64 alphabet roulette all stay as they were.

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use url::Url;

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub proto: String,
    pub outbound: Value,
    pub raw: String,
}

fn b64(t: &str) -> Option<Vec<u8>> {
    let trimmed = t.trim().trim_end_matches('=');
    if trimmed.is_empty() {
        return None;
    }
    let engines = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
    ];
    for e in engines {
        if let Ok(v) = e.decode(trimmed) {
            return Some(v);
        }
    }
    // Generators that mix the alphabets: translate the specials and retry.
    let swapped: String = trimmed
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(swapped)
        .ok()
}

fn decode_any(s: &str) -> Option<String> {
    b64(s).and_then(|v| String::from_utf8(v).ok())
}

/// Decode a subscription body: base64 blob or plain line list.
pub fn parse_body(body: &str) -> Vec<Node> {
    let mut text = body.trim().to_string();
    if !text.contains("://") {
        if let Some(dec) = decode_any(&text) {
            if dec.contains("://") {
                text = dec;
            }
        }
    }
    let mut out: Vec<Node> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(n) = parse_uri(line) {
            if seen.insert(n.id.clone()) {
                out.push(n);
            }
        }
    }
    out
}

fn node_id(raw: &str) -> String {
    use sha1::{Digest, Sha1};
    let d = Sha1::digest(raw.as_bytes());
    format!("n-{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

pub fn parse_uri(raw: &str) -> Option<Node> {
    let raw = raw.trim();
    let (scheme, _rest) = raw.split_once("://")?;
    let proto = scheme.to_ascii_lowercase();
    let (name, ob) = match proto.as_str() {
        "vmess" => parse_vmess(raw)?,
        "vless" => parse_userinfo(raw, "vless").ok()?,
        "trojan" => parse_userinfo(raw, "trojan").ok()?,
        "anytls" => parse_userinfo(raw, "anytls").ok()?,
        "ss" => parse_ss(raw)?,
        "hy2" | "hysteria2" => parse_userinfo(raw, "hy2").ok()?,
        "tuic" => parse_userinfo(raw, "tuic").ok()?,
        "socks" | "socks5" => parse_userinfo(raw, "socks").ok()?,
        _ => return None,
    };
    Some(Node {
        id: node_id(raw),
        name,
        proto,
        outbound: ob,
        raw: raw.to_string(),
    })
}

fn qmap(u: &Url) -> HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn q<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(|s| s.as_str()).unwrap_or("")
}

fn is_true(s: &str) -> bool {
    s == "1" || s.eq_ignore_ascii_case("true")
}

fn fragment_name(u: &Url, proto: &str, host: &str, port: u16) -> String {
    match u.fragment() {
        Some(f) => {
            let d = percent_decode_str(f).decode_utf8_lossy().to_string();
            if d.is_empty() {
                format!("{proto}-{host}:{port}")
            } else {
                d
            }
        }
        None => format!("{proto}-{host}:{port}"),
    }
}

fn parse_userinfo(raw: &str, proto: &str) -> Result<(String, Value), String> {
    let u = Url::parse(raw).map_err(|e| format!("URI 解析失败: {e}"))?;
    let host = u.host_str().unwrap_or("").to_string();
    let port = u.port().unwrap_or(0);
    if host.is_empty() || port == 0 {
        return Err("缺少 host/port".into());
    }
    let qm = qmap(&u);
    let user = percent_decode_str(u.username()).decode_utf8_lossy().to_string();
    let pass = u
        .password()
        .map(|p| percent_decode_str(p).decode_utf8_lossy().to_string());

    let mut ob = Map::new();
    ob.insert("tag".into(), json!(""));
    ob.insert("server".into(), json!(host));
    ob.insert("server_port".into(), json!(port));

    match proto {
        "vless" => {
            ob.insert("type".into(), json!("vless"));
            ob.insert("uuid".into(), json!(user));
            let flow = q(&qm, "flow");
            if !flow.is_empty() {
                ob.insert("flow".into(), json!(flow));
            }
            ob.insert("tls".into(), tls_block(&qm, false));
            attach_transport(&mut ob, &qm);
        }
        "trojan" => {
            ob.insert("type".into(), json!("trojan"));
            ob.insert("password".into(), json!(pass.unwrap_or(user)));
            ob.insert("tls".into(), tls_block(&qm, true));
            attach_transport(&mut ob, &qm);
        }
        "anytls" => {
            ob.insert("type".into(), json!("anytls"));
            ob.insert("password".into(), json!(pass.unwrap_or(user)));
            ob.insert("tls".into(), tls_block(&qm, true));
        }
        "hy2" => {
            ob.insert("type".into(), json!("hysteria2"));
            ob.insert("password".into(), json!(pass.unwrap_or(user)));
            ob.insert("tls".into(), tls_block(&qm, true));
            let obfs = q(&qm, "obfs");
            if !obfs.is_empty() {
                ob.insert(
                    "obfs".into(),
                    json!({"type": obfs, "password": q(&qm, "obfs-password")}),
                );
            }
        }
        "tuic" => {
            ob.insert("type".into(), json!("tuic"));
            ob.insert("uuid".into(), json!(user));
            ob.insert("password".into(), json!(pass.unwrap_or_default()));
            let cc = q(&qm, "congestion_control");
            if !cc.is_empty() {
                ob.insert("congestion_control".into(), json!(cc));
            }
            let mut tls = tls_block(&qm, true);
            let alpn = q(&qm, "alpn");
            if !alpn.is_empty() {
                tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
            }
            ob.insert("tls".into(), tls);
        }
        "socks" => {
            ob.insert("type".into(), json!("socks"));
            ob.insert("version".into(), json!("5"));
            if !user.is_empty() {
                ob.insert("username".into(), json!(user));
                if let Some(p) = pass {
                    ob.insert("password".into(), json!(p));
                }
            }
        }
        _ => return Err("未知协议".into()),
    }
    let name = fragment_name(&u, proto, &host, port);
    Ok((name, Value::Object(ob)))
}

fn utls_fingerprint(fp: &str) -> Option<&'static str> {
    let v = fp.trim().to_ascii_lowercase();
    let known = match v.as_str() {
        "chrome" | "chrome_auto" => "chrome",
        "firefox" | "firefox_auto" => "firefox",
        "edge" | "edge_auto" => "edge",
        "safari" | "safari_auto" => "safari",
        "360" | "360_auto" => "360",
        "qq" | "qq_auto" => "qq",
        "ios" | "ios_auto" => "ios",
        "android" | "android_auto" => "android",
        "random" | "randomized" => "random",
        _ => return None,
    };
    Some(known)
}

fn tls_block(qm: &HashMap<String, String>, default_tls: bool) -> Value {
    let security = q(qm, "security").to_ascii_lowercase();
    if security == "none" {
        return json!({"enabled": false});
    }
    if !default_tls && security.is_empty() {
        return json!({"enabled": false});
    }
    let mut t = Map::new();
    t.insert("enabled".into(), json!(true));
    let sni = q(qm, "sni");
    if !sni.is_empty() {
        t.insert("server_name".into(), json!(sni));
    }
    let mut insecure = q(qm, "allowInsecure").to_string();
    if insecure.is_empty() {
        insecure = q(qm, "insecure").to_string();
    }
    if is_true(&insecure) {
        t.insert("insecure".into(), json!(true));
    }
    let alpn = q(qm, "alpn");
    if !alpn.is_empty() {
        t.insert("alpn".into(), json!(alpn.split(',').collect::<Vec<_>>()));
    }
    let fp = q(qm, "fp");
    if !fp.is_empty() {
        if let Some(known) = utls_fingerprint(fp) {
            t.insert("utls".into(), json!({"enabled": true, "fingerprint": known}));
        }
    }
    if security == "reality" {
        if !t.contains_key("utls") {
            t.insert("utls".into(), json!({"enabled": true, "fingerprint": "chrome"}));
        }
        t.insert(
            "reality".into(),
            json!({
                "enabled": true,
                "public_key": q(qm, "pbk"),
                "short_id": q(qm, "sid"),
            }),
        );
    }
    Value::Object(t)
}

fn attach_transport(ob: &mut Map<String, Value>, qm: &HashMap<String, String>) {
    match q(qm, "type").to_ascii_lowercase().as_str() {
        "ws" => {
            let mut tr = Map::new();
            tr.insert("type".into(), json!("ws"));
            let p = q(qm, "path");
            if !p.is_empty() {
                tr.insert("path".into(), json!(p));
            }
            let h = q(qm, "host");
            if !h.is_empty() {
                tr.insert("headers".into(), json!({"Host": h}));
            }
            ob.insert("transport".into(), Value::Object(tr));
        }
        "grpc" => {
            let mut tr = Map::new();
            tr.insert("type".into(), json!("grpc"));
            let sn = q(qm, "serviceName");
            if !sn.is_empty() {
                tr.insert("service_name".into(), json!(sn));
            }
            ob.insert("transport".into(), Value::Object(tr));
        }
        "http" => {
            if q(qm, "headerType") == "http" {
                let mut tr = Map::new();
                tr.insert("type".into(), json!("http"));
                let h = q(qm, "host");
                if !h.is_empty() {
                    tr.insert("host".into(), json!(h.split(',').collect::<Vec<_>>()));
                }
                let p = q(qm, "path");
                if !p.is_empty() {
                    tr.insert("path".into(), json!(p));
                }
                ob.insert("transport".into(), Value::Object(tr));
            }
        }
        _ => {}
    }
}

fn parse_vmess(raw: &str) -> Option<(String, Value)> {
    let rest = raw.split_once("://")?.1;
    let payload = decode_any(rest)?;
    let m: Map<String, Value> = serde_json::from_str(&payload).ok()?;
    let get = |keys: &[&str]| -> String {
        for k in keys {
            if let Some(v) = m.get(*k) {
                let s = match v {
                    Value::String(s) => s.trim().to_string(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => String::new(),
                };
                if !s.is_empty() && s != "0" {
                    return s;
                }
            }
        }
        String::new()
    };
    let host = get(&["add"]);
    let port: u16 = get(&["port"]).parse().ok()?;
    let uuid = get(&["id"]);
    if host.is_empty() || port == 0 || uuid.is_empty() {
        return None;
    }
    let mut ob = Map::new();
    ob.insert("tag".into(), json!(""));
    ob.insert("type".into(), json!("vmess"));
    ob.insert("server".into(), json!(host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("uuid".into(), json!(uuid));
    let aid: i64 = get(&["aid", "alterId"]).parse().unwrap_or(0);
    ob.insert("alter_id".into(), json!(aid));
    let scy = {
        let s = get(&["scy", "security"]);
        if s.is_empty() {
            "auto".to_string()
        } else {
            s
        }
    };
    ob.insert("security".into(), json!(scy));
    if get(&["tls"]).eq_ignore_ascii_case("tls") {
        let mut t = Map::new();
        t.insert("enabled".into(), json!(true));
        let mut sni = get(&["sni"]);
        if sni.is_empty() {
            sni = get(&["host"]);
        }
        if !sni.is_empty() {
            t.insert("server_name".into(), json!(sni));
        }
        let ins = get(&["allowInsecure", "insecure"]);
        if is_true(&ins) {
            t.insert("insecure".into(), json!(true));
        }
        let alpn = get(&["alpn"]);
        if !alpn.is_empty() {
            t.insert("alpn".into(), json!(alpn.split(',').collect::<Vec<_>>()));
        }
        ob.insert("tls".into(), Value::Object(t));
    }
    let mut qm: HashMap<String, String> = HashMap::new();
    let net = get(&["net"]).to_ascii_lowercase();
    qm.insert("type".into(), net.clone());
    qm.insert("path".into(), get(&["path"]));
    qm.insert("host".into(), get(&["host"]));
    qm.insert("serviceName".into(), get(&["path"]));
    if matches!(net.as_str(), "ws" | "grpc") {
        attach_transport(&mut ob, &qm);
    }
    let mut name = get(&["ps", "remark"]);
    if name.is_empty() {
        name = format!("vmess-{host}:{port}");
    }
    Some((name, Value::Object(ob)))
}

fn split_host_port(hp: &str) -> Option<(String, u16)> {
    let (h, p) = match hp.rsplit_once(':') {
        Some(x) => x,
        None => return None,
    };
    let port: u16 = p.parse().ok()?;
    let h = h.trim_start_matches('[').trim_end_matches(']').to_string();
    if h.is_empty() || port == 0 {
        return None;
    }
    Some((h, port))
}

fn split_user_pass(s: &str) -> Option<(String, String)> {
    let (m, p) = s.split_once(':')?;
    if m.is_empty() || p.is_empty() {
        return None;
    }
    Some((m.to_string(), p.to_string()))
}

fn parse_ss(raw: &str) -> Option<(String, Value)> {
    let mut body = raw.strip_prefix("ss://")?.to_string();
    let mut frag = String::new();
    if let Some(i) = body.find('#') {
        frag = percent_decode_str(&body[i + 1..])
            .decode_utf8_lossy()
            .to_string();
        body.truncate(i);
    }
    if !body.contains('@') {
        body = decode_any(&body)?;
    }
    let (userinfo, hostport) = body.split_once('@')?;
    let (method, password) = match split_user_pass(userinfo) {
        Some(mp) => mp,
        None => {
            let dec = decode_any(userinfo)?;
            split_user_pass(&dec)?
        }
    };
    let (host, port) = split_host_port(hostport)?;
    let ob = json!({
        "tag": "",
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    });
    let name = if frag.is_empty() {
        format!("ss-{host}:{port}")
    } else {
        frag
    };
    Some((name, ob))
}

/// Fetch one subscription with the UA the vendor answers in a parseable shape.
pub async fn fetch(client: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    let resp = client
        .get(url)
        .header("user-agent", "v2rayN/6.31")
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.text().await?)
}
