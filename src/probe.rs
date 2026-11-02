// Egress-IP probe.
//
// A probe has to leave through one specific node, so it gets its own socks5
// handshake instead of a reqwest client: reqwest expresses a proxy per client,
// which would mean one client (and one TLS stack) per node, per round. The
// probe target is plain HTTP on purpose — the answer we want is a bare IP, and
// paying for a TLS handshake 228 times to read five characters is silly.

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Fetch `probe_url` through 127.0.0.1:`socks_port` and return the IP text.
pub async fn egress_ip(socks_port: u16, probe_url: &str, timeout: Duration) -> Option<(String, u64)> {
    let u = url::Url::parse(probe_url).ok()?;
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default()?;
    let path = if u.path().is_empty() { "/" } else { u.path() };

    let started = Instant::now();
    let work = async {
        let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.ok()?;
        // greeting: no auth
        s.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.ok()?;
        if g[0] != 0x05 || g[1] != 0x00 {
            return None;
        }
        // CONNECT with a domain name: the node resolves, same as the real traffic
        let mut req = vec![0x05, 0x01, 0x00, 0x03];
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return None;
        }
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.ok()?;
        if head[1] != 0x00 {
            return None; // node refused / unreachable
        }
        match head[3] {
            0x01 => {
                let mut skip = [0u8; 6];
                s.read_exact(&mut skip).await.ok()?;
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.ok()?;
                let mut skip = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut skip).await.ok()?;
            }
            0x04 => {
                let mut skip = [0u8; 18];
                s.read_exact(&mut skip).await.ok()?;
            }
            _ => return None,
        }
        let hosthdr = if port == 80 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let get = format!(
            "GET {path} HTTP/1.1\r\nHost: {hosthdr}\r\nUser-Agent: exitmap/0.1\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
        );
        s.write_all(get.as_bytes()).await.ok()?;
        let mut buf = Vec::with_capacity(2048);
        let _ = s.read_to_end(&mut buf).await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let body = match text.split_once("\r\n\r\n") {
            Some((_, b)) => b.to_string(),
            None => text,
        };
        extract_ip(&body)
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(Some(ip)) => Some((ip, started.elapsed().as_millis() as u64)),
        _ => None,
    }
}

/// The probe endpoint answers with a bare IP, sometimes as JSON, sometimes as
/// an HTML page. Pull the first public-looking IPv4 out of whatever came back.
fn extract_ip(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let cand = &s[start..i];
            let parts: Vec<&str> = cand.split('.').collect();
            if parts.len() == 4
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
            {
                let first: u16 = parts[0].parse().unwrap_or(0);
                if !(first == 0 || first == 10 || first == 127 || first >= 224) {
                    return Some(cand.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    None
}
