//! The proxy server: HTTP CONNECT tunneling + plain-HTTP forwarding with
//! enforced host filtering.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{copy_bidirectional, AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::audit::{Audit, AuditRecord};
use crate::rules::HostFilter;

const MAX_HEAD_BYTES: usize = 32 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TTL: Duration = Duration::from_secs(60);

/// Proxy configuration.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Bind address; use `127.0.0.1` (default via `Default`) — the sandbox is
    /// only ever granted reachability to loopback.
    pub bind_ip: IpAddr,
    /// 0 = pick an ephemeral port (recommended: per-session).
    pub port: u16,
    /// Required Proxy-Authorization token. `None` disables auth (Linux/bwrap
    /// mode, where MXC forbids credentials in the proxy URL because they would
    /// leak through /proc cmdline).
    pub token: Option<String>,
    pub filter: HostFilter,
    pub audit_path: Option<std::path::PathBuf>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([127, 0, 0, 1]),
            port: 0,
            token: None,
            filter: HostFilter::default(),
            audit_path: None,
        }
    }
}

/// A running proxy. Drop or call [`BoundProxy::shutdown`] to stop it.
pub struct BoundProxy {
    pub addr: SocketAddr,
    pub port: u16,
    shutdown_tx: watch::Sender<bool>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl BoundProxy {
    /// Stop accepting and abort all live tunnels/connections.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.abort_all();
        }
    }
}

impl Drop for BoundProxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Generate a random per-session token (`Proxy-Authorization` bearer/basic
/// password).
pub fn generate_token() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Bind and serve until shutdown.
pub async fn spawn(config: ProxyConfig) -> anyhow::Result<BoundProxy> {
    let listener = TcpListener::bind(SocketAddr::new(config.bind_ip, config.port)).await?;
    let addr = listener.local_addr()?;
    let audit = match &config.audit_path {
        Some(p) => Audit::file(p)?,
        None => Audit::disabled(),
    };
    let config = Arc::new(config);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    shutdown_rx.borrow_and_update(); // mark initial value seen
    let tasks = Arc::new(Mutex::new(JoinSet::<()>::new()));

    let dns_cache: Arc<Mutex<HashMap<String, (IpAddr, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let tls_tasks = tasks.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { break };
                    stream.set_nodelay(true).ok();
                    let config = config.clone();
                    let audit = audit.clone();
                    let dns = dns_cache.clone();
                    if let Ok(mut guard) = tls_tasks.lock() {
                        guard.spawn(handle_connection(stream, peer, config, audit, dns));
                    }
                }
            }
        }
    });

    Ok(BoundProxy { addr, port: addr.port(), shutdown_tx, tasks })
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    audit: Audit,
    dns: Arc<Mutex<HashMap<String, (IpAddr, Instant)>>>,
) {
    let _ = stream.set_nodelay(true);
    let mut reader = tokio::io::BufReader::new(stream);
    // Read the request head line by line until the blank line.
    let mut head = Vec::with_capacity(512);
    loop {
        let mut line = Vec::with_capacity(128);
        match tokio::time::timeout(HEAD_TIMEOUT, reader.read_until(b'\n', &mut line)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => return,
            Ok(Ok(_)) => {
                head.extend_from_slice(&line);
                if head.len() > MAX_HEAD_BYTES {
                    return;
                }
                if line == b"\r\n" || line == b"\n" {
                    break;
                }
            }
        }
    }

    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next().unwrap_or_default().trim().to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let l = line.trim_end();
        if l.is_empty() {
            continue;
        }
        if let Some(idx) = l.find(':') {
            headers.push((l[..idx].trim().to_ascii_lowercase(), l[idx + 1..].trim().to_string()));
        }
    }
    let header = |name: &str| -> Option<&str> {
        headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_string();

    if method.is_empty() || target.is_empty() {
        write_simple_response(reader.get_mut(), "400 Bad Request", "malformed request").await.ok();
        return;
    }

    // ---- Auth -----------------------------------------------------------
    if let Some(token) = &config.token {
        let ok = header("proxy-authorization")
            .map(|v| check_authorization(v, token))
            .unwrap_or(false);
        if !ok {
            audit.record(AuditRecord {
                event: "error",
                host: "-".into(),
                port: 0,
                reason: format!("auth failed from {peer}"),
            });
            write_simple_response(
                reader.get_mut(),
                "407 Proxy Authentication Required",
                "agentbox: missing or invalid proxy credentials",
            )
            .await
            .ok();
            let _ = reader.get_mut().flush().await;
            return;
        }
    }

    // ---- Authority extraction -------------------------------------------
    let authority = if method == "CONNECT" {
        target.clone()
    } else {
        // Absolute-form (http://host/path) or origin-form + Host header.
        if let Some(rest) = target.strip_prefix("http://") {
            match rest.find('/') {
                Some(idx) => rest[..idx].to_string(),
                None => rest.to_string(),
            }
        } else {
            match header("host") {
                Some(h) => h.to_string(),
                None => {
                    write_simple_response(reader.get_mut(), "400 Bad Request", "missing Host")
                        .await
                        .ok();
                    return;
                }
            }
        }
    };

    let (host_raw, port) = match crate::rules::split_authority(&authority) {
        Ok(v) => v,
        Err(e) => {
            write_simple_response(reader.get_mut(), "400 Bad Request", &e).await.ok();
            return;
        }
    };

    // ---- Policy decision -------------------------------------------------
    let decision = config.filter.decide_hp(&host_raw, port);
    if !decision.allowed {
        audit.record(AuditRecord {
            event: "deny",
            host: host_raw.clone(),
            port,
            reason: decision.reason.clone(),
        });
        write_simple_response(
            reader.get_mut(),
            "403 Forbidden",
            &format!("agentbox: destination `{host_raw}:{port}` denied by sandbox policy"),
        )
        .await
        .ok();
        return;
    }
    audit.record(AuditRecord {
        event: "allow",
        host: host_raw.clone(),
        port,
        reason: decision.reason.clone(),
    });

    // ---- Upstream connect -------------------------------------------------
    let upstream_addr = match resolve(&host_raw, port, &dns).await {
        Ok(a) => a,
        Err(e) => {
            audit.record(AuditRecord {
                event: "error",
                host: host_raw.clone(),
                port,
                reason: format!("dns: {e}"),
            });
            write_simple_response(reader.get_mut(), "502 Bad Gateway", "dns resolution failed")
                .await
                .ok();
            return;
        }
    };
    let mut upstream =
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(upstream_addr, port)))
            .await
        {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            audit.record(AuditRecord {
                event: "error",
                host: host_raw.clone(),
                port,
                reason: format!("connect: {e}"),
            });
            write_simple_response(reader.get_mut(), "502 Bad Gateway", "upstream connect failed")
                .await
                .ok();
            return;
        }
        Err(_) => {
            write_simple_response(reader.get_mut(), "504 Gateway Timeout", "upstream timeout")
                .await
                .ok();
            return;
        }
    };

    if method == "CONNECT" {
        let _ = upstream.set_nodelay(true);
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .ok();
        reader.get_mut().flush().await.ok();
        let mut client = reader.into_inner();
        let _ = copy_bidirectional(&mut client, &mut upstream).await;
    } else {
        // Plain HTTP: rewrite to origin-form and forward the head verbatim
        // minus hop-by-hop proxy headers. Remaining body bytes and the
        // response flow through the bidirectional relay.
        let path = {
            let mut p = target.clone();
            if let Some(rest) = target.strip_prefix("http://") {
                p = match rest.find('/') {
                    Some(idx) => rest[idx..].to_string(),
                    None => "/".to_string(),
                };
            }
            p
        };
        let version = {
            let v = request_line.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
            if v.starts_with("HTTP/") { v.to_string() } else { "HTTP/1.1".to_string() }
        };
        let mut out = format!("{method} {path} {version}\r\n");
        out.push_str(&format!("Host: {host_raw}\r\n"));
        for (k, v) in &headers {
            if k == "proxy-authorization"
                || k == "proxy-connection"
                || k == "host"
                || k == "connection"
                || k == "keep-alive"
            {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        let mut up = upstream;
        if up.write_all(out.as_bytes()).await.is_err() {
            return;
        }
        up.flush().await.ok();
        let mut client = reader.into_inner();
        let _ = copy_bidirectional(&mut client, &mut up).await;
    }
}

/// Constant-enough token comparison: accept `Basic` (token as user **or**
/// password — different clients fill either slot) or `Bearer <token>`.
fn check_authorization(value: &str, token: &str) -> bool {
    let value = value.trim();
    if let Some(b64) = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) {
        use base64::Engine;
        let decoded: Result<Vec<u8>, _> =
            base64::engine::general_purpose::STANDARD.decode(b64.trim());
        if let Ok(bytes) = decoded {
            if let Ok(creds) = String::from_utf8(bytes) {
                let (_, pass) = creds.split_once(':').unwrap_or((&creds, ""));
                return secure_eq(pass, token) || secure_eq(&creds, token);
            }
        }
        return false;
    }
    if let Some(bearer) = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")) {
        return secure_eq(bearer.trim(), token);
    }
    false
}

fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn write_simple_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

/// Resolve at the proxy side with a tiny TTL cache. Prefers IPv4 so slirp /
/// dual-stack oddities don't produce unreachable v6 upstreams on hosts
/// without v6 egress.
async fn resolve(
    host: &str,
    port: u16,
    cache: &Mutex<HashMap<String, (IpAddr, Instant)>>,
) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    {
        let cache = cache.lock().unwrap();
        if let Some((ip, at)) = cache.get(host) {
            if at.elapsed() < DNS_TTL {
                return Ok(*ip);
            }
        }
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    let picked = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| anyhow::anyhow!("no addresses for {host}"))?
        .ip();
    if let Ok(mut cache) = cache.lock() {
        cache.insert(host.to_string(), (picked, Instant::now()));
    }
    Ok(picked)
}
