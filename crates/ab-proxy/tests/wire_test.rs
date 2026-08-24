//! Socket-level tests: a real upstream echo server + real proxy instance.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ab_proxy::{spawn, BoundProxy, HostFilter, HostRule, ProxyConfig};

/// Echo server that also answers a plain-HTTP request with a fixed response.
async fn spawn_upstream() -> (u16, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Keep accepting until aborted: breaking after the first connection races
    // with slow clients under parallel test load.
    let handle = tokio::spawn(async move {
        let mut seen_first_line = String::new();
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            if seen_first_line.is_empty() && n > 0 {
                let text = String::from_utf8_lossy(&buf[..n]);
                seen_first_line = text.lines().next().unwrap_or_default().to_string();
            }
            // Echo back whatever we got (tunnel payload or HTTP response path).
            let _ = sock.write_all(&buf[..n]).await;
            let _ = sock.shutdown().await;
        }
        seen_first_line
    });
    (port, handle)
}

async fn spawn_proxy(filter: HostFilter, token: Option<String>) -> (u16, BoundProxy) {
    let cfg = ProxyConfig {
        port: 0,
        token,
        filter,
        ..Default::default()
    };
    let bound = spawn(cfg).await.unwrap();
    (bound.port, bound)
}

fn basic_auth(user_pass: &str) -> String {
    use base64::Engine;
    format!(
        "Proxy-Authorization: Basic {}",
        base64::engine::general_purpose::STANDARD.encode(user_pass)
    )
}

#[tokio::test]
async fn connect_allowed_roundtrips() {
    let (up_port, up_task) = spawn_upstream().await;
    // Explicit IP rule: also covers the "allowlisted IP literal" path.
    let (proxy_port, _proxy) = spawn_proxy(
        HostFilter::new(vec![HostRule::parse("127.0.0.1").unwrap()], vec![]),
        None,
    )
    .await;

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();

    let mut head = vec![0u8; 256];
    let n = s.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
        "got: {}",
        String::from_utf8_lossy(&head[..n])
    );

    s.write_all(b"ping-agentbox").await.unwrap();
    let mut echo = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(8), s.read_exact(&mut echo))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(&echo, b"ping-agentbox");
    up_task.abort();
}

#[tokio::test]
async fn connect_denied_host_gets_403() {
    let (_up_port, up_task) = spawn_upstream().await;
    let (proxy_port, _proxy) = spawn_proxy(
        HostFilter::new(vec![HostRule::parse("ok.io").unwrap()], vec![]),
        None,
    )
    .await;

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"),
        "got: {}",
        String::from_utf8_lossy(&buf[..n])
    );
    up_task.abort();
}

#[tokio::test]
async fn auth_required_when_token_set() {
    let (_up, up_task) = spawn_upstream().await;
    let (proxy_port, _proxy) = spawn_proxy(
        HostFilter::new(vec![HostRule::parse("*").unwrap()], vec![]),
        Some("sekret".into()),
    )
    .await;

    // No credentials → 407.
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(b"CONNECT anything.io:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 407"));

    // Wrong password → 407.
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(
        format!(
            "CONNECT anything.io:443 HTTP/1.1\r\n{}\r\n\r\n",
            basic_auth("user:wrong")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 407"));

    // Correct password (in either userinfo slot) → passes auth (then denied
    // by policy since `anything.io` is allowlisted via `*`… actually allowed).
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(
        format!(
            "CONNECT anything.io:443 HTTP/1.1\r\n{}\r\n\r\n",
            basic_auth("agentbox:sekret")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    up_task.abort();
}

#[tokio::test]
async fn ip_literal_blocked_by_default() {
    let (_up, up_task) = spawn_upstream().await;
    let (proxy_port, _proxy) = spawn_proxy(HostFilter::default(), None).await;
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));
    up_task.abort();
}

// ---- Issue #4: post-resolution IP validation (SSRF / DNS rebinding) ------

/// An allowlisted *hostname* that resolves to loopback (localhost -> 127.0.0.1
/// via /etc/hosts) must be refused even though the name itself is allowlisted:
/// the tunnel would otherwise land on a host-local service.
#[tokio::test]
async fn allowlisted_hostname_resolving_to_loopback_refused() {
    let (up_port, up_task) = spawn_upstream().await;
    let (proxy_port, _proxy) = spawn_proxy(
        HostFilter::new(vec![HostRule::parse("localhost").unwrap()], vec![]),
        None,
    )
    .await;

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(
        format!("CONNECT localhost:{up_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "expected 502 for hostname resolving into loopback, got: {head}"
    );
    assert!(
        head.contains("protected"),
        "reason should mention the guard: {head}"
    );
    up_task.abort();
}

/// The explicit opt-out (`allow_private_dns`) restores the old tunneling
/// behavior — the escape hatch must actually work.
#[tokio::test]
async fn private_dns_opt_in_tunnels_again() {
    let (up_port, up_task) = spawn_upstream().await;
    let cfg = ProxyConfig {
        port: 0,
        filter: HostFilter::new(vec![HostRule::parse("localhost").unwrap()], vec![]),
        allow_private_dns: true,
        ..Default::default()
    };
    let bound = spawn(cfg).await.unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", bound.port)).await.unwrap();
    s.write_all(
        format!("CONNECT localhost:{up_port} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = vec![0u8; 256];
    let n = s.read(&mut head).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"),
        "opted-in private DNS should tunnel, got: {}",
        String::from_utf8_lossy(&head[..n])
    );
    // And the tunnel really reaches the upstream echo server.
    s.write_all(b"ping-agentbox").await.unwrap();
    let mut echo = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(8), s.read_exact(&mut echo))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(&echo, b"ping-agentbox");
    up_task.abort();
}

/// Explicit IP-literal allow rules keep working untouched (deliberate
/// configuration bypasses the guard).
#[tokio::test]
async fn explicit_ip_rule_still_bypasses_guard() {
    let (up_port, up_task) = spawn_upstream().await;
    let (proxy_port, _proxy) = spawn_proxy(
        HostFilter::new(vec![HostRule::parse("127.0.0.1").unwrap()], vec![]),
        None,
    )
    .await;

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = vec![0u8; 256];
    let n = s.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    up_task.abort();
}

// ---- Issue #5: bounded concurrency and tunnel lifetime -------------------

/// With `max_connections = 1` a second concurrent connection is closed
/// immediately instead of being served or queued.
#[tokio::test]
async fn concurrency_limit_closes_excess_connections() {
    let (_up, up_task) = spawn_upstream().await;
    let cfg = ProxyConfig {
        port: 0,
        filter: HostFilter::new(vec![HostRule::parse("*").unwrap()], vec![]),
        max_connections: 1,
        ..Default::default()
    };
    let bound = spawn(cfg).await.unwrap();

    // First connection holds the only permit (its handler starts reading the
    // head and blocks there).
    let mut first = TcpStream::connect(("127.0.0.1", bound.port)).await.unwrap();
    first
        .write_all(b"CONNECT hold.io:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Second connection must be dropped without a response.
    let mut second = TcpStream::connect(("127.0.0.1", bound.port)).await.unwrap();
    second
        .write_all(b"CONNECT other.io:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let closed = tokio::time::timeout(Duration::from_secs(3), second.read(&mut buf)).await;
    match closed {
        Ok(Ok(0)) => {} // clean EOF: connection closed
        Ok(Ok(n)) => panic!("excess connection was served ({n} bytes)"),
        Ok(Err(_)) => {} // reset also counts as a close
        Err(_) => panic!("excess connection neither served nor closed"),
    }
    up_task.abort();
}

/// `tunnel_max_duration` tears down a tunnel that stays open past the cap.
#[tokio::test]
async fn tunnel_lifetime_cap_closes_long_tunnels() {
    let (up_port, up_task) = spawn_upstream().await;
    let cfg = ProxyConfig {
        port: 0,
        filter: HostFilter::new(vec![HostRule::parse("127.0.0.1").unwrap()], vec![]),
        tunnel_max_duration: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let bound = spawn(cfg).await.unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", bound.port)).await.unwrap();
    s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = vec![0u8; 256];
    let n = s.read(&mut head).await.unwrap();
    assert!(n > 0, "expected the 200 handshake response");

    // Hold the tunnel open well past the cap; the relay must terminate it.
    let read_deadline = Duration::from_secs(5);
    let mut got_eof = false;
    let start = std::time::Instant::now();
    while start.elapsed() < read_deadline {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(read_deadline, s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                got_eof = true;
                break;
            }
            Ok(Ok(_)) => continue,
            Err(_) => break,
        }
    }
    assert!(got_eof, "tunnel was not torn down at the lifetime cap");
    up_task.abort();
}
