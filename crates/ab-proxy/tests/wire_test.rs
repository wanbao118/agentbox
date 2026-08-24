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
            let n = match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await
            {
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
    let cfg = ProxyConfig { port: 0, token, filter, ..Default::default() };
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
    s.write_all(format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut head = vec![0u8; 256];
    let n = s.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"), "got: {}", String::from_utf8_lossy(&head[..n]));

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
    let (proxy_port, _proxy) =
        spawn_proxy(HostFilter::new(vec![HostRule::parse("ok.io").unwrap()], vec![]), None).await;

    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n").await.unwrap();
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
    s.write_all(b"CONNECT anything.io:443 HTTP/1.1\r\n\r\n").await.unwrap();
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
    s.write_all(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));
    up_task.abort();
}
