//! MITM HTTPS engine for credential injection.
//!
//! When a CONNECT request targets a host with a credential rule, the proxy
//! terminates TLS locally (presenting a dynamically generated certificate
//! signed by a per-session CA), decrypts the HTTP request, injects the
//! credential header, re-encrypts, and forwards to the real upstream.
//!
//! The sandbox trusts the per-session CA via `SSL_CERT_FILE`.

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

use crate::audit::{Audit, AuditRecord};

/// Per-session Certificate Authority.  Generates host certificates on the fly,
/// all signed by the same CA key pair.
pub struct MitmCa {
    /// CA certificate in DER (for rustls ServerConfig).
    ca_cert_der: Vec<u8>,
    /// CA certificate in PEM (for `SSL_CERT_FILE` delivery to sandbox).
    ca_cert_pem: String,
}

impl MitmCa {
    /// Generate a fresh CA for this proxy session.
    pub fn generate() -> anyhow::Result<Self> {
        let ca_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec!["agentbox-proxy-ca".to_string()])?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = params.self_signed(&ca_key)?;

        let ca_cert_der = ca_cert.der().to_vec();
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
        })
    }

    /// CA certificate in PEM format — write this to `SSL_CERT_FILE` in the
    /// sandbox so MITM certificates are trusted.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// CA certificate in DER format.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// Build a [`rustls::ServerConfig`] that presents a valid certificate for
    /// `hostname`, signed by this CA.
    fn server_config_for(&self, hostname: &str) -> anyhow::Result<Arc<ServerConfig>> {
        let mut params = CertificateParams::new(vec![hostname.to_string()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);

        let host_key = KeyPair::generate()?;
        let host_cert = params.self_signed(&host_key)?;

        let host_cert_der = rustls::pki_types::CertificateDer::from(host_cert.der().to_vec());
        let host_key_der = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(host_key.serialize_der()),
        );

        let mut roots = rustls::RootCertStore::empty();
        let ca_cert = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        roots.add(ca_cert)?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![host_cert_der], host_key_der)?;

        Ok(Arc::new(server_config))
    }

    /// Build a [`rustls::ClientConfig`] that trusts this CA.
    fn client_config(&self) -> anyhow::Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        let ca_cert = rustls::pki_types::CertificateDer::from(self.ca_cert_der.clone());
        roots.add(ca_cert)?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Arc::new(config))
    }
}

/// Mitm a single CONNECT request: accept TLS from the agent using a fake
/// host cert, read the decrypted HTTP request, inject credentials, and
/// forward to the real upstream over TLS.
pub async fn mitm_connect(
    agent_stream: TcpStream,
    upstream_addr: SocketAddr,
    hostname: &str,
    ca: &MitmCa,
    cred_header: &str,
    cred_value: &str,
    audit: &Audit,
) -> anyhow::Result<()> {
    // ---- 1. TLS handshake with agent (present fake host cert) -----------
    let server_config = ca.server_config_for(hostname)?;
    let acceptor = TlsAcceptor::from(server_config);
    let mut agent_tls = acceptor.accept(agent_stream).await?;

    // ---- 2. Connect to real upstream with TLS ----------------------------
    let upstream_stream = TcpStream::connect(upstream_addr).await?;
    let connector = TlsConnector::from(ca.client_config()?);
    let domain = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow::anyhow!("invalid hostname `{hostname}`: {e}"))?;
    let mut upstream_tls = connector.connect(domain, upstream_stream).await?;

    // ---- 3. Read decrypted HTTP request from agent -----------------------
    let mut request_buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            agent_tls.read(&mut temp),
        )
        .await??;
        if n == 0 {
            anyhow::bail!("agent closed connection before sending complete request");
        }
        request_buf.extend_from_slice(&temp[..n]);
        if request_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if request_buf.len() > 64 * 1024 {
            anyhow::bail!("request headers too large (>64KB)");
        }
    }

    // ---- 4. Inject credential header ------------------------------------
    let modified = inject_header(&request_buf, cred_header, cred_value);

    // ---- 5. Forward modified request to upstream -------------------------
    upstream_tls.write_all(&modified).await?;
    upstream_tls.flush().await?;

    audit.record(AuditRecord {
        event: "allow",
        host: hostname.to_string(),
        port: upstream_addr.port(),
        reason: "mitm-cred-inject".into(),
        cred_injected: true,
    });

    // ---- 6. Bidirectional relay -----------------------------------------
    tokio::io::copy_bidirectional(&mut agent_tls, &mut upstream_tls).await?;

    Ok(())
}

/// Find the position of `\r\n\r\n` in `buf`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Inject (or replace) a header in an HTTP request head.
fn inject_header(request: &[u8], header_name: &str, header_value: &str) -> Vec<u8> {
    let header_name_lower = header_name.to_ascii_lowercase();
    let header_line = format!("{}: {}\r\n", header_name, header_value);

    let header_end = match find_header_end(request) {
        Some(pos) => pos,
        None => return request.to_vec(),
    };

    let head = &request[..header_end];
    let tail = &request[header_end..];

    let mut result = Vec::with_capacity(request.len() + 64);
    let mut replaced = false;

    for line in head.split(|&b| b == b'\n') {
        let line_trimmed = line.trim_ascii_end();
        if line_trimmed.is_empty() {
            continue;
        }
        if let Some(colon_pos) = line_trimmed.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line_trimmed[..colon_pos]).to_ascii_lowercase();
            if name == header_name_lower {
                result.extend_from_slice(header_line.as_bytes());
                replaced = true;
                continue;
            }
        }
        result.extend_from_slice(line);
        if !line.ends_with(b"\r\n") {
            result.extend_from_slice(b"\r\n");
        }
    }

    if !replaced {
        result.extend_from_slice(header_line.as_bytes());
    }

    result.extend_from_slice(tail);
    result
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_header_adds_new() {
        let req = b"GET /test HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let out = inject_header(req, "authorization", "Bearer sk-123");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("authorization: Bearer sk-123\r\n"));
        assert!(s.contains("Host: api.example.com\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn inject_header_replaces_existing() {
        let req =
            b"GET /test HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer old\r\n\r\n";
        let out = inject_header(req, "authorization", "Bearer new");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("old"));
        assert!(s.contains("authorization: Bearer new\r\n"));
    }

    #[test]
    fn inject_header_case_insensitive() {
        let req =
            b"GET /test HTTP/1.1\r\nHost: api.example.com\r\nAUTHORIZATION: Bearer old\r\n\r\n";
        let out = inject_header(req, "authorization", "Bearer new");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("old"));
        assert!(s.contains("authorization: Bearer new\r\n"));
    }

    #[test]
    fn find_header_end_works() {
        // "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"
        // Bytes: G(0) E(1) T(2) ' '(3) /(4) ' '(5) H(6) T(7) T(8) P(9)
        //        /(10) 1(11) .(12) 1(13) CR(14) LF(15)
        //        H(16) o(17) s(18) t(19) :(20) ' '(21) x(22)
        //        CR(23) LF(24) CR(25) LF(26)
        //        b(27) o(28) d(29) y(30)
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(req), Some(23));
    }

    #[test]
    fn inject_header_preserves_body() {
        let req = b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n{\"key\":\"value\"}";
        let out = inject_header(req, "authorization", "Bearer tok");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("{\"key\":\"value\"}"));
        assert!(s.contains("authorization: Bearer tok\r\n"));
    }

    #[test]
    fn mitm_ca_generates_valid_cert() {
        let ca = MitmCa::generate().unwrap();
        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        // Verify we can build server config for a hostname.
        let _config = ca.server_config_for("api.example.com").unwrap();
    }
}
