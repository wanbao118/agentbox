# Enterprise Credential Injection — Implementation Plan

## Problem Statement

Currently, API keys (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) are injected as **environment variables** into the sandbox. The LLM/agent can:

1. **Read** them via `echo $ANTHROPIC_API_KEY` / `process.env.ANTHROPIC_API_KEY`
2. **Exfiltrate** them through allowed API domains (embed key in request body/query)
3. **Leak** them in error messages, logs, or tool outputs

**Goal**: Credentials never enter the sandbox. The proxy injects auth transparently — for both HTTP and HTTPS.

## Design: Proxy-Side Credential Injection with MITM HTTPS

### Core Concept

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Before (current)                         After (new)                        │
│                                                                              │
│  Sandbox env:                            Sandbox env:                       │
│    ANTHROPIC_API_KEY=sk-ant-...            (no API keys)                     │
│    OPENAI_API_KEY=sk-...                   ANTHROPIC_BASE_URL=http://..      │
│    ANTHROPIC_BASE_URL=...                  ANTHROPIC_MODEL=sonnet-4          │
│    SSL_CERT_FILE=/proxy/ca.pem            HTTP_PROXY=http://proxy           │
│                                           SSL_CERT_FILE=/proxy/ca.pem       │
│  Agent can echo $KEY ✓                    Agent cannot see keys ✗            │
│                                                                              │
│  HTTP: request → proxy → upstream        HTTP: request → proxy:             │
│  (no auth injection)                       inject Authorization header       │
│                                           → upstream (with auth)             │
│                                                                              │
│  HTTPS: CONNECT → raw tunnel → upstream  HTTPS: CONNECT → proxy MITM:      │
│  (agent sends auth in encrypted tunnel,    1. Proxy responds 200             │
│   proxy cannot see or inject)              2. Proxy presents fake cert       │
│                                            3. Agent completes TLS            │
│                                            4. Proxy decrypts HTTP request    │
│                                            5. Inject Authorization header    │
│                                            6. Re-encrypt to upstream         │
└──────────────────────────────────────────────────────────────────────────────┘
```

### HTTPS MITM Flow

```
Agent                    Proxy                         Upstream
  |                        |                              |
  |-- CONNECT api.anthropic.com:443 -->|                  |
  |<-- 200 Connection Established -----|                  |
  |                        |                              |
  |  [TLS ClientHello to api.anthropic.com]               |
  |                        |                              |
  |  Proxy intercepts:                                    |
  |  - Has credential rule for *.anthropic.com            |
  |  - Generates cert for api.anthropic.com (signed by proxy CA)
  |  - Presents fake cert to agent                        |
  |<-- [TLS ServerHello + fake cert] ---|                 |
  |                        |                              |
  |  [TLS Finished]        |                              |
  |                        |                              |
  |-- POST /v1/messages --|  (decrypted by proxy)        |
  |   (no Authorization)  |                              |
  |                        |  Inject: Authorization: Bearer sk-ant-...
  |                        |                              |
  |                        |-- POST /v1/messages -------->|
  |                        |   Authorization: Bearer sk-ant-...  |
  |                        |                              |
  |                        |<-- 200 OK -------------------|
  |<-- 200 OK ------------|                              |
```

### Scope

| Category | Env Vars | Injection Point |
|----------|----------|-----------------|
| **Proxy-injected** (sensitive) | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, `XAI_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY` | Proxy intercepts HTTP/HTTPS requests, injects `Authorization` header |
| **Sandbox-passthrough** (non-sensitive) | `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`, `OPENAI_BASE_URL`, config vars | Forwarded to sandbox env as before |
| **CA certificate** | `SSL_CERT_FILE=/session/ca.pem` | Proxy CA cert for MITM HTTPS trust |

### Threat Model

- **Prevents**: LLM reading/leaking API keys via env, logs, error messages
- **Prevents**: Agent sending unauthenticated requests (proxy always injects)
- **Does NOT prevent**: Agent exfiltrating data through allowed API endpoints (inherent to API access)
- **Mitigation**: Proxy audit logs every request; `--strict` mode fails on deny

## Architecture

### 1. `ab-proxy/src/credential.rs` (new file)

```rust
use std::collections::HashMap;
use std::path::PathBuf;

/// How the proxy should inject credentials for a specific host pattern.
pub struct CredentialRule {
    /// Host pattern (same syntax as HostRule: exact, *.domain, *)
    pub host_pattern: String,
    /// Optional port restriction
    pub ports: Option<Vec<u16>>,
    /// Header name to inject (e.g., "authorization")
    pub header_name: String,
    /// Header value: "Bearer {env_value}" or literal
    pub header_value_template: String,
    /// Source of the credential value
    pub source: CredentialSource,
}

pub enum CredentialSource {
    /// Read from host environment variable at proxy startup
    Env(String),
}

/// The credential injection engine.
pub struct CredentialStore {
    rules: Vec<CredentialRule>,
    /// Resolved values: rule_index -> header_value (with env var substituted)
    resolved: Vec<String>,
}

impl CredentialStore {
    /// Create from rules, resolving all env var sources immediately.
    pub fn new(rules: Vec<CredentialRule>) -> Self { ... }

    /// Check if there's a credential rule matching this host:port.
    pub fn has_rule_for(&self, host: &str, port: u16) -> bool { ... }

    /// Find the injection (header_name, header_value) for a request.
    pub fn find_injection(&self, host: &str, port: u16) -> Option<(&str, &str)> { ... }

    /// Whether this host needs MITM (has a credential rule AND uses HTTPS).
    pub fn needs_mitm(&self, host: &str, port: u16) -> bool { ... }
}
```

### 2. `ab-proxy/src/mitm.rs` (new file) — HTTPS MITM Engine

```rust
use std::sync::Arc;
use rcgen::{Certificate, CertificateParams, KeyPair};
use rustls::ServerConfig;

/// Per-session CA that generates host certificates on the fly.
pub struct MitmCa {
    /// The CA certificate (to be distributed to sandboxes)
    ca_cert: Certificate,
    ca_cert_der: Vec<u8>,
    /// Cache: host -> TLS server config (with host-specific cert)
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmCa {
    /// Generate a new CA for this session.
    pub fn generate() -> anyhow::Result<Self> { ... }

    /// Get the CA certificate in DER format (for distribution).
    pub fn ca_cert_der(&self) -> &[u8] { ... }

    /// Get the CA certificate in PEM format (for SSL_CERT_FILE).
    pub fn ca_cert_pem(&self) -> String { ... }

    /// Get or generate a TLS config for a specific host.
    /// The cert is signed by our CA for `hostname`.
    pub fn server_config_for(&self, hostname: &str) -> Arc<ServerConfig> { ... }
}

/// MITM a single HTTPS connection: decrypt agent's request, inject
/// credentials, re-encrypt to upstream.
pub async fn mitm_connect(
    agent_stream: TcpStream,
    upstream_addr: SocketAddr,
    hostname: &str,
    ca: &MitmCa,
    credential: (&str, &str), // (header_name, header_value)
    audit: &Audit,
) -> anyhow::Result<()> { ... }
```

**MITM connect flow**:

```rust
pub async fn mitm_connect(...) {
    // 1. Complete TLS handshake with agent (using fake cert for hostname)
    let tls_config = ca.server_config_for(hostname);
    let agent_tls = TlsAcceptor::from(tls_config).accept(agent_stream).await?;

    // 2. Connect to real upstream with TLS
    let upstream_tls = connect_upstream_tls(upstream_addr, hostname).await?;

    // 3. Read decrypted HTTP request from agent
    let request = read_http_request(&mut agent_tls).await?;

    // 4. Inject credential header, strip agent-provided auth
    let modified_request = inject_credential(&request, cred_header, cred_value);

    // 5. Forward modified request to upstream
    upstream_tls.write_all(&modified_request).await?;

    // 6. Bidirectional relay (encrypted on both sides)
    tokio::io::copy_bidirectional(&mut agent_tls, &mut upstream_tls).await?;
}
```

### 3. Modify `ab-proxy/src/server.rs`

**In `handle_connection()`**, after policy decision, before upstream connect:

```rust
// Check if this request needs MITM (credential rule + HTTPS)
if let Some(cred_store) = &config.credential_store {
    if cred_store.needs_mitm(&host_raw, port) && method == "CONNECT" {
        // MITM path: intercept TLS, inject credentials
        let cred = cred_store.find_injection(&host_raw, port).unwrap();
        let ca = config.mitm_ca.as_ref().expect("MITM CA must be set");
        mitm_connect(stream, upstream_addr, &host_raw, ca, cred, &audit).await;
        return;
    }
}

// Normal CONNECT path (no credential rule → raw tunnel)
if method == "CONNECT" {
    // ... existing relay code ...
}
```

**Add fields to `ProxyConfig`**:

```rust
pub struct ProxyConfig {
    // ... existing fields ...
    pub credential_store: Option<CredentialStore>,
    pub mitm_ca: Option<MitmCa>,
}
```

### 4. Modify `ab-profiles/src/lib.rs`

```rust
pub struct ProxyCredential {
    pub host_pattern: &'static str,
    pub header: &'static str,      // "authorization"
    pub env_var: &'static str,     // "ANTHROPIC_API_KEY"
    pub value_prefix: &'static str, // "Bearer "
}

pub struct AgentProfile {
    // ... existing fields ...
    pub proxy_credentials: &'static [ProxyCredential],
}
```

**Updated profiles** (example: claude-code):

```rust
pub const CLAUDE_CODE: AgentProfile = AgentProfile {
    secrets_env: &[
        // Non-sensitive config only:
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_SMALL_FAST_MODEL",
        "API_TIMEOUT_MS",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
        "AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    ],
    proxy_credentials: &[
        ProxyCredential { host_pattern: "*.anthropic.com", header: "authorization", env_var: "ANTHROPIC_API_KEY", value_prefix: "Bearer " },
        ProxyCredential { host_pattern: "claude.ai", header: "authorization", env_var: "ANTHROPIC_API_KEY", value_prefix: "Bearer " },
    ],
};
```

### 5. Modify `ab-runtime/src/session.rs`

```rust
// In run_session():
// 1. Build credential store from profile + CLI overrides
let cred_rules = build_credential_rules(&opts);
let credential_store = if cred_rules.is_empty() { None } else { Some(CredentialStore::new(cred_rules)) };

// 2. Generate MITM CA if needed
let mitm_ca = if credential_store.is_some() {
    Some(MitmCa::generate()?)
} else { None };

// 3. Write CA cert to session dir for sandbox trust
if let Some(ca) = &mitm_ca {
    let ca_path = session_dir.join("proxy-ca.pem");
    write_secret_file(&ca_path, &ca.ca_cert_pem())?;
    // Add SSL_CERT_FILE to sandbox env
    env.insert("SSL_CERT_FILE".into(), ca_path.display().to_string());
}

// 4. Pass to proxy config
let config = ProxyConfig {
    credential_store,
    mitm_ca,
    ..Default::default()
};
```

### 6. CLI Changes

```bash
# Inject credential at proxy level
--credential '*.anthropic.com:authorization:ANTHROPIC_API_KEY:Bearer '

# Skip default proxy credentials
--no-proxy-credentials
```

## Implementation Steps

### Phase 1: Core Credential Store (ab-proxy)
1. Create `ab-proxy/src/credential.rs` — CredentialStore, CredentialRule, pattern matching
2. Add `credential_store: Option<CredentialStore>` to ProxyConfig
3. Unit tests

### Phase 2: HTTP Injection (ab-proxy)
4. Modify `handle_connection()` — strip + inject auth headers in plain HTTP path
5. Add `cred_injected` to AuditRecord
6. Wire tests for HTTP injection

### Phase 3: MITM HTTPS (ab-proxy)
7. Add `rcgen` + `rustls` + `tokio-rustls` dependencies
8. Create `ab-proxy/src/mitm.rs` — MitmCa generation, host cert caching
9. Implement `mitm_connect()` — TLS termination, HTTP parsing, credential injection, re-encryption
10. Wire MITM path in `handle_connection()`
11. Wire tests for MITM injection

### Phase 4: Profile Integration (ab-profiles)
12. Add ProxyCredential struct, proxy_credentials field to AgentProfile
13. Update all 6 profiles — move sensitive keys to proxy_credentials
14. Update tests

### Phase 5: Runtime Wiring (ab-runtime)
15. `build_credential_rules()` — converts profile + CLI to CredentialRule list
16. MITM CA generation + CA cert delivery to sandbox
17. Wire into run_session()
18. `build_env()` — skip proxy-injected secrets, add SSL_CERT_FILE

### Phase 6: CLI (ab-cli)
19. `--credential` flag (format: `host:header:env_var:prefix`)
20. `--no-proxy-credentials` flag
21. `proxy` subcommand credential support

### Phase 7: Tests & Documentation
22. Wire tests: HTTP injection, MITM injection, auth stripping, missing creds
23. README security model update
24. e2e script: verify env var is empty + API call succeeds

## Dependencies

```toml
# ab-proxy/Cargo.toml
rcgen = "0.13"
rustls = "0.23"
tokio-rustls = "0.26"
rustls-pemfile = "2"
```

## File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `crates/ab-proxy/Cargo.toml` | MODIFY | Add rcgen, rustls, tokio-rustls, rustls-pemfile |
| `crates/ab-proxy/src/credential.rs` | **NEW** | CredentialStore, CredentialRule |
| `crates/ab-proxy/src/mitm.rs` | **NEW** | MitmCa, mitm_connect, TLS termination |
| `crates/ab-proxy/src/lib.rs` | MODIFY | Add modules + re-exports |
| `crates/ab-proxy/src/server.rs` | MODIFY | Inject/strip auth, MITM path |
| `crates/ab-proxy/src/audit.rs` | MODIFY | Add cred_injected field |
| `crates/ab-proxy/tests/wire_test.rs` | MODIFY | Add credential injection tests |
| `crates/ab-profiles/src/lib.rs` | MODIFY | Add ProxyCredential, update profiles |
| `crates/ab-runtime/src/session.rs` | MODIFY | Wire credential store + MITM CA |
| `crates/ab-runtime/Cargo.toml` | MODIFY | (no new deps needed) |
| `crates/ab-cli/src/main.rs` | MODIFY | Add --credential flags |
| `Cargo.lock` | MODIFY | New dependency tree |

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Agent doesn't trust proxy CA | `SSL_CERT_FILE` set in sandbox env; agent TLS libs respect it |
| Agent uses certificate pinning | Rare for LLM API clients; fallback: HTTP path still works |
| Performance overhead of MITM | Per-host cert caching; TLS is fast on modern hardware |
| CONNECT + credential → MITM is transparent to agent | Agent sees valid TLS cert (just signed by proxy CA, not real CA) |
| Credential leak via request body | Proxy audit logs all requests; body inspection out of scope v1 |
| Backward compat | `--no-proxy-credentials` disables all injection; profiles without proxy_credentials unchanged |
