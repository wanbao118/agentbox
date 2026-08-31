//! ab-proxy — the enforcing egress proxy of agentbox.
//!
//! MXC guarantees at the kernel layer that a sandboxed process can only reach
//! this proxy's exact `127.0.0.1:<port>` endpoint (Seatbelt profile scoping on
//! macOS; netns + iptables on Linux). This crate provides the other half of
//! that contract: an HTTP(S) forward proxy that enforces a *hostname*
//! allowlist at the application layer, so domain-level policy is actually
//! applied to every tunneled connection.
//!
//! Design constraints:
//!
//! - **Deny by default.** With no allow rules, nothing passes.
//! - **DNS resolves here, not in the sandbox.** CONNECT carries hostnames, so
//!   the sandbox never needs direct DNS and cannot use it as a side channel.
//! - **IP-literal hosts are rejected** unless explicitly allowlisted, which
//!   closes the "resolve once, connect by IP" bypass.
//! - **Per-session bearer token** (Proxy-Authorization) stops other local
//!   processes from borrowing this proxy's policy.
//! - **Post-DNS destination check** (`netguard`): allowlisted hostnames that
//!   resolve into loopback/link-local/RFC1918/ULA space are refused, closing
//!   SSRF and DNS-rebinding paths at the L7 layer.
//! - **Bounded resources**: concurrent connections are semaphore-capped and
//!   every tunnel has a total-lifetime cap, so a compromised sandbox cannot
//!   exhaust host FDs/memory through the proxy.
//! - **JSONL audit log** of every allow/deny decision for fast allowlist
//!   iteration.

pub mod audit;
pub mod credential;
pub mod mitm;
pub mod netguard;
pub mod rules;
pub mod server;

pub use audit::{Audit, AuditRecord};
pub use credential::{CredentialMatch, CredentialRule, CredentialSource, CredentialStore};
pub use mitm::MitmCa;
pub use netguard::is_protected_destination;
pub use rules::{normalize_host, HostFilter, HostRule};
pub use server::{
    generate_token, spawn, BoundProxy, ProxyConfig, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_TUNNEL_MAX_DURATION,
};
