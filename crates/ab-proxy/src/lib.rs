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
//! - **JSONL audit log** of every allow/deny decision for fast allowlist
//!   iteration.

pub mod audit;
pub mod rules;
pub mod server;

pub use audit::{Audit, AuditRecord};
pub use rules::{normalize_host, HostFilter, HostRule};
pub use server::{generate_token, spawn, BoundProxy, ProxyConfig};
