//! Locate the platform MXC native binary.
//!
//! Trust roots (searched in order):
//! 1. `AGENTBOX_MXC_BIN` — explicit override.
//! 2. `$PATH`.
//! 3. `~/.agentbox/bin/<name>` (recommended install location).
//!
//! A sibling `mxc` source checkout (`<ancestor>/mxc/src/target/{<triple>,}
//! release/<name>` or `<ancestor>/mxc/sdk/node/bin/<arch>/<name>`) is NOT
//! trusted by default: any repository a victim clones can place an executable
//! at that plausible-looking path, and this binary is the sandbox *launcher*
//! running unsandboxed on the host. Opt in per-environment with
//! `AGENTBOX_ALLOW_SIBLING_MXC=1` (e.g. your own dev checkout or CI, which
//! builds `../mxc` itself); see [`sibling_mxc_hint`] for actionable
//! diagnostics.

use std::path::{Path, PathBuf};

/// Native binary name per MXC's build layout.
pub fn mxc_binary_name() -> &'static str {
    if std::env::consts::OS == "macos" {
        "mxc-exec-mac"
    } else {
        "lxc-exec"
    }
}

/// Directory name used by the mxc SDK bundling convention (`x64` / `arm64`).
fn sdk_arch_dir() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    }
}

/// Rust target triple for cargo target dirs.
fn rust_triple() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        if std::env::consts::OS == "macos" {
            "aarch64-apple-darwin"
        } else {
            "aarch64-unknown-linux-gnu"
        }
    } else if std::env::consts::OS == "macos" {
        "x86_64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.is_file()
            && p.metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

fn path_dirs() -> Vec<PathBuf> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(std::path::MAIN_SEPARATOR)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Env var that re-enables trusting an `mxc/` source checkout found among the
/// ancestors of the CWD (or of the executable). Off by default: those
/// directories are attacker-controllable (cloning any repo puts one there)
/// and the discovered binary runs unsandboxed on the host as the user.
pub const SIBLING_DISCOVERY_ENV: &str = "AGENTBOX_ALLOW_SIBLING_MXC";

/// Sibling-checkout discovery is enabled only via an explicit opt-in.
fn sibling_discovery_enabled() -> bool {
    matches!(
        std::env::var(SIBLING_DISCOVERY_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Ancestor roots for sibling discovery: CWD upward plus our own executable's
/// directory upward (CWD-only discovery breaks when the CLI is invoked from
/// elsewhere).
fn discovery_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.extend(cwd.ancestors().map(Path::to_path_buf));
    }
    if let Ok(exe) = std::env::current_exe() {
        roots.extend(exe.ancestors().map(Path::to_path_buf));
    }
    roots
}

/// Walk `roots` for a usable binary inside a sibling `mxc/` checkout.
fn sibling_from_roots(roots: &[PathBuf], name: &str) -> Option<PathBuf> {
    for ancestor in roots {
        let mxc_root = ancestor.join("mxc");
        if !mxc_root.join("src").exists() && !mxc_root.join("sdk").exists() {
            continue;
        }
        let mut candidates = vec![
            mxc_root
                .join("src/target")
                .join(rust_triple())
                .join("release")
                .join(name),
            mxc_root.join("src/target/release").join(name),
            mxc_root
                .join("sdk/node/bin")
                .join(sdk_arch_dir())
                .join(name),
        ];
        candidates.sort();
        candidates.dedup();
        for c in candidates {
            if is_executable(&c) {
                return Some(c);
            }
        }
    }
    None
}

/// Find the mxc native binary, if present.
pub fn find_mxc_binary() -> Option<PathBuf> {
    let name = mxc_binary_name();

    if let Ok(exe) = std::env::var("AGENTBOX_MXC_BIN") {
        let p = PathBuf::from(exe);
        if is_executable(&p) {
            return Some(p);
        }
    }

    for dir in path_dirs() {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    let home = std::env::var("HOME").ok()?;
    let installed = PathBuf::from(&home).join(".agentbox/bin").join(name);
    if is_executable(&installed) {
        return Some(installed);
    }

    // Sibling checkouts are gated: see module docs + SIBLING_DISCOVERY_ENV.
    if sibling_discovery_enabled() {
        return sibling_from_roots(&discovery_roots(), name);
    }
    None
}

/// Where a sibling-checkout binary *would* have been found, ignoring the
/// opt-in gate. Read-only diagnostics for `doctor`: it never executes or
/// returns this path from [`find_mxc_binary`] unless the operator sets
/// `AGENTBOX_ALLOW_SIBLING_MXC=1`.
pub fn sibling_mxc_hint() -> Option<PathBuf> {
    sibling_from_roots(&discovery_roots(), mxc_binary_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure root-walk must find a binary laid out like a built checkout,
    /// and skip directories without src/sdk markers.
    #[test]
    fn sibling_scan_finds_built_checkout() {
        let tmp = std::env::temp_dir().join(format!("ab-mxcbin-test-{}", std::process::id()));
        let target = tmp.join("fakeproj/mxc/src/target/release");
        std::fs::create_dir_all(&target).unwrap();
        let bin = target.join(mxc_binary_name());
        std::fs::write(
            &bin,
            b"#!/bin/sh
",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let found = sibling_from_roots(&[tmp.join("fakeproj"), tmp.clone()], mxc_binary_name());
        assert_eq!(found, Some(bin.clone()));

        // No marker dirs -> nothing found even if an identically named file
        // exists somewhere along the roots.
        let empty = std::env::temp_dir().join(format!("ab-mxcbin-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(
            sibling_from_roots(std::slice::from_ref(&empty), mxc_binary_name()),
            None
        );

        let _ = std::fs::remove_file(&bin);
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
