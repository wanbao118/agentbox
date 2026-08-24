//! Locate the platform MXC native binary.
//!
//! Search order:
//! 1. `AGENTBOX_MXC_BIN` — explicit override.
//! 2. `$PATH`.
//! 3. `~/.agentbox/bin/<name>` (recommended install location).
//! 4. A sibling `mxc` source checkout: any `<ancestor>/mxc/src/target/
//!    {<triple>,release}/<name>`, then `<ancestor>/mxc/sdk/node/bin/<arch>/<name>`
//!    (the build scripts copy binaries there).

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
            && p.metadata().map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
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

    // Sibling checkout discovery from CWD upward and from our own
    // executable's directory upward (CWD-dependent discovery breaks when the
    // CLI is invoked from elsewhere).
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.extend(cwd.ancestors().map(Path::to_path_buf));
    }
    if let Ok(exe) = std::env::current_exe() {
        roots.extend(exe.ancestors().map(Path::to_path_buf));
    }
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
            mxc_root.join("sdk/node/bin").join(sdk_arch_dir()).join(name),
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
