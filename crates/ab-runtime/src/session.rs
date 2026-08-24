//! Session orchestration: profile + options → running MXC sandbox with an
//! enforcing proxy, PTY pass-through, audit summary and cleanup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ab_profiles::{effective_rules, AgentProfile};

use crate::configgen::{build_config, ExecSpec, FsPolicy, NetworkPosture, SeatbeltOptions};

/// How the agent's home dot-dirs are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfigMode {
    /// Copy into a scratch HOME at session start; the real dirs are never
    /// touched (default).
    Snapshot,
    /// Point read-write access at the real directories (convenient, riskier:
    /// the agent can rewrite its own config/login state).
    Rw,
}

/// Everything a run needs.
#[derive(Clone)]
pub struct RunOptions {
    pub profile: &'static AgentProfile,
    pub workspace: PathBuf,
    pub passthrough: Vec<String>,
    /// `-e K=V` (literal) or `-e K` (forward host value).
    pub env: Vec<String>,
    pub inherit_secrets: Vec<String>,
    pub extra_allow: Vec<String>,
    pub extra_deny: Vec<String>,
    /// Extra network groups (`--net-preset packages,...`).
    pub net_groups: Vec<String>,
    pub no_default_groups: bool,
    pub offline: bool,
    pub config_mode: ConfigMode,
    pub keychain: bool,
    /// Opt-in: let the sandbox bind/listen (dev servers, test stubs).
    pub allow_listen: bool,
    /// Opt-out: skip mounting host toolchain caches / snapshotting their
    /// credential files (Nexus tokens, npmrc, netrc, ...).
    pub no_toolchain_cache: bool,
    pub keep_session: bool,
    pub dry_run: bool,
    pub debug: bool,
    pub denied_paths: Vec<PathBuf>,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditSummary {
    pub allowed: u64,
    pub denied: u64,
    pub errors: u64,
    pub top_denied: Vec<(String, u64)>,
}

#[derive(Debug)]
pub struct SessionOutcome {
    pub exit_code: i32,
    pub session_dir: PathBuf,
    pub audit_path: Option<PathBuf>,
    pub audit_summary: Option<AuditSummary>,
    pub proxy_port: Option<u16>,
}

/// Best-effort chmod 0700 (ignore on non-unix / failure: the unpredictable
/// tokenized dir name is the first line of defense).
fn restrict_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[allow(unused_variables)]
    let _ = path;
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// HostRule::parse with anyhow-compatible errors.
fn rule(s: &str) -> anyhow::Result<ab_proxy::HostRule> {
    ab_proxy::HostRule::parse(s).map_err(|e| anyhow::anyhow!("{e}"))
}

fn which(name: &str) -> Option<PathBuf> {
    let dirs = std::env::var("PATH").unwrap_or_default();
    let sep = if std::env::consts::OS == "windows" { ";" } else { ":" };
    for dir in dirs.split(sep) {
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if candidate.is_file()
                && candidate
                    .metadata()
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn copy_tree(src: &Path, dest: &Path) -> anyhow::Result<u64> {
    let mut copied = 0u64;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src)?;
        let target = dest.join(rel);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if file_type.is_symlink() {
            // Skip symlinks: they can point anywhere on the host.
            eprintln!(
                "agentbox: skipping symlink {} during snapshot",
                entry.path().display()
            );
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
            copied += 1;
        }
    }
    Ok(copied)
}

/// Readonly toolchain roots worth exposing to the sandbox.
fn toolchain_roots() -> Vec<PathBuf> {
    let os = std::env::consts::OS;
    let candidates: &[&str] = if os == "macos" {
        &["/usr/local", "/opt/homebrew"]
    } else {
        &["/usr/local", "/opt", "/snap"]
    };
    candidates
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// Expand profile `extra_rw` templates (`{uid}`) and ensure the dirs exist.
fn extra_rw_paths(profile: &AgentProfile) -> Vec<PathBuf> {
    if profile.extra_rw.is_empty() {
        return Vec::new();
    }
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "501".into());
    profile
        .extra_rw
        .iter()
        .map(|t| t.replace("{uid}", &uid))
        .map(PathBuf::from)
        .filter_map(|p| {
            // Pre-create so backends that bind existing paths succeed.
            match std::fs::create_dir_all(&p).map(|_| restrict_owner_only(&p)) {
                Ok(_) => Some(p),
                Err(e) => {
                    eprintln!("agentbox: warning: cannot prepare {}: {e}", p.display());
                    None
                }
            }
        })
        .collect()
}

/// Parent directory of each resolved binary (so agents next to custom
/// install locations stay reachable read-only).
fn binary_dirs(profile: &AgentProfile) -> Vec<PathBuf> {
    profile
        .binaries
        .iter()
        .find_map(|b| which(b))
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .into_iter()
        .collect()
}

fn parse_env_entries(
    entries: &[String],
) -> (Vec<(String, String)>, Vec<String>) {
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for entry in entries {
        match entry.split_once('=') {
            Some((k, v)) if !k.is_empty() => out.push((k.to_string(), v.to_string())),
            _ => match std::env::var(entry) {
                Ok(v) => out.push((entry.clone(), v)),
                Err(_) => missing.push(entry.clone()),
            },
        }
    }
    (out, missing)
}

fn build_allowlist(opts: &RunOptions) -> anyhow::Result<ab_proxy::HostFilter> {
    let mut allow: Vec<ab_proxy::HostRule> = Vec::new();
    for r in effective_rules(opts.profile) {
        allow.push(rule(r)?);
    }
    if !opts.no_default_groups {
        for group_name in &opts.net_groups {
            let rules = ab_profiles::group(group_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown net group `{group_name}` (known: packages, packages-pip, \
                     packages-npm, packages-cargo, telemetry, git, anthropic, openai, \
                     google, openrouter)"
                )
            })?;
            for r in rules.iter() {
                allow.push(rule(r)?);
            }
        }
    }
    for r in &opts.extra_allow {
        allow.push(rule(r)?);
    }

    let mut deny = Vec::new();
    for r in &opts.extra_deny {
        deny.push(rule(r)?);
    }

    Ok(ab_proxy::HostFilter { allow, deny, allow_ip_literals: false })
}

/// Small credential/config FILES snapshotted into the session HOME so package
/// managers reach private registries (Nexus, Artifactory, GPR, ...). Only
/// existing files are copied; they live in the ephemeral scratch and die with
/// the session.
const TOOLCHAIN_CONFIG_FILES: &[&str] = &[
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    ".cargo/config.toml",
    ".cargo/credentials.toml",
    ".config/pip/pip.conf",
    ".config/go/env",
];

/// Build-cache directories mounted READ-WRITE from the host so repeated
/// builds reuse artifacts instead of re-downloading through the proxy.
const TOOLCHAIN_CACHE_DIRS: &[&str] = &[
    ".m2/repository",
    ".gradle/caches",
    ".npm",
    ".cache/pip",
    "go/pkg/mod",
    ".cargo/registry",
    ".cargo/git/db",
];

/// Apply toolchain config snapshots + cache mounts. Returns extra rw paths.
fn apply_toolchain_mounts(
    home: &Path,
    scratch_home: &Path,
) -> Vec<PathBuf> {
    let mut rw = Vec::new();

    for rel in TOOLCHAIN_CONFIG_FILES {
        let src = home.join(rel);
        if !src.is_file() {
            continue;
        }
        let dest = scratch_home.join(rel);
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(&src, &dest) {
            Ok(_) => eprintln!("agentbox: config snapshotted ~/{rel}", rel = rel),
            Err(e) => eprintln!("agentbox: warning: ~/{rel} not copied: {e}", rel = rel),
        }
    }

    for rel in TOOLCHAIN_CACHE_DIRS {
        let real = home.join(rel);
        if let Some(parent) = real.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Mount whether or not it exists yet — first build populates it and
        // subsequent sessions reuse the host cache.
        std::fs::create_dir_all(&real).ok();
        rw.push(real);
    }
    rw
}

fn build_env(
    opts: &RunOptions,
    scratch_home: &Path,
    scratch_tmp: &Path,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut env: HashMap<String, String> = HashMap::new();

    // PATH: inherit so node/python/etc. resolve inside; HOME/TMPDIR: scratch.
    env.insert(
        "PATH".into(),
        std::env::var("PATH")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()),
    );
    env.insert("HOME".into(), scratch_home.display().to_string());
    // Redirect the sandbox-wide temp dir into the session scratch area so
    // tools that `mkdir $(tmpdir)/<name>` (Bun/opencode, pip, npm) land in a
    // writable path instead of getting EPERM on the host /tmp.
    env.insert("TMPDIR".into(), scratch_tmp.display().to_string());
    // Align every JVM's temp dir with the sandbox-writable TMPDIR. This is
    // what makes the JDK attach API work between two in-sandbox JVMs (attach
    // protocol creates .attach_pid<pid> in the shared tmp) and keeps
    // temp-heavy builds off the read-only host /tmp. Existing user flags are
    // preserved by prepending ours (JVM merges JAVA_TOOL_OPTIONS last-wins
    // per property).
    let jto = match std::env::var("JAVA_TOOL_OPTIONS") {
        Ok(v) if !v.is_empty() => format!("-Djava.io.tmpdir=\"{}\" {v}", scratch_tmp.display()),
        _ => format!("-Djava.io.tmpdir=\"{}\"", scratch_tmp.display()),
    };
    env.insert("JAVA_TOOL_OPTIONS".into(), jto);
    for passthrough_key in ["TERM", "LANG", "LC_ALL", "TZ", "SHELL"] {
        if let Ok(v) = std::env::var(passthrough_key) {
            env.insert(passthrough_key.into(), v);
        }
    }

    // Profile secrets that exist on the host.
    let mut warned_missing: Vec<String> = Vec::new();
    for key in opts.profile.secrets_env {
        match std::env::var(key) {
            Ok(v) if !v.is_empty() => {
                env.insert((*key).to_string(), v);
            }
            _ => {}
        }
    }

    // -e entries and explicit --inherit-secret.
    let (extra, missing) = parse_env_entries(&opts.env);
    for k in missing {
        warned_missing.push(k);
    }
    for (k, v) in extra {
        env.insert(k, v);
    }
    for key in &opts.inherit_secrets {
        match std::env::var(key) {
            Ok(v) => {
                env.insert(key.clone(), v);
            }
            Err(_) => warned_missing.push(key.clone()),
        }
    }
    for k in &warned_missing {
        eprintln!("agentbox: warning: requested env var `{k}` is not set on the host");
    }

    Ok(env.into_iter().collect())
}

async fn summarize_audit(path: &Path) -> Option<AuditSummary> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    let mut allowed = 0u64;
    let mut denied = 0u64;
    let mut errors = 0u64;
    let mut denied_hosts: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        match v["event"].as_str() {
            Some("allow") => allowed += 1,
            Some("deny") => {
                denied += 1;
                if let Some(h) = v["host"].as_str() {
                    *denied_hosts.entry(h.to_string()).or_default() += 1;
                }
            }
            Some("error") => errors += 1,
            _ => {}
        }
    }
    let mut top: Vec<(String, u64)> = denied_hosts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top.truncate(5);
    Some(AuditSummary { allowed, denied, errors, top_denied: top })
}

/// Execute one sandboxed agent session end-to-end.
pub async fn run_session(opts: RunOptions) -> anyhow::Result<SessionOutcome> {
    if std::env::consts::OS == "windows" {
        anyhow::bail!(
            "agentbox does not support Windows yet: only macOS Seatbelt and Linux \
             Bubblewrap backends are wired. See README roadmap."
        );
    }
    let workspace = opts.workspace.canonicalize().map_err(|e| {
        anyhow::anyhow!("workspace {}: {e}", opts.workspace.display())
    })?;

    // ---- Session scratch dir --------------------------------------------
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let session_dir =
        std::env::temp_dir().join(format!("agentbox-{nanos}-{}", ab_proxy::generate_token()));
    let scratch_home = session_dir.join("home");
    let scratch_tmp = session_dir.join("tmp");
    std::fs::create_dir_all(scratch_home.join(".cache"))?;
    std::fs::create_dir_all(&scratch_tmp)?;
    // Session scratch holds snapshotted credentials and egress logs; tighten
    // every level (children are created before the parent chmod above).
    restrict_owner_only(&session_dir);
    restrict_owner_only(&scratch_home);
    restrict_owner_only(&scratch_tmp);
    restrict_owner_only(scratch_home.join(".cache").as_path());

    // ---- Snapshot agent config ------------------------------------------
    let mut rw_extra: Vec<PathBuf> = Vec::new();
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()));
    for spec in opts.profile.home_specs {
        let src = home.join(spec.rel);
        if !src.exists() {
            continue;
        }
        match opts.config_mode {
            ConfigMode::Snapshot => {
                let dest = scratch_home.join(spec.rel);
                match copy_tree(&src, &dest) {
                    Ok(n) => eprintln!("agentbox: snapshotted ~/{rel} ({n} files)", rel = spec.rel),
                    Err(e) => eprintln!(
                        "agentbox: warning: snapshot of ~/{rel} failed: {e}",
                        rel = spec.rel
                    ),
                }
            }
            ConfigMode::Rw => {
                eprintln!(
                    "agentbox: WARNING: exposing real ~/{rel} read-write inside the sandbox",
                    rel = spec.rel
                );
                rw_extra.push(src);
            }
        }
    }

    // ---- Proxy -----------------------------------------------------------
    let (bound, proxy_url): (Option<ab_proxy::BoundProxy>, Option<String>) = if opts.offline {
        eprintln!("agentbox: offline mode — no proxy, no network");
        (None, None)
    } else {
        let filter = build_allowlist(&opts)?;
        // Seatbelt injects proxy env internally, so credentials in the URL are
        // safe there. Bubblewrap passes the URL via argv (world-readable via
        // /proc/<pid>/cmdline) and MXC rejects credential-bearing URLs — so on
        // Linux we run tokenless on a per-session random port.
        let macos = std::env::consts::OS == "macos";
        let token = if macos { Some(ab_proxy::generate_token()) } else { None };
        let audit_path = session_dir.join("proxy-audit.jsonl");
        let bound = ab_proxy::spawn(ab_proxy::ProxyConfig {
            port: 0,
            token: token.clone(),
            filter,
            audit_path: Some(audit_path.clone()),
            ..Default::default()
        })
        .await?;
        let port = bound.port;
        eprintln!(
            "agentbox: enforcing proxy on 127.0.0.1:{port} ({}, audit: {})",
            if token.is_some() { "token-authenticated" } else { "unauthenticated (platform limit)" },
            audit_path.display()
        );
        let url = match token {
            Some(t) => format!("http://agentbox:{t}@127.0.0.1:{port}"),
            None => format!("http://127.0.0.1:{port}"),
        };
        (Some(bound), Some(url))
    };

    // ---- Environment -----------------------------------------------------
    let env_pairs = build_env(&opts, &scratch_home, &scratch_tmp)?;

    // ---- Command line ----------------------------------------------------
    let bin = which(opts.profile.binaries[0])
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| opts.profile.binaries[0].to_string());
    let mut parts = vec!["exec".to_string(), sh_quote(&bin)];
    parts.extend(opts.passthrough.iter().map(|a| sh_quote(a)));
    let command_line = parts.join(" ");

    // ---- Filesystem policy -------------------------------------------------
    let readonly = {
        let mut v = toolchain_roots();
        v.extend(binary_dirs(opts.profile));
        v.sort();
        v.dedup();
        v
    };
    let fs = FsPolicy {
        readwrite: {
            let mut v = vec![workspace.clone(), scratch_home.clone(), scratch_tmp.clone()];
            v.extend(extra_rw_paths(opts.profile));
            v.extend(rw_extra.iter().cloned());
            if !opts.no_toolchain_cache {
                v.extend(apply_toolchain_mounts(&home, &scratch_home));
            }
            v
        },
        readonly,
        denied: opts.denied_paths.clone(),
    };

    let exec = ExecSpec { command_line, cwd: workspace, env: env_pairs };

    let containment = crate::default_containment();
    let seatbelt_opts =
        SeatbeltOptions { nested_pty: true, keychain_access: opts.keychain };

    let config = build_config(
        containment,
        &exec,
        &fs,
        &NetworkPosture { proxy_url: proxy_url.clone(), ingress_allow: opts.allow_listen },
        &seatbelt_opts,
    );

    if opts.dry_run {
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(SessionOutcome {
            exit_code: 0,
            session_dir,
            audit_path: None,
            audit_summary: None,
            proxy_port: bound.as_ref().map(|b| b.port),
        });
    }

    // ---- Locate mxc and spawn ----------------------------------------------
    let mxc = crate::find_mxc_binary().ok_or_else(|| {
        anyhow::anyhow!(
            "mxc native binary `{}` not found (AGENTBOX_MXC_BIN, ~/.agentbox/bin, PATH, or sibling ./mxc build)",
            crate::mxc_binary_name()
        )
    })?;

    let encoded = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(config.to_string())
    };

    eprintln!(
        "agentbox: launching {} ({}) for {}",
        mxc.display(),
        containment.as_str(),
        opts.profile.id
    );

    let mut cmd = tokio::process::Command::new(&mxc);
    cmd.arg("--config-base64").arg(&encoded).stdin(std::process::Stdio::inherit());
    if opts.debug {
        cmd.arg("--debug");
    }
    // stdin/stdout/stderr default to inherit in tokio when not configured;
    // make it explicit for clarity.
    cmd.stdout(std::process::Stdio::inherit()).stderr(std::process::Stdio::inherit());

    let status = cmd.status().await.map_err(|e| anyhow::anyhow!("spawn mxc: {e}"))?;
    let exit_code = status.code().unwrap_or(1);

    // ---- Teardown ----------------------------------------------------------
    if let Some(b) = &bound {
        b.shutdown();
    }

    let audit_path_opt = session_dir.join("proxy-audit.jsonl");
    let audit_summary = if audit_path_opt.exists() {
        summarize_audit(&audit_path_opt).await
    } else {
        None
    };

    if let Some(summary) = &audit_summary {
        eprintln!(
            "agentbox: egress summary — allowed: {}, denied: {}, errors: {}",
            summary.allowed, summary.denied, summary.errors
        );
        for (host, n) in &summary.top_denied {
            eprintln!("agentbox:   denied {host} ×{n}");
        }
    }

    if opts.keep_session {
        eprintln!("agentbox: session dir kept at {}", session_dir.display());
    } else {
        let _ = std::fs::remove_dir_all(&session_dir);
    }
    let audit_path_out = audit_summary.as_ref().map(|_| audit_path_opt);

    Ok(SessionOutcome {
        exit_code,
        session_dir,
        audit_path: audit_path_out,
        audit_summary,
        proxy_port: bound.as_ref().map(|b| b.port),
    })
}
