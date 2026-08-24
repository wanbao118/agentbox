//! MXC config (schema `0.8.0-alpha`) generation.
//!
//! One cross-platform shape is emitted for both backends: the GA "model 2"
//! posture — egress denied by default, ingress denied, with the loopback
//! enforcing proxy as the only sanctioned egress path. Seatbelt scopes the
//! sandbox profile to the proxy's exact loopback port; Bubblewrap does the
//! same inside a private netns (slirp4netns + iptables, unprivileged).
//!
//! Field shapes verified against `mxc/src/core/wxc_common/src/{wire.rs,
//! network_parser.rs}` in microsoft/mxc.

use std::path::PathBuf;

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Containment {
    Seatbelt,
    Bubblewrap,
}

impl Containment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Containment::Seatbelt => "seatbelt",
            Containment::Bubblewrap => "bubblewrap",
        }
    }
}

/// Network posture of the session.
#[derive(Clone, Debug, Default)]
pub struct NetworkPosture {
    /// Loopback proxy URL (may carry credentials on seatbelt; must be bare
    /// on bubblewrap). `None` = fully offline.
    pub proxy_url: Option<String>,
    /// Opt-in: allow the sandbox to bind/listen (framework dev servers,
    /// integration-test stubs). Seatbelt cannot separate intra-sandbox
    /// loopback from host loopback, so this necessarily admits inbound
    /// host-loopback connections too — enforced choice, documented trade-off.
    /// Egress stays proxy-only either way.
    pub ingress_allow: bool,
}

/// Process execution parameters.
#[derive(Clone, Debug)]
pub struct ExecSpec {
    pub command_line: String,
    pub cwd: PathBuf,
    /// `KEY=VALUE` pairs; MXC starts the child from a cleared environment and
    /// applies exactly these.
    pub env: Vec<(String, String)>,
}

/// Filesystem policy.
#[derive(Clone, Debug, Default)]
pub struct FsPolicy {
    pub readwrite: Vec<PathBuf>,
    pub readonly: Vec<PathBuf>,
    pub denied: Vec<PathBuf>,
}

/// Seatbelt-specific options.
#[derive(Clone, Copy, Debug)]
pub struct SeatbeltOptions {
    /// Allow the inner process to allocate PTYs (TUI agents need this).
    pub nested_pty: bool,
    /// Allow Keychain reachability (macOS-credential-backed agent logins).
    pub keychain_access: bool,
}

impl Default for SeatbeltOptions {
    fn default() -> Self {
        Self {
            nested_pty: true,
            keychain_access: false,
        }
    }
}

/// Build the full one-shot config document.
pub fn build_config(
    containment: Containment,
    exec: &ExecSpec,
    fs: &FsPolicy,
    network: &NetworkPosture,
    seatbelt: &SeatbeltOptions,
) -> Value {
    let env_pairs = exec
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>();

    let mut config = json!({
        "version": "0.8.0-alpha",
        "containment": containment.as_str(),
        "process": {
            "commandLine": exec.command_line,
            "cwd": exec.cwd.display().to_string(),
            "env": env_pairs,
        },
        "filesystem": {
            "readwritePaths": paths(&fs.readwrite),
            "readonlyPaths": paths(&fs.readonly),
            "deniedPaths": paths(&fs.denied),
        },
        // Egress: proxy-only (model 2), never loosened. Ingress: deny by
        // default; `ingress_allow` opts in to bind/listen (Seatbelt mandates
        // hostLoopback == default, so the pair moves together).
        "network": {
            "egress": { "default": "deny" },
            "ingress": {
                "default": if network.ingress_allow { "allow" } else { "deny" },
                "hostLoopback": if network.ingress_allow { "allow" } else { "deny" },
            },
        },
    });

    if let Some(url) = &network.proxy_url {
        config["runtimeConfig"] = json!({ "networkProxy": url });
    }

    if containment == Containment::Seatbelt {
        config["seatbelt"] = json!({
            "nestedPty": seatbelt.nested_pty,
            "keychainAccess": seatbelt.keychain_access,
        });
    }

    config
}

fn paths(v: &[PathBuf]) -> Vec<String> {
    v.iter().map(|p| p.display().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (ExecSpec, FsPolicy, NetworkPosture) {
        let exec = ExecSpec {
            command_line: "exec 'claude' '--model' 'sonnet'".into(),
            cwd: PathBuf::from("/Users/dev/proj"),
            env: vec![
                ("HOME".into(), "/tmp/scratch/home".into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
            ],
        };
        let fs = FsPolicy {
            readwrite: vec![
                PathBuf::from("/Users/dev/proj"),
                PathBuf::from("/tmp/scratch/home"),
            ],
            readonly: vec![PathBuf::from("/usr/local")],
            denied: vec![],
        };
        let net = NetworkPosture {
            proxy_url: Some("http://agentbox:t0k@127.0.0.1:55555".into()),
            ingress_allow: false,
        };
        (exec, fs, net)
    }

    #[test]
    fn seatbelt_config_shape() {
        let (exec, fs, net) = sample();
        let v = build_config(
            Containment::Seatbelt,
            &exec,
            &fs,
            &net,
            &SeatbeltOptions::default(),
        );
        assert_eq!(v["version"], "0.8.0-alpha");
        assert_eq!(v["containment"], "seatbelt");
        assert_eq!(
            v["process"]["commandLine"],
            "exec 'claude' '--model' 'sonnet'"
        );
        assert_eq!(v["network"]["egress"]["default"], "deny");
        assert_eq!(v["network"]["ingress"]["hostLoopback"], "deny");
        assert_eq!(
            v["runtimeConfig"]["networkProxy"],
            "http://agentbox:t0k@127.0.0.1:55555"
        );
        assert_eq!(v["seatbelt"]["nestedPty"], true);
        assert_eq!(v["filesystem"]["readwritePaths"][0], "/Users/dev/proj");
        // Env serialized as KEY=VALUE strings.
        let env = v["process"]["env"].as_array().unwrap();
        assert!(env.contains(&json!("HOME=/tmp/scratch/home")));
    }

    #[test]
    fn bubblewrap_config_has_no_seatbelt_key() {
        let (exec, fs, net) = sample();
        let v = build_config(
            Containment::Bubblewrap,
            &exec,
            &fs,
            &net,
            &SeatbeltOptions::default(),
        );
        assert!(v.get("seatbelt").is_none());
        assert_eq!(v["containment"], "bubblewrap");
    }

    #[test]
    fn ingress_allow_opens_bind_listen_pair() {
        let (exec, fs, _) = sample();
        let v = build_config(
            Containment::Seatbelt,
            &exec,
            &fs,
            &NetworkPosture {
                proxy_url: None,
                ingress_allow: true,
            },
            &SeatbeltOptions::default(),
        );
        assert_eq!(v["network"]["ingress"]["default"], "allow");
        // Seatbelt requires hostLoopback == default.
        assert_eq!(v["network"]["ingress"]["hostLoopback"], "allow");
        assert_eq!(v["network"]["egress"]["default"], "deny");
    }

    #[test]
    fn offline_posture_omits_runtime_config() {
        let (exec, fs, _) = sample();
        let v = build_config(
            Containment::Seatbelt,
            &exec,
            &fs,
            &NetworkPosture::default(),
            &SeatbeltOptions::default(),
        );
        assert!(v.get("runtimeConfig").is_none());
    }
}
