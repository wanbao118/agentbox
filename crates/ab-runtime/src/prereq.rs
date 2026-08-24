//! `agentbox doctor` — environment readiness checks.

use std::path::PathBuf;

use ab_profiles::AgentProfile;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn which(name: &str) -> Option<PathBuf> {
    let dirs = std::env::var("PATH").unwrap_or_default();
    for dir in dirs.split(':') {
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

/// Run all checks; `profile` adds agent-specific checks when given.
pub async fn run_doctor(profile: Option<&'static AgentProfile>) -> Vec<Check> {
    let mut out = Vec::new();

    // Host basics. Windows has no wired backend yet — say so up front.
    let windows = std::env::consts::OS == "windows";
    out.push(Check {
        name: "host".into(),
        ok: !windows,
        detail: format!(
            "{os} {arch}{suffix}",
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            suffix = if windows {
                " — not supported yet (macOS/Linux only in v1)"
            } else {
                ""
            }
        ),
    });

    // MXC binary.
    match super::find_mxc_binary() {
        Some(p) => out.push(Check {
            name: "mxc-binary".into(),
            ok: true,
            detail: p.display().to_string(),
        }),
        None => out.push(Check {
            name: "mxc-binary".into(),
            ok: false,
            detail: format!(
                "`{}` not found. Set AGENTBOX_MXC_BIN, install to ~/.agentbox/bin/, \
                 or build the sibling checkout (cd mxc && ./build-mac.sh --rust-only / ./build.sh)",
                super::mxc_binary_name()
            ),
        }),
    }

    // Platform prerequisites.
    if std::env::consts::OS == "macos" {
        out.push(Check {
            name: "seatbelt".into(),
            ok: true,
            detail: "built into macOS (sandbox_init); no extra packages".into(),
        });
    } else {
        for tool in ["bwrap", "slirp4netns", "iptables", "ip6tables"] {
            let found = which(tool);
            out.push(Check {
                name: format!("linux-tool-{tool}"),
                ok: found.is_some(),
                detail: found
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| match tool {
                        "bwrap" => "install bubblewrap".into(),
                        "slirp4netns" => "install slirp4netns (proxy-mode egress)".into(),
                        _ => format!("install {tool} (netns firewall rules)"),
                    }),
            });
        }
        let userns =
            std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone").ok();
        let enabled = userns.map(|s| s.trim() != "0").unwrap_or(true);
        out.push(Check {
            name: "unprivileged-userns".into(),
            ok: enabled,
            detail: if enabled {
                "enabled".into()
            } else {
                "kernel.unprivileged_userns_clone=0 — enable it or bwrap cannot run".into()
            },
        });
    }

    // Proxy self-test: can we bind an ephemeral loopback proxy at all?
    {
        let bound = ab_proxy::spawn(ab_proxy::ProxyConfig::default()).await;
        out.push(match bound {
            Ok(b) => {
                b.shutdown();
                Check { name: "loopback-bind".into(), ok: true, detail: format!("ephemeral bind on {}", b.port) }
            }
            Err(e) => Check {
                name: "loopback-bind".into(),
                ok: false,
                detail: format!("cannot bind 127.0.0.1: {e}"),
            },
        });
    }

    // Profile-specific checks.
    if let Some(profile) = profile {
        let bin_found = profile.binaries.iter().find_map(|b| which(b));
        out.push(Check {
            name: format!("{}-binary", profile.id),
            ok: bin_found.is_some(),
            detail: bin_found
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| format!(
                    "none of {:?} found in PATH — install the CLI or run inside with an explicit path",
                    profile.binaries
                )),
        });

        let home = std::env::var("HOME").unwrap_or_default();
        for spec in profile.home_specs {
            let path = std::path::Path::new(&home).join(spec.rel);
            let exists = path.exists();
            out.push(Check {
                name: format!("home/{}", spec.rel),
                ok: exists || spec.optional,
                detail: if exists {
                    path.display().to_string()
                } else if spec.optional {
                    "absent (optional)".into()
                } else {
                    "missing — run the agent once on the host first, or expect a fresh login"
                        .into()
                },
            });
        }

        let mut present = Vec::new();
        for key in profile.secrets_env {
            if std::env::var_os(key).map(|v| !v.is_empty()).unwrap_or(false) {
                present.push(*key);
            }
        }
        out.push(Check {
            name: "credentials-env".into(),
            ok: !present.is_empty(),
            detail: if present.is_empty() {
                format!(
                    "no {} vars set; OAuth snapshot from home dirs will be used",
                    profile.secrets_env.join("/")
                )
            } else {
                format!("forwarding candidates: {}", present.join(", "))
            },
        });
    }

    out
}
