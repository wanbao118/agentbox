//! agentbox — run coding agents inside MXC-enforced sandboxes.

use std::path::PathBuf;

use ab_profiles::{group, effective_rules, PROFILES};
use ab_runtime::run_session;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentbox",
    version,
    about = "Run coding agents inside an MXC-enforced sandbox with domain-level egress control",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a coding agent inside a sandboxed session.
    Run {
        /// Agent profile id (see `agentbox profiles`).
        profile: String,
        /// Workspace directory (defaults to CWD); the only writable host path.
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Extra allow rules, e.g. `--allow '*.example.com'` or `--allow 10.0.2.2:443`.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Deny rules; always win over allows.
        #[arg(long = "deny")]
        deny: Vec<String>,
        /// Extra network groups: packages, packages-npm, packages-pip,
        /// packages-cargo, telemetry, git, anthropic, openai, google, openrouter.
        #[arg(long = "net-group", value_delimiter = ',')]
        net_groups: Vec<String>,
        /// Skip the profile's default groups.
        #[arg(long = "no-default-groups", default_value_t = false)]
        no_default_groups: bool,
        /// No network at all (no proxy is started).
        #[arg(long)]
        offline: bool,
        /// Env vars to forward: `-e KEY=VALUE` or `-e KEY` (host value).
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        /// Force-forward specific env vars (warned when missing).
        #[arg(long = "inherit-secret")]
        inherit_secret: Vec<String>,
        /// Paths to explicitly deny read/write inside the sandbox.
        #[arg(long = "deny-path")]
        deny_path: Vec<PathBuf>,
        /// Expose real agent config dirs read-write instead of snapshotting.
        #[arg(long, default_value_t = false)]
        rw_config: bool,
        /// macOS only: allow Keychain reachability inside the sandbox.
        #[arg(long)]
        keychain: bool,
        /// Let the sandbox bind/listen (dev servers, test stubs). Egress
        /// stays proxy-only; on Seatbelt this also admits host-loopback
        /// inbound (platform limitation).
        #[arg(long)]
        allow_listen: bool,
        /// Skip host toolchain caches (.m2, gradle, npm, pip, go, cargo) and
        /// credential-file snapshots.
        #[arg(long)]
        no_toolchain_cache: bool,
        /// Print the generated MXC config and exit.
        #[arg(long)]
        dry_run: bool,
        /// Keep the session scratch dir after exit (for debugging).
        #[arg(long)]
        keep_session: bool,
        /// Pass --debug through to the mxc binary.
        #[arg(long)]
        debug: bool,
        /// Arguments passed verbatim to the agent CLI (after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        passthrough: Vec<String>,
    },
    /// Check host readiness for sandboxed runs.
    Doctor {
        /// Also check a specific agent profile.
        profile: Option<String>,
    },
    /// List built-in profiles and their baselines.
    Profiles {
        /// Show detailed network rules for each profile.
        #[arg(long)]
        verbose: bool,
    },
    /// Print a profile's effective network baseline.
    Allowlist { profile: String },
    /// Test whether a host would be allowed for a profile (+ groups).
    Match {
        profile: String,
        /// Host or host:port to test.
        host: String,
        /// Extra groups applied on top of the baseline.
        #[arg(long = "net-group", value_delimiter = ',')]
        net_groups: Vec<String>,
        /// Extra allow rules as on `run`.
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
    /// Start a standalone enforcing proxy (for debugging / custom runners).
    Proxy {
        /// Allow rules (repeatable). No rules = deny all.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Deny rules (win over allows).
        #[arg(long = "deny")]
        deny: Vec<String>,
        /// Require this token via Proxy-Authorization.
        #[arg(long)]
        token: Option<String>,
        /// Port to bind (default: ephemeral).
        #[arg(long)]
        port: Option<u16>,
        /// JSONL audit output path.
        #[arg(long)]
        audit: Option<PathBuf>,
    },
}

fn resolve_profile(id: &str) -> anyhow::Result<&'static ab_profiles::AgentProfile> {
    ab_profiles::get(id).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown profile `{id}` — available: {}",
            PROFILES.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
        )
    })
}

async fn build_filter_for_match(
    profile: &str,
    net_groups: &[String],
    extra_allow: &[String],
) -> anyhow::Result<ab_proxy::HostFilter> {
    let p = resolve_profile(profile)?;
    let rule = |s: &str| -> anyhow::Result<ab_proxy::HostRule> {
        ab_proxy::HostRule::parse(s).map_err(|e| anyhow::anyhow!("{e}"))
    };
    let mut allow: Vec<ab_proxy::HostRule> =
        effective_rules(p).iter().map(|r| rule(r)).collect::<Result<_, _>>()?;
    for g in net_groups {
        let rules = group(g)
            .ok_or_else(|| anyhow::anyhow!("unknown group `{g}`"))?;
        for r in rules.iter() {
            allow.push(rule(r)?);
        }
    }
    for r in extra_allow {
        allow.push(rule(r)?);
    }
    Ok(ab_proxy::HostFilter::new(allow, vec![]))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            profile,
            workspace,
            allow,
            deny,
            net_groups,
            no_default_groups,
            offline,
            env,
            inherit_secret,
            deny_path,
            rw_config,
            keychain,
            allow_listen,
            no_toolchain_cache,
            dry_run,
            keep_session,
            debug,
            passthrough,
        } => {
            let profile_ref = resolve_profile(&profile)?;
            let opts = ab_runtime::RunOptions {
                profile: profile_ref,
                workspace: workspace
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
                passthrough,
                env,
                inherit_secrets: inherit_secret,
                extra_allow: allow,
                extra_deny: deny,
                net_groups,
                no_default_groups,
                offline,
                config_mode: if rw_config {
                    ab_runtime::ConfigMode::Rw
                } else {
                    ab_runtime::ConfigMode::Snapshot
                },
                keychain,
                allow_listen,
                no_toolchain_cache,
                keep_session,
                dry_run,
                debug,
                denied_paths: deny_path,
            };
            let outcome = run_session(opts).await?;
            std::process::exit(outcome.exit_code);
        }

        Command::Doctor { profile } => {
            let profile_ref = match &profile {
                Some(p) => Some(resolve_profile(p)?),
                None => None,
            };
            let checks = ab_runtime::run_doctor(profile_ref).await;
            let width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
            for c in &checks {
                println!(
                    "{status} {name:<width$}  {detail}",
                    status = if c.ok { "✓" } else { "✗" },
                    name = c.name,
                    width = width,
                    detail = c.detail
                );
            }
            if checks.iter().all(|c| c.ok) {
                println!("\nall checks passed");
                return Ok(());
            }
            std::process::exit(1);
        }

        Command::Profiles { verbose } => {
            for p in PROFILES {
                println!("{}  — {}", p.id, p.display);
                if verbose {
                    for b in p.binaries {
                        println!("    binary:      {b}");
                    }
                    for s in p.home_specs {
                        println!("    home dir:    ~/{}{}", s.rel, if s.optional { " (optional)" } else { "" });
                    }
                    println!("    secrets:     {}", p.secrets_env.join(", "));
                    println!(
                        "    net groups:  {}",
                        if p.default_groups.is_empty() { "-".into() } else { p.default_groups.join(", ") }
                    );
                    for r in effective_rules(p) {
                        println!("    allow:       {r}");
                    }
                    println!("    notes:       {}", p.notes);
                    println!();
                }
            }
            Ok(())
        }

        Command::Allowlist { profile } => {
            let p = resolve_profile(&profile)?;
            for r in effective_rules(p) {
                println!("{r}");
            }
            Ok(())
        }

        Command::Match { profile, host, net_groups, allow } => {
            let filter = build_filter_for_match(&profile, &net_groups, &allow).await?;
            let decision = filter.decide(&host);
            println!("{}", decision.reason);
            std::process::exit(if decision.allowed { 0 } else { 1 });
        }

        Command::Proxy { allow, deny, token, port, audit } => {
            let rule = |s: &str| -> anyhow::Result<ab_proxy::HostRule> {
                ab_proxy::HostRule::parse(s).map_err(|e| anyhow::anyhow!("{e}"))
            };
            let filter = ab_proxy::HostFilter {
                allow: allow.iter().map(|a| rule(a)).collect::<Result<_, _>>()?,
                deny: deny.iter().map(|d| rule(d)).collect::<Result<_, _>>()?,
                allow_ip_literals: false,
            };
            let bound = ab_proxy::spawn(ab_proxy::ProxyConfig {
                bind_ip: std::net::IpAddr::from([127, 0, 0, 1]),
                port: port.unwrap_or(0),
                token,
                filter,
                audit_path: audit,
            })
            .await?;
            eprintln!("agentbox-proxy listening on {}", bound.addr);
            eprintln!("press Ctrl-C to stop");
            tokio::signal::ctrl_c().await.ok();
            bound.shutdown();
            Ok(())
        }
    }
}
