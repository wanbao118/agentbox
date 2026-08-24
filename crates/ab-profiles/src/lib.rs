//! Built-in profiles for popular coding agents.
//!
//! A profile bundles three things the runtime needs:
//! 1. **Filesystem posture** — which dot-directories under `$HOME` hold agent
//!    config/login state (snapshotted into a scratch HOME by default).
//! 2. **Credentials** — environment variables worth forwarding into the
//!    sandbox when present on the host.
//! 3. **Network baseline** — hostname rules the agent minimally needs, plus
//!    named opt-in groups (package registries, telemetry, git hosting).
//!
//! Baselines are intentionally *minimal*. Anything missing shows up instantly
//! in the proxy audit log and can be added per-run with `--allow`.

/// Where an agent keeps state under the user's real `$HOME`.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct HomeSpec {
    /// Path relative to `$HOME`; may be a directory or a file.
    pub rel: &'static str,
    /// When false, absence is normal and not reported by `doctor`.
    pub optional: bool,
}

/// Named network rule groups a run can opt into via `--net-preset`.
pub const GROUP_PACKAGES: &[&str] = &[
    "registry.npmjs.org",
    "*.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "rubygems.org",
];

pub const GROUP_TELEMETRY: &[&str] = &[
    "statsig.com",
    "*.statsig.com",
    "statsigapi.net",
    "*.statsigapi.net",
    "sentry.io",
    "*.sentry.io",
];

pub const GROUP_GIT: &[&str] = &[
    "github.com",
    "*.github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "githubusercontent.com",
    "*.githubusercontent.com",
    "gitlab.com",
    "*.gitlab.com",
];

pub const GROUP_AI_PROVIDER_ANTHROPIC: &[&str] =
    &["anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai"];

pub const GROUP_AI_PROVIDER_OPENAI: &[&str] =
    &["openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"];

pub const GROUP_AI_PROVIDER_GOOGLE: &[&str] = &[
    "googleapis.com",
    "*.googleapis.com",
    "accounts.google.com",
    "gstatic.com",
    "*.gstatic.com",
];

pub const GROUP_AI_PROVIDER_OPENROUTER: &[&str] =
    &["openrouter.ai", "*.openrouter.ai"];

/// A complete agent profile.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct AgentProfile {
    pub id: &'static str,
    pub display: &'static str,
    /// Executable names searched in PATH.
    pub binaries: &'static [&'static str],
    pub home_specs: &'static [HomeSpec],
    /// Environment variables forwarded when present on the host.
    pub secrets_env: &'static [&'static str],
    /// Baseline network allowlist (always applied).
    pub net_allow: &'static [&'static str],
    /// Groups recommended by default for this agent (`--net-preset base`
    /// still applies them; use `--no-default-groups` to trim further).
    pub default_groups: &'static [&'static str],
    /// Extra writable paths the agent hardcodes (outside HOME/workspace).
    /// `{uid}` expands to the host user id at session start.
    pub extra_rw: &'static [&'static str],
    pub notes: &'static str,
}

const ANTHROPIC_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_OAUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "API_TIMEOUT_MS",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

pub const CLAUDE_CODE: AgentProfile = AgentProfile {
    id: "claude-code",
    display: "Claude Code (Anthropic)",
    binaries: &["claude"],
    home_specs: &[HomeSpec { rel: ".claude", optional: false }],
    secrets_env: ANTHROPIC_ENV,
    net_allow: &[
        "api.anthropic.com",
        "*.anthropic.com",
        "claude.ai",
        "*.claude.ai",
    ],
    default_groups: &["telemetry"],
    extra_rw: &["/tmp/claude-{uid}"],
    notes: "OAuth login state lives in ~/.claude; keychain-backed logins also \
            need --keychain on macOS. Bedrock mode additionally needs the AWS_* vars.",
};

pub const CODEX: AgentProfile = AgentProfile {
    id: "codex",
    display: "Codex CLI (OpenAI)",
    binaries: &["codex"],
    home_specs: &[HomeSpec { rel: ".codex", optional: false }],
    secrets_env: &[
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "CODEX_HOME",
        "AZURE_OPENAI_API_KEY",
        "OPENAI_AZURE_ENDPOINT",
    ],
    net_allow: &[
        "chatgpt.com",
        "*.chatgpt.com",
        "auth.openai.com",
        "api.openai.com",
        "*.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
    ],
    default_groups: &[],
    extra_rw: &[],
    notes: "Login state lives in ~/.codex/auth.json. ChatGPT-plan auth refreshes \
            against auth.openai.com; keep it allowlisted even with API keys.",
};

pub const GEMINI: AgentProfile = AgentProfile {
    id: "gemini",
    display: "Gemini CLI (Google)",
    binaries: &["gemini"],
    home_specs: &[HomeSpec { rel: ".gemini", optional: false }],
    secrets_env: &[
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ],
    net_allow: &[
        "cloudcode-pa.googleapis.com",
        "generativelanguage.googleapis.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "accounts.google.com",
    ],
    default_groups: &[],
    extra_rw: &[],
    notes: "OAuth flow opens accounts.google.com in the HOST browser; the sandbox \
            only needs the API endpoints. Vertex AI mode needs GOOGLE_CLOUD_* vars.",
};

pub const AIDER: AgentProfile = AgentProfile {
    id: "aider",
    display: "Aider",
    binaries: &["aider"],
    home_specs: &[
        HomeSpec { rel: ".aider", optional: true },
        HomeSpec { rel: ".aider.conf.yml", optional: true },
    ],
    secrets_env: &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "OLLAMA_API_BASE",
        "AZURE_API_VERSION",
        "AZURE_API_KEY",
        "AZURE_ENDPOINT",
    ],
    net_allow: &[
        "api.deepseek.com",
        "deepseek.com",
        "*.deepseek.com",
    ],
    default_groups: &["packages-pip"],
    extra_rw: &[],
    notes: "Provider endpoints depend on the configured model; the union of common \
            providers is covered across net_allow + groups. Aider pip-installs \
            updates from PyPI.",
};

pub const OPENCODE: AgentProfile = AgentProfile {
    id: "opencode",
    display: "OpenCode",
    binaries: &["opencode"],
    home_specs: &[
        HomeSpec { rel: ".local/share/opencode", optional: false },
        HomeSpec { rel: ".config/opencode", optional: true },
    ],
    secrets_env: &[
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "XAI_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "DEEPSEEK_API_KEY",
    ],
    net_allow: &[
        "models.dev",
        "*.models.dev",
        "opencode.ai",
        "*.opencode.ai",
        "openrouter.ai",
        "*.openrouter.ai",
        "api.deepseek.com",
        "*.deepseek.com",
        "groq.com",
        "*.groq.com",
        "mistral.ai",
        "*.mistral.ai",
        "api.x.ai",
    ],
    default_groups: &[],
    extra_rw: &[],
    notes: "Model catalog is fetched from models.dev at startup; without it the \
            TUI degrades. Provider set is broad because opencode is multi-provider.",
};

/// Generic escape hatch: run any command under the same enforcement.
pub const SHELL: AgentProfile = AgentProfile {
    id: "shell",
    display: "Generic shell (no agent assumptions)",
    binaries: &["bash"],
    home_specs: &[],
    secrets_env: &[],
    net_allow: &[],
    default_groups: &[],
    extra_rw: &[],
    notes: "Nothing is allowlisted by default — pass --allow rules explicitly. \
            Useful for verification and for agents without a dedicated profile.",
};

/// All built-in profiles, in presentation order.
pub const PROFILES: &[AgentProfile] =
    &[CLAUDE_CODE, CODEX, GEMINI, AIDER, OPENCODE, SHELL];

/// Look up a profile by id.
pub fn get(id: &str) -> Option<&'static AgentProfile> {
    PROFILES.iter().find(|p| p.id == id)
}

/// Resolve a group name to its rules. Unknown names yield `None`.
pub fn group(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "packages" => Some(GROUP_PACKAGES),
        "packages-pip" => Some(&["pypi.org", "files.pythonhosted.org"]),
        "packages-npm" => Some(&["registry.npmjs.org", "*.npmjs.org"]),
        "packages-cargo" => Some(&["crates.io", "static.crates.io", "index.crates.io"]),
        "telemetry" => Some(GROUP_TELEMETRY),
        "git" => Some(GROUP_GIT),
        "anthropic" => Some(GROUP_AI_PROVIDER_ANTHROPIC),
        "openai" => Some(GROUP_AI_PROVIDER_OPENAI),
        "google" => Some(GROUP_AI_PROVIDER_GOOGLE),
        "openrouter" => Some(GROUP_AI_PROVIDER_OPENROUTER),
        _ => None,
    }
}

/// All effective baseline + default-group rules for a profile.
pub fn effective_rules(profile: &AgentProfile) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = profile.net_allow.to_vec();
    for g in profile.default_groups {
        if let Some(rules) = group(g) {
            out.extend_from_slice(rules);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ab_proxy::HostRule;

    #[test]
    fn unique_ids() {
        let mut ids: Vec<_> = PROFILES.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), PROFILES.len());
    }

    #[test]
    fn all_rules_parse() {
        for p in PROFILES {
            for r in p.net_allow {
                HostRule::parse(r).unwrap_or_else(|e| panic!("{p:?} rule `{r}`: {e}"));
            }
            for g in p.default_groups {
                assert!(group(g).is_some(), "{p:?} unknown group {g}");
            }
            for s in p.secrets_env {
                assert!(s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
            }
        }
        for g in ["packages", "packages-pip", "packages-npm", "packages-cargo", "git"] {
            assert!(group(g).is_some());
        }
        assert!(group("nope").is_none());
    }

    #[test]
    fn lookup_works() {
        assert!(get("claude-code").is_some());
        assert!(get("nope").is_none());
    }

    #[test]
    fn effective_rules_nonempty() {
        for p in PROFILES {
            // The generic shell profile is intentionally deny-all with an
            // empty baseline.
            if p.id == "shell" {
                continue;
            }
            assert!(!effective_rules(p).is_empty(), "{}", p.id);
        }
    }
}
