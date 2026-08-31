//! Credential injection engine for the enforcing proxy.
//!
//! Maps destination host patterns to credentials that the proxy injects into
//! outbound requests.  The sandbox never sees the actual secret — the proxy
//! reads it from the host environment at startup and inserts the corresponding
//! header transparently.

/// How to obtain the secret value for a credential rule.
#[derive(Clone, Debug)]
pub enum CredentialSource {
    /// Read from a host environment variable at proxy startup.
    Env(String),
}

/// A single credential-injection rule: when a request matches `host_pattern`
/// (+ optional `ports`), the proxy strips any existing `header_name` from the
/// client request and injects `header_value_prefix` + resolved secret.
#[derive(Clone, Debug)]
pub struct CredentialRule {
    /// Host pattern — same semantics as [`crate::HostRule`]:
    /// - `api.anthropic.com` — exact match
    /// - `*.anthropic.com` — any subdomain (not bare apex)
    /// - `*` — catch-all
    pub host_pattern: String,
    /// Optional port restriction (empty = any port).
    pub ports: Option<Vec<u16>>,
    /// Header to inject, e.g. `"authorization"` (always lowercase).
    pub header_name: String,
    /// Prefix prepended to the resolved secret, e.g. `"Bearer "`.
    /// The full header value becomes `{prefix}{secret}`.
    pub header_value_prefix: String,
    /// Where the secret comes from.
    pub source: CredentialSource,
}

/// Result of looking up a credential for a specific request.
#[derive(Debug, Clone)]
pub struct CredentialMatch<'a> {
    pub header_name: &'a str,
    /// The fully assembled header value, e.g. `"Bearer sk-ant-..."`.
    pub header_value: String,
}

/// The credential injection engine.  Built once per proxy session from profile
/// defaults + CLI overrides; all env-var sources are resolved eagerly.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    rules: Vec<CredentialRule>,
    /// Pre-resolved header values (index-aligned with `rules`).
    resolved: Vec<String>,
}

impl CredentialStore {
    /// Build a store, resolving all [`CredentialSource::Env`] values from the
    /// current host process environment.  Missing env vars produce an empty
    /// string (the rule still matches but injects an obviously-wrong header,
    /// which the upstream will reject — safer than silently skipping).
    pub fn new(rules: Vec<CredentialRule>) -> Self {
        let resolved: Vec<String> = rules
            .iter()
            .map(|r| {
                let secret = match &r.source {
                    CredentialSource::Env(name) => {
                        std::env::var(name).unwrap_or_default()
                    }
                };
                format!("{}{}", r.header_value_prefix, secret)
            })
            .collect();
        Self { rules, resolved }
    }

    /// Returns `true` when a credential rule matches `host:port`.
    pub fn has_rule_for(&self, host: &str, port: u16) -> bool {
        self.find_index(host, port).is_some()
    }

    /// Look up the credential to inject for `host:port`.
    pub fn find_injection(&self, host: &str, port: u16) -> Option<CredentialMatch<'_>> {
        let idx = self.find_index(host, port)?;
        let rule = &self.rules[idx];
        Some(CredentialMatch {
            header_name: &rule.header_name,
            header_value: self.resolved[idx].clone(),
        })
    }

    /// All rules in this store (for diagnostics / `profiles --verbose`).
    pub fn rules(&self) -> &[CredentialRule] {
        &self.rules
    }

    /// Whether this store has any rules at all.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    // ---- internal --------------------------------------------------------

    fn find_index(&self, host: &str, port: u16) -> Option<usize> {
        self.rules.iter().position(|r| rule_matches(r, host, port))
    }
}

/// Does a single rule match the given host + port?
fn rule_matches(rule: &CredentialRule, host: &str, port: u16) -> bool {
    if let Some(ports) = &rule.ports {
        if !ports.contains(&port) {
            return false;
        }
    }
    match rule.host_pattern.as_str() {
        "*" => true,
        p if p.starts_with("*.") => {
            let suffix = &p[1..]; // ".anthropic.com"
            host.len() > suffix.len() && host.ends_with(suffix)
        }
        p => p == host,
    }
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, ports: Option<Vec<u16>>) -> CredentialRule {
        CredentialRule {
            host_pattern: pattern.into(),
            ports,
            header_name: "authorization".into(),
            header_value_prefix: "Bearer ".into(),
            source: CredentialSource::Env("TEST_KEY".into()),
        }
    }

    #[test]
    fn exact_match() {
        let r = rule("api.anthropic.com", None);
        assert!(rule_matches(&r, "api.anthropic.com", 443));
        assert!(!rule_matches(&r, "other.com", 443));
    }

    #[test]
    fn wildcard_subdomain() {
        let r = rule("*.anthropic.com", None);
        assert!(rule_matches(&r, "api.anthropic.com", 443));
        assert!(rule_matches(&r, "deep.a.anthropic.com", 80));
        assert!(!rule_matches(&r, "anthropic.com", 443)); // apex not matched
        assert!(!rule_matches(&r, "notanthropic.com", 443));
    }

    #[test]
    fn catch_all() {
        let r = rule("*", None);
        assert!(rule_matches(&r, "anything.io", 12345));
    }

    #[test]
    fn port_restriction() {
        let r = rule("api.openai.com", Some(vec![80, 443]));
        assert!(rule_matches(&r, "api.openai.com", 443));
        assert!(rule_matches(&r, "api.openai.com", 80));
        assert!(!rule_matches(&r, "api.openai.com", 8080));
    }

    #[test]
    fn store_resolve_from_env() {
        std::env::set_var("TEST_INJECT_KEY", "sk-test-12345");
        let rules = vec![CredentialRule {
            host_pattern: "*.anthropic.com".into(),
            ports: None,
            header_name: "authorization".into(),
            header_value_prefix: "Bearer ".into(),
            source: CredentialSource::Env("TEST_INJECT_KEY".into()),
        }];
        let store = CredentialStore::new(rules);

        let m = store.find_injection("api.anthropic.com", 443).unwrap();
        assert_eq!(m.header_name, "authorization");
        assert_eq!(m.header_value, "Bearer sk-test-12345");

        assert!(store.has_rule_for("api.anthropic.com", 443));
        assert!(!store.has_rule_for("other.com", 443));

        std::env::remove_var("TEST_INJECT_KEY");
    }

    #[test]
    fn store_missing_env_yields_empty() {
        let rules = vec![rule("*.example.com", None)];
        let store = CredentialStore::new(rules);
        let m = store.find_injection("api.example.com", 443).unwrap();
        assert_eq!(m.header_value, "Bearer "); // empty secret
    }

    #[test]
    fn store_multiple_rules_first_match_wins() {
        std::env::set_var("KEY_A", "aaa");
        std::env::set_var("KEY_B", "bbb");
        let rules = vec![
            CredentialRule {
                host_pattern: "api.anthropic.com".into(),
                ports: None,
                header_name: "x-api-key".into(),
                header_value_prefix: "".into(),
                source: CredentialSource::Env("KEY_A".into()),
            },
            CredentialRule {
                host_pattern: "*.anthropic.com".into(),
                ports: None,
                header_name: "authorization".into(),
                header_value_prefix: "Bearer ".into(),
                source: CredentialSource::Env("KEY_B".into()),
            },
        ];
        let store = CredentialStore::new(rules);

        // Exact match wins over wildcard
        let m = store.find_injection("api.anthropic.com", 443).unwrap();
        assert_eq!(m.header_name, "x-api-key");
        assert_eq!(m.header_value, "aaa");

        // Wildcard matches the rest
        let m = store.find_injection("other.anthropic.com", 443).unwrap();
        assert_eq!(m.header_name, "authorization");
        assert_eq!(m.header_value, "Bearer bbb");

        std::env::remove_var("KEY_A");
        std::env::remove_var("KEY_B");
    }

    #[test]
    fn empty_store_matches_nothing() {
        let store = CredentialStore::new(vec![]);
        assert!(store.is_empty());
        assert!(!store.has_rule_for("anything.io", 443));
    }
}
