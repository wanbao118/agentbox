//! Hostname allow/block rules with wildcard support.

use std::net::IpAddr;

/// A single host rule: a pattern plus an optional port restriction.
///
/// Pattern forms:
/// - `api.anthropic.com` — exact match (apex included only when named).
/// - `*.anthropic.com` — any *subdomain* depth of `anthropic.com`; the bare
///   apex `anthropic.com` is NOT matched (add it explicitly when needed).
/// - `*` — anything.
///
/// Ports may be attached to either form: `host:443`, `host:80,443,8080`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostRule {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
}

impl HostRule {
    /// Parse a CLI/config rule like `*.example.com`, `host:80,443`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("empty host rule".into());
        }
        let (pattern, ports) = match input.rfind(':') {
            Some(idx) if !input[idx + 1..].is_empty() && !input[..idx].is_empty() => {
                // Do not mistake an IPv6 literal for host:port.
                let host_part = &input[..idx];
                if host_part.contains(':') && !host_part.starts_with('[') {
                    (normalize_host(input), None)
                } else {
                    let mut list = Vec::new();
                    for part in input[idx + 1..].split(',') {
                        let port: u16 = part
                            .trim()
                            .parse()
                            .map_err(|_| format!("invalid port in rule `{input}`"))?;
                        if port == 0 {
                            return Err(format!("port 0 is not allowed in rule `{input}`"));
                        }
                        list.push(port);
                    }
                    (normalize_host(host_part), Some(list))
                }
            }
            _ => (normalize_host(input), None),
        };
        if pattern.is_empty() {
            return Err(format!("rule `{input}` has an empty host"));
        }
        Ok(Self { pattern, ports })
    }

    /// Does this rule match `host` (already normalized) on `port`?
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if let Some(ports) = &self.ports {
            if !ports.contains(&port) {
                return false;
            }
        }
        match self.pattern.as_str() {
            "*" => true,
            p if p.starts_with("*.") => {
                // Subdomains only; require at least one label before the suffix.
                let suffix = &p[1..]; // ".anthropic.com"
                host.len() > suffix.len() && host.ends_with(suffix)
            }
            p => p == host,
        }
    }
}

/// Lowercase, strip one trailing dot, and unwrap `[ipv6]` brackets.
pub fn normalize_host(host: &str) -> String {
    let mut h = host.trim().to_ascii_lowercase();
    if h.starts_with('[') && h.ends_with(']') {
        h = h[1..h.len() - 1].to_string();
    }
    while h.ends_with('.') {
        h.pop();
    }
    h
}

/// True when `host` is a raw IP literal (v4 or v6).
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Outcome of evaluating an authority against a filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
}

impl Decision {
    fn allow(reason: impl Into<String>) -> Self {
        Self { allowed: true, reason: reason.into() }
    }
    fn deny(reason: impl Into<String>) -> Self {
        Self { allowed: false, reason: reason.into() }
    }
}

/// The policy engine. Deny wins over allow; deny-by-default when no allow
/// rules exist.
#[derive(Clone, Debug, Default)]
pub struct HostFilter {
    pub allow: Vec<HostRule>,
    pub deny: Vec<HostRule>,
    /// Allow IP-literal CONNECT authorities without an explicit rule.
    /// Off by default: explicit IP rules are auditable, blanket IP allowance
    /// reopens the DNS-pinning bypass.
    pub allow_ip_literals: bool,
}

impl HostFilter {
    pub fn new(allow: Vec<HostRule>, deny: Vec<HostRule>) -> Self {
        Self { allow, deny, allow_ip_literals: false }
    }

    /// Decide for `authority` — either `host` or `host:port` (CONNECT form).
    pub fn decide(&self, authority: &str) -> Decision {
        let (host, port) = match split_authority(authority) {
            Ok(v) => v,
            Err(e) => return Decision::deny(e),
        };
        self.decide_hp(&host, port)
    }

    /// Decide for an already-split host + port.
    pub fn decide_hp(&self, host: &str, port: u16) -> Decision {
        let host = normalize_host(host);

        for rule in &self.deny {
            if rule.matches(&host, port) {
                return Decision::deny(format!("matched deny rule `{}`", rule.pattern));
            }
        }

        if is_ip_literal(&host) {
            // An explicit allow rule can still name the exact IP.
            for rule in &self.allow {
                if rule.matches(&host, port) {
                    return Decision::allow(format!("explicit ip rule `{}`", rule.pattern));
                }
            }
            if self.allow_ip_literals {
                return Decision::allow("ip literals permitted by configuration");
            }
            return Decision::deny(
                "ip-literal destinations are blocked; allowlist hostnames instead",
            );
        }

        if self.allow.is_empty() {
            return Decision::deny("no allow rules configured (deny-by-default)");
        }
        for rule in &self.allow {
            if rule.matches(&host, port) {
                return Decision::allow(format!("matched allow rule `{}`", rule.pattern));
            }
        }
        Decision::deny("no allow rule matched")
    }
}

/// Split `host:port`, tolerating `[v6]:port` and defaulting the port.
pub(crate) fn split_authority(authority: &str) -> Result<(String, u16), String> {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        // [v6]:port or [v6]
        let close = rest.find(']').ok_or("unbalanced ipv6 authority")?;
        let host = normalize_host(&rest[..close]);
        if host.parse::<IpAddr>().is_err() {
            return Err(format!("invalid ipv6 authority `{a}`"));
        }
        let port = rest[close + 1..]
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|_| "invalid port".to_string()))
            .transpose()?
            .unwrap_or(443);
        return Ok((host, port));
    }
    match a.rfind(':') {
        Some(idx) => {
            let host = normalize_host(&a[..idx]);
            let port: u16 = a[idx + 1..]
                .parse()
                .map_err(|_| format!("invalid port in authority `{a}`"))?;
            if port == 0 {
                return Err(format!("invalid port 0 in authority `{a}`"));
            }
            // A second colon means this was a bare ipv6 literal; re-parse whole.
            if host.contains(':') {
                let h = normalize_host(a);
                h.parse::<IpAddr>()
                    .map_err(|_| format!("invalid ipv6 authority `{a}`"))?;
                return Ok((h, 443));
            }
            Ok((host, port))
        }
        None => Ok((normalize_host(a), 443)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_and_wildcard() {
        let r = HostRule::parse("api.anthropic.com").unwrap();
        assert_eq!(r.pattern, "api.anthropic.com");
        assert!(r.ports.is_none());

        let r = HostRule::parse("*.Anthropic.COM.").unwrap();
        assert_eq!(r.pattern, "*.anthropic.com");
    }

    #[test]
    fn parse_with_ports() {
        let r = HostRule::parse("localhost:3000").unwrap();
        assert_eq!(r.ports, Some(vec![3000]));
        let r = HostRule::parse("dev.local:80,443,8080").unwrap();
        assert_eq!(r.ports, Some(vec![80, 443, 8080]));
        assert!(HostRule::parse("host:0").is_err());
        assert!(HostRule::parse("").is_err());
        assert!(HostRule::parse("host:abc").is_err());
    }

    #[test]
    fn wildcard_requires_subdomain() {
        let r = HostRule::parse("*.anthropic.com").unwrap();
        assert!(r.matches("api.anthropic.com", 443));
        assert!(r.matches("statsig.anthropic.com", 443));
        assert!(r.matches("deep.a.b.anthropic.com", 8443));
        assert!(!r.matches("anthropic.com", 443)); // apex not covered
        assert!(!r.matches("notanthropic.com", 443));
        assert!(!r.matches("anthropic.com.evil.io", 443));
    }

    #[test]
    fn port_restriction_applies() {
        let r = HostRule::parse("web.local:80,443").unwrap();
        assert!(r.matches("web.local", 443));
        assert!(r.matches("web.local", 80));
        assert!(!r.matches("web.local", 8080));
    }

    #[test]
    fn normalization_forms() {
        assert_eq!(normalize_host("API.Example.com."), "api.example.com");
        assert_eq!(normalize_host("[2001:DB8::1]"), "2001:db8::1");
    }

    #[test]
    fn deny_by_default_and_deny_overrides_allow() {
        let f = HostFilter::default();
        assert!(!f.decide("example.com").allowed);

        let f = HostFilter::new(
            vec![HostRule::parse("*.ok.io").unwrap()],
            vec![HostRule::parse("bad.ok.io").unwrap()],
        );
        assert!(f.decide("a.ok.io:443").allowed);
        assert!(!f.decide("bad.ok.io:443").allowed);
        assert!(!f.decide("ok.io").allowed); // apex unmatched by wildcard
    }

    #[test]
    fn ip_literals_blocked_unless_explicit() {
        let f = HostFilter::new(vec![HostRule::parse("*.ok.io").unwrap()], vec![]);
        assert!(!f.decide("1.2.3.4:443").allowed);

        let f = HostFilter::new(
            vec![
                HostRule::parse("10.0.2.2").unwrap(),
                HostRule::parse("*.ok.io").unwrap(),
            ],
            vec![],
        );
        assert!(f.decide("10.0.2.2:443").allowed);
        assert!(!f.decide("10.0.2.3:443").allowed);
    }

    #[test]
    fn ipv6_authority_splitting() {
        assert_eq!(
            split_authority("[::1]:8443").unwrap(),
            ("::1".to_string(), 8443)
        );
        assert_eq!(split_authority("[::1]").unwrap(), ("::1".to_string(), 443));
        assert_eq!(
            split_authority("2001:db8::1").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
        assert_eq!(
            split_authority("example.com:8080").unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            split_authority("Example.COM").unwrap(),
            ("example.com".to_string(), 443)
        );
    }
}
