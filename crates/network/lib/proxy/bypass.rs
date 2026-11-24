//! Destinations that skip the outbound proxy.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Longest host name accepted in a rule (RFC 1035, without the root dot).
const MAX_HOST_NAME_LEN: usize = 253;

/// Longest label accepted in a rule's host name.
const MAX_LABEL_LEN: usize = 63;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destinations the sandbox reaches directly even when an outbound proxy is
/// configured, in the spirit of `NO_PROXY`.
///
/// Each rule is written as one of:
///
/// - `*`: every destination.
/// - an IP address (`10.1.2.3`, `2001:db8::1` or `[2001:db8::1]`).
/// - a CIDR range (`10.0.0.0/8`, `fd00::/8`).
/// - a host name (`corp.example`, `.corp.example` or `*.corp.example`), which
///   matches the name and every subdomain of it.
///
/// Ports are not part of a rule. The list serializes as an array of these
/// strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyBypass {
    rules: Vec<ProxyBypassRule>,
}

/// One [`ProxyBypass`] rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyBypassRule {
    /// Every destination.
    All,
    /// One IP address.
    Ip(IpAddr),
    /// A CIDR range.
    Network(IpNetwork),
    /// A host name (lowercase, no leading or trailing dot) and its subdomains.
    Domain(String),
}

/// Error returned when a bypass rule is not `*`, an IP, a CIDR range or a host name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid proxy bypass rule {rule:?}: {reason}")]
pub struct ProxyBypassParseError {
    rule: String,
    reason: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyBypass {
    /// Parses each rule in `rules`.
    pub fn parse<I, S>(rules: I) -> Result<Self, ProxyBypassParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        rules
            .into_iter()
            .map(|rule| rule.as_ref().parse())
            .collect::<Result<_, _>>()
            .map(|rules| Self { rules })
    }

    /// Whether the list has no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules in the order they were written.
    pub fn rules(&self) -> &[ProxyBypassRule] {
        &self.rules
    }

    /// Whether a connection to `ip` skips the proxy by address.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.rules.iter().any(|rule| match rule {
            ProxyBypassRule::All => true,
            ProxyBypassRule::Ip(rule) => *rule == ip,
            ProxyBypassRule::Network(network) => network.contains(ip),
            ProxyBypassRule::Domain(_) => false,
        })
    }

    /// Whether a connection to the host `name` skips the proxy by name.
    pub fn matches_name(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.');
        self.rules.iter().any(|rule| match rule {
            ProxyBypassRule::All => true,
            ProxyBypassRule::Domain(domain) => {
                name.eq_ignore_ascii_case(domain)
                    || (name.len() > domain.len()
                        && name.as_bytes()[name.len() - domain.len() - 1] == b'.'
                        && name[name.len() - domain.len()..].eq_ignore_ascii_case(domain))
            }
            ProxyBypassRule::Ip(_) | ProxyBypassRule::Network(_) => false,
        })
    }
}

impl ProxyBypassParseError {
    fn new(rule: &str, reason: &'static str) -> Self {
        Self {
            rule: rule.to_string(),
            reason,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for ProxyBypassRule {
    type Err = ProxyBypassParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let rule = raw.trim();
        if rule.is_empty() {
            return Err(ProxyBypassParseError::new(raw, "the rule is empty"));
        }
        if rule == "*" {
            return Ok(Self::All);
        }
        let unbracketed = rule
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(rule);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Self::Ip(canonical_ip(ip)));
        }
        if rule.contains('/') {
            return rule
                .parse::<IpNetwork>()
                .map(|network| Self::Network(canonical_network(network)))
                .map_err(|_| ProxyBypassParseError::new(raw, "expected a CIDR range"));
        }
        if rule.contains(':') || rule.contains('[') {
            return Err(ProxyBypassParseError::new(
                raw,
                "ports are not supported; write a host name, IP address or CIDR range",
            ));
        }
        let domain = rule
            .strip_prefix("*.")
            .or_else(|| rule.strip_prefix('.'))
            .unwrap_or(rule)
            .trim_end_matches('.');
        if !is_host_name(domain) {
            return Err(ProxyBypassParseError::new(
                raw,
                "a host name must be dot-separated labels of letters, digits, hyphens and underscores",
            ));
        }
        Ok(Self::Domain(domain.to_ascii_lowercase()))
    }
}

impl fmt::Display for ProxyBypassRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Network(network) => write!(f, "{network}"),
            Self::Domain(domain) => f.write_str(domain),
        }
    }
}

impl Serialize for ProxyBypass {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.rules.iter().map(ToString::to_string))
    }
}

impl<'de> Deserialize<'de> for ProxyBypass {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rules = Vec::<String>::deserialize(deserializer)?;
        Self::parse(rules).map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// An IPv4-mapped IPv6 address is compared as the IPv4 address.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// A range is stored by its network address, so `10.1.2.3/8` reads back as `10.0.0.0/8`.
fn canonical_network(network: IpNetwork) -> IpNetwork {
    IpNetwork::new(network.network(), network.prefix()).unwrap_or(network)
}

fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_NAME_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass(rules: &[&str]) -> ProxyBypass {
        ProxyBypass::parse(rules).unwrap()
    }

    #[test]
    fn parses_each_rule_form() {
        let parsed = bypass(&[
            "*",
            "10.1.2.3",
            "[2001:db8::1]",
            "::ffff:192.0.2.9",
            "10.1.2.3/8",
            "fd00::/8",
            "Corp.Example",
            ".svc.example",
            "*.internal.example.",
            "_srv.example",
            " spaced.example ",
        ]);
        let text: Vec<String> = parsed.rules().iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            [
                "*",
                "10.1.2.3",
                "2001:db8::1",
                "192.0.2.9",
                "10.0.0.0/8",
                "fd00::/8",
                "corp.example",
                "svc.example",
                "internal.example",
                "_srv.example",
                "spaced.example",
            ]
        );
    }

    #[test]
    fn rejects_malformed_rules() {
        for rule in [
            "",
            "   ",
            "corp.example:443",
            "10.0.0.1:80",
            "[2001:db8::1]:443",
            "10.0.0.0/33",
            "fd00::/129",
            "corp.example/24",
            "a..b",
            "**.example",
            "*example",
            "exa mple.com",
            "user@example.com",
            "ex\u{e4}mple.com",
            "corp\r\n.example",
        ] {
            assert!(
                rule.parse::<ProxyBypassRule>().is_err(),
                "{rule:?} was accepted"
            );
        }
    }

    #[test]
    fn domains_match_themselves_and_subdomains_only() {
        let rules = bypass(&["corp.example", "*.svc.example"]);
        for name in [
            "corp.example",
            "CORP.example.",
            "git.corp.example",
            "a.b.corp.example",
            "svc.example",
            "api.svc.example",
        ] {
            assert!(rules.matches_name(name), "{name} not bypassed");
        }
        for name in [
            "evilcorp.example",
            "corp.example.attacker.test",
            "example",
            "orp.example",
            "svc.example.com",
        ] {
            assert!(!rules.matches_name(name), "{name} bypassed");
        }
        assert!(!rules.matches_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn addresses_match_exact_ips_and_ranges() {
        let rules = bypass(&["192.0.2.7", "10.0.0.0/8", "fd00::/8"]);
        for ip in [
            "192.0.2.7",
            "10.200.1.1",
            "fd12::3",
            "::ffff:10.1.1.1",
            "::ffff:192.0.2.7",
        ] {
            assert!(rules.matches_ip(ip.parse().unwrap()), "{ip} not bypassed");
        }
        for ip in ["192.0.2.8", "11.0.0.1", "fe80::1", "2001:db8::1"] {
            assert!(!rules.matches_ip(ip.parse().unwrap()), "{ip} bypassed");
        }
        assert!(!rules.matches_name("10.200.1.1"));
    }

    #[test]
    fn star_bypasses_everything_and_empty_bypasses_nothing() {
        let all = bypass(&["*"]);
        assert!(all.matches_ip("203.0.113.1".parse().unwrap()));
        assert!(all.matches_name("anything.example"));
        let none = ProxyBypass::default();
        assert!(none.is_empty());
        assert!(!none.matches_ip("203.0.113.1".parse().unwrap()));
        assert!(!none.matches_name("anything.example"));
    }

    #[cfg(feature = "engine")]
    #[test]
    fn serializes_as_a_list_of_rule_strings() {
        let rules = bypass(&["Corp.Example", "10.0.0.0/8", "*"]);
        let value = serde_json::to_value(&rules).unwrap();
        assert_eq!(
            value,
            serde_json::json!(["corp.example", "10.0.0.0/8", "*"])
        );
        assert_eq!(serde_json::from_value::<ProxyBypass>(value).unwrap(), rules);
        let error = serde_json::from_value::<ProxyBypass>(serde_json::json!(["ok.example", "x:1"]))
            .unwrap_err();
        assert!(error.to_string().contains("\"x:1\""), "{error}");
    }
}
