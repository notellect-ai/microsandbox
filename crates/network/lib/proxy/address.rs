//! Outbound proxy endpoint addresses.

use std::fmt;
#[cfg(feature = "engine")]
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "engine")]
use tokio::net::TcpStream;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Longest host name accepted for a proxy endpoint (RFC 1035, without the root dot).
const MAX_HOST_NAME_LEN: usize = 253;

/// Longest label accepted in a proxy host name.
const MAX_LABEL_LEN: usize = 63;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Where an outbound proxy listens: an IP socket address, or a host name and
/// port that the host's resolver looks up each time a connection is opened.
///
/// It is written as `IP:PORT`, `[IPv6]:PORT` or `HOST:PORT`, and serialized
/// as that string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyAddress {
    /// An IP socket address.
    Socket(SocketAddr),
    /// A host name (lowercase ASCII, no trailing dot) and port.
    Host {
        /// Host name, resolved when a connection is opened.
        name: String,
        /// Proxy port.
        port: u16,
    },
}

/// Error returned when a proxy address is neither `IP:PORT` nor `HOST:PORT`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct ProxyAddressParseError {
    reason: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyAddress {
    /// Opens a TCP connection to the proxy. A host name is resolved now, and
    /// its addresses are tried in the resolver's order.
    #[cfg(feature = "engine")]
    pub(crate) async fn connect(&self) -> io::Result<TcpStream> {
        match self {
            Self::Socket(address) => TcpStream::connect(address).await,
            Self::Host { name, port } => {
                TcpStream::connect((name.as_str(), *port))
                    .await
                    .map_err(|error| {
                        io::Error::new(error.kind(), format!("proxy {name}:{port}: {error}"))
                    })
            }
        }
    }
}

impl ProxyAddressParseError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<SocketAddr> for ProxyAddress {
    fn from(address: SocketAddr) -> Self {
        Self::Socket(address)
    }
}

impl FromStr for ProxyAddress {
    type Err = ProxyAddressParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = raw.parse::<SocketAddr>() {
            return Ok(Self::Socket(address));
        }
        let (name, port) = raw
            .rsplit_once(':')
            .ok_or_else(|| ProxyAddressParseError::new("expected IP:PORT or HOST:PORT"))?;
        let port = parse_port(port)?;
        if name.starts_with('[') || name.contains(':') {
            return Err(ProxyAddressParseError::new(
                "invalid IPv6 address; write it as [IPv6]:PORT",
            ));
        }
        validate_host_name(name)?;
        Ok(Self::Host {
            name: name.to_ascii_lowercase(),
            port,
        })
    }
}

impl fmt::Display for ProxyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(address) => write!(f, "{address}"),
            Self::Host { name, port } => write!(f, "{name}:{port}"),
        }
    }
}

impl Serialize for ProxyAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProxyAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn parse_port(raw: &str) -> Result<u16, ProxyAddressParseError> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProxyAddressParseError::new(
            "the port must be a decimal number",
        ));
    }
    match raw.parse::<u16>() {
        Ok(0) | Err(_) => Err(ProxyAddressParseError::new(
            "the port must be between 1 and 65535",
        )),
        Ok(port) => Ok(port),
    }
}

/// Accepts a DNS host name of letters, digits and hyphens (RFC 1123 labels).
/// An all-numeric last label is refused, so a mistyped IPv4 address is
/// reported rather than looked up as a name.
fn validate_host_name(name: &str) -> Result<(), ProxyAddressParseError> {
    if name.is_empty() {
        return Err(ProxyAddressParseError::new("the host name is empty"));
    }
    if name.len() > MAX_HOST_NAME_LEN {
        return Err(ProxyAddressParseError::new("the host name is too long"));
    }
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        if !valid {
            return Err(ProxyAddressParseError::new(
                "the host name must be dot-separated labels of letters, digits and hyphens",
            ));
        }
    }
    if name
        .rsplit('.')
        .next()
        .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ProxyAddressParseError::new("invalid IPv4 address"));
    }
    Ok(())
}

/// Whether `name` can be sent to an outbound proxy as a destination host
/// (HTTP CONNECT authority, SOCKS5 domain): lowercase-insensitive DNS labels
/// of letters, digits, hyphens and underscores, no trailing dot.
#[cfg(feature = "engine")]
pub(crate) fn is_destination_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_NAME_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        && name.parse::<std::net::IpAddr>().is_err()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socket_addresses_and_host_names() {
        let cases = [
            (
                "127.0.0.1:3128",
                ProxyAddress::Socket("127.0.0.1:3128".parse().unwrap()),
            ),
            (
                "[2001:db8::1]:8080",
                ProxyAddress::Socket("[2001:db8::1]:8080".parse().unwrap()),
            ),
            (
                "proxy.corp.example:8080",
                ProxyAddress::Host {
                    name: "proxy.corp.example".into(),
                    port: 8080,
                },
            ),
            (
                "Proxy-1.CORP.example:3128",
                ProxyAddress::Host {
                    name: "proxy-1.corp.example".into(),
                    port: 3128,
                },
            ),
            (
                "localhost:1080",
                ProxyAddress::Host {
                    name: "localhost".into(),
                    port: 1080,
                },
            ),
            (
                "1proxy.example:65535",
                ProxyAddress::Host {
                    name: "1proxy.example".into(),
                    port: 65535,
                },
            ),
        ];
        for (raw, want) in cases {
            let parsed: ProxyAddress = raw.parse().unwrap_or_else(|error| panic!("{raw}: {error}"));
            assert_eq!(parsed, want, "{raw}");
            // The text form round-trips (host names are lowercased).
            assert_eq!(parsed.to_string().parse::<ProxyAddress>().unwrap(), want);
        }
    }

    #[test]
    fn rejects_malformed_addresses() {
        let long_label = format!("{}.example:80", "a".repeat(64));
        let long_name = format!("{}example:80", "abcdefghi.".repeat(25));
        for raw in [
            "",
            "proxy.example",
            "proxy.example:",
            ":3128",
            "proxy.example:0",
            "proxy.example:65536",
            "proxy.example:+80",
            "proxy.example: 80",
            "proxy.example:80 ",
            "proxy..example:80",
            ".proxy.example:80",
            "proxy.example.:80",
            "-proxy.example:80",
            "proxy-.example:80",
            "proxy_1.example:80",
            "pröxy.example:80",
            "user@proxy.example:80",
            "proxy.example/path:80",
            "proxy example:80",
            "2001:db8::1:80",
            "[2001:db8::1:80",
            "[proxy.example]:80",
            "256.1.1.1:80",
            "10.0.0:80",
            "proxy.123:80",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(raw.parse::<ProxyAddress>().is_err(), "{raw:?} was accepted");
        }
    }

    #[test]
    fn serializes_as_a_string_compatible_with_socket_addresses() {
        let socket: SocketAddr = "192.0.2.1:3128".parse().unwrap();
        // A value written before host names were accepted reads back unchanged.
        let old = serde_json::to_value(socket).unwrap();
        let read: ProxyAddress = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(read, ProxyAddress::Socket(socket));
        assert_eq!(serde_json::to_value(&read).unwrap(), old);

        let host: ProxyAddress = "proxy.corp.example:8080".parse().unwrap();
        let value = serde_json::to_value(&host).unwrap();
        assert_eq!(value, serde_json::json!("proxy.corp.example:8080"));
        assert_eq!(serde_json::from_value::<ProxyAddress>(value).unwrap(), host);
        assert!(serde_json::from_value::<ProxyAddress>(serde_json::json!("bad name:1")).is_err());
    }

    #[cfg(feature = "engine")]
    #[test]
    fn destination_host_names_are_dns_names_only() {
        for name in [
            "example.com",
            "a",
            "_dmarc.example.com",
            "x-1.example",
            "1.example",
        ] {
            assert!(is_destination_host_name(name), "{name:?} refused");
        }
        let long = format!("{}com", "abcdefghi.".repeat(26));
        for name in [
            "",
            "example.com.",
            ".example.com",
            "a..b",
            "exa mple.com",
            "example.com\r\nX-Injected: 1",
            "example.com:443",
            "user@example.com",
            "ex\u{e4}mple.com",
            "192.0.2.1",
            "::1",
            &long,
        ] {
            assert!(!is_destination_host_name(name), "{name:?} accepted");
        }
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn connect_resolves_a_host_name_each_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let address: ProxyAddress = format!("localhost:{port}").parse().unwrap();
        let accept = tokio::spawn(async move {
            for _ in 0..2 {
                listener.accept().await.unwrap();
            }
        });
        for _ in 0..2 {
            let stream = tokio::time::timeout(std::time::Duration::from_secs(5), address.connect())
                .await
                .expect("connect timed out")
                .expect("connect failed");
            assert!(stream.peer_addr().unwrap().ip().is_loopback());
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), accept)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn connect_names_an_unresolvable_proxy() {
        // `.invalid` never resolves (RFC 6761).
        let address: ProxyAddress = "proxy.invalid:3128".parse().unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(30), address.connect())
            .await
            .expect("lookup timed out")
            .unwrap_err();
        assert!(
            error.to_string().contains("proxy proxy.invalid:3128"),
            "{error}"
        );
    }
}
