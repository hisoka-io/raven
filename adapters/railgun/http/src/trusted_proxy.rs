//! Peer-gated client-IP extraction.
//!
//! Forwarding headers are attacker-controlled unless the immediate peer is a
//! proxy the operator named. A boolean cannot express that distinction, so
//! trust is scoped to CIDR ranges and an untrusted peer always keys to its own
//! socket address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use http::Request;
use thiserror::Error;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

/// Failure parsing one `trusted_proxy_cidrs` entry.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CidrParseError {
    /// Entry was not `ADDR` or `ADDR/PREFIX`.
    #[error("trusted proxy range {entry:?}: expected `ADDR` or `ADDR/PREFIX`, found {segments} `/`-separated segments")]
    Shape {
        /// The offending entry, verbatim.
        entry: String,
        /// How many `/`-separated segments were seen.
        segments: usize,
    },
    /// Address half did not parse as IPv4 or IPv6.
    #[error("trusted proxy range {entry:?}: {addr:?} is not a valid IPv4 or IPv6 address")]
    Address {
        /// The offending entry, verbatim.
        entry: String,
        /// The address half that failed to parse.
        addr: String,
    },
    /// Prefix half was not a decimal integer.
    #[error("trusted proxy range {entry:?}: prefix {prefix:?} is not a decimal integer")]
    PrefixNotAnInteger {
        /// The offending entry, verbatim.
        entry: String,
        /// The prefix half that failed to parse.
        prefix: String,
    },
    /// Prefix exceeded the address family's width.
    #[error("trusted proxy range {entry:?}: prefix /{prefix} exceeds the {family} maximum /{max}")]
    PrefixTooLong {
        /// The offending entry, verbatim.
        entry: String,
        /// The prefix length that was requested.
        prefix: u32,
        /// `IPv4` or `IPv6`.
        family: &'static str,
        /// Widest prefix the family allows.
        max: u8,
    },
    /// Address carried bits below the prefix, which reads as a host, not a network.
    #[error("trusted proxy range {entry:?}: host bits are set below /{prefix}; write the network address {network}/{prefix}")]
    HostBitsSet {
        /// The offending entry, verbatim.
        entry: String,
        /// The prefix length that was requested.
        prefix: u8,
        /// The entry masked down to its network address.
        network: IpAddr,
    },
}

/// An IPv4 or IPv6 network in CIDR form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// True when `addr` falls inside this network.
    ///
    /// IPv4-mapped IPv6 peers are compared as IPv4, so a dual-stack listener
    /// still matches IPv4 ranges. Write IPv4 ranges in IPv4 form.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, canonical_ip(addr)) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => mask_v4(ip, self.prefix_len) == network,
            (IpAddr::V6(network), IpAddr::V6(ip)) => mask_v6(ip, self.prefix_len) == network,
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let entry = s.trim();
        let segments: Vec<&str> = entry.split('/').collect();
        let (addr_str, prefix_str) = match segments.as_slice() {
            [addr] => (*addr, None),
            [addr, prefix] => (*addr, Some(*prefix)),
            _ => {
                return Err(CidrParseError::Shape {
                    entry: entry.to_owned(),
                    segments: segments.len(),
                })
            }
        };

        let network: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| CidrParseError::Address {
                entry: entry.to_owned(),
                addr: addr_str.trim().to_owned(),
            })?;
        let (family, max) = match network {
            IpAddr::V4(_) => ("IPv4", 32_u8),
            IpAddr::V6(_) => ("IPv6", 128_u8),
        };

        let prefix_len = match prefix_str {
            None => max,
            Some(raw) => {
                let requested: u32 =
                    raw.trim()
                        .parse()
                        .map_err(|_| CidrParseError::PrefixNotAnInteger {
                            entry: entry.to_owned(),
                            prefix: raw.trim().to_owned(),
                        })?;
                let too_long = || CidrParseError::PrefixTooLong {
                    entry: entry.to_owned(),
                    prefix: requested,
                    family,
                    max,
                };
                if requested > u32::from(max) {
                    return Err(too_long());
                }
                u8::try_from(requested).map_err(|_| too_long())?
            }
        };

        let masked = match network {
            IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix_len)),
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix_len)),
        };
        if masked != network {
            return Err(CidrParseError::HostBitsSet {
                entry: entry.to_owned(),
                prefix: prefix_len,
                network: masked,
            });
        }

        Ok(Self {
            network,
            prefix_len,
        })
    }
}

/// Parse a `trusted_proxy_cidrs` list, preserving order.
///
/// # Errors
/// The first entry that fails to parse.
pub fn parse_trusted_ranges(entries: &[String]) -> Result<Vec<IpCidr>, CidrParseError> {
    entries.iter().map(|e| e.parse()).collect()
}

/// Resolve an operator's `(trust_proxy_header, trusted_proxy_cidrs)` pair.
///
/// Empty result means no peer is trusted. Callable before any engine work so an
/// exposed-origin config is refused at parse time rather than after bootstrap.
///
/// # Errors
/// `Err(String)` when the two fields disagree or an entry fails to parse.
pub fn resolve_declared_ranges(
    trust_proxy_header: bool,
    trusted_proxy_cidrs: &[String],
) -> Result<Vec<IpCidr>, String> {
    match (trust_proxy_header, trusted_proxy_cidrs.is_empty()) {
        (true, true) => Err(
            "trust_proxy_header = true requires a non-empty trusted_proxy_cidrs: a boolean \
             cannot tell \"behind a proxy\" from \"directly reachable\", so on an exposed \
             origin it lets anyone forge X-Forwarded-For and escape the per-IP rate limit. \
             List the peer ranges the proxy connects from (e.g. \
             trusted_proxy_cidrs = [\"127.0.0.1/32\", \"172.16.0.0/12\"]), or set \
             trust_proxy_header = false to key every request on its socket address."
                .to_owned(),
        ),
        (false, false) => Err(format!(
            "trusted_proxy_cidrs lists {} range(s) while trust_proxy_header = false, so none of \
             them would be honoured. Set trust_proxy_header = true to use them, or drop \
             trusted_proxy_cidrs.",
            trusted_proxy_cidrs.len()
        )),
        (false, true) => Ok(Vec::new()),
        (true, false) => parse_trusted_ranges(trusted_proxy_cidrs).map_err(|e| e.to_string()),
    }
}

/// Rate-limit key extractor that honours forwarding headers only from trusted peers.
///
/// An untrusted peer keys to its own socket address. A trusted peer's
/// `x-forwarded-for` chain is walked RIGHT to LEFT and the first entry outside
/// every trusted range wins: a proxy appends the address it saw, so only the
/// suffix is proxy-authored and everything left of it is caller-supplied.
/// An empty range list trusts nobody.
#[derive(Clone, Debug)]
pub struct TrustedProxyIpKeyExtractor {
    trusted: Arc<[IpCidr]>,
}

impl TrustedProxyIpKeyExtractor {
    /// Build an extractor over `trusted`; an empty slice trusts nobody.
    pub fn new(trusted: Arc<[IpCidr]>) -> Self {
        Self { trusted }
    }

    /// True when `peer` sits inside any configured range.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.trusted.iter().any(|range| range.contains(peer))
    }

    /// True when the request's immediate peer is trusted; false when the peer is unknown.
    pub fn trusts_request<T>(&self, req: &Request<T>) -> bool {
        peer_ip(req).is_some_and(|peer| self.trusts(peer))
    }

    /// Rightmost `x-forwarded-for` entry outside every trusted range.
    ///
    /// `None` when the chain is absent, unparseable, or entirely trusted; the
    /// caller then falls back to the socket peer.
    fn rightmost_untrusted<T>(&self, req: &Request<T>) -> Option<IpAddr> {
        let chain: Vec<IpAddr> = req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
            .map(canonical_ip)
            .collect();
        chain.into_iter().rev().find(|hop| !self.trusts(*hop))
    }
}

impl KeyExtractor for TrustedProxyIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = peer_ip(req).ok_or(GovernorError::UnableToExtractKey)?;
        if !self.trusts(peer) {
            return Ok(canonical_ip(peer));
        }
        Ok(self
            .rightmost_untrusted(req)
            .unwrap_or_else(|| canonical_ip(peer)))
    }
}

/// The immediate socket peer, ignoring every header.
pub(crate) fn peer_ip<T>(req: &Request<T>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

fn mask_v4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let masked = if prefix_len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - u32::from(prefix_len.min(32))))
    };
    Ipv4Addr::from(masked)
}

fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let masked = if prefix_len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - u32::from(prefix_len.min(128))))
    };
    Ipv6Addr::from(masked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn ranges(entries: &[&str]) -> TrustedProxyIpKeyExtractor {
        let owned: Vec<String> = entries.iter().map(|e| (*e).to_owned()).collect();
        let parsed = parse_trusted_ranges(&owned).expect("test ranges must parse");
        TrustedProxyIpKeyExtractor::new(parsed.into())
    }

    fn request(peer: &str, forwarded_for: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/v1/status");
        if let Some(xff) = forwarded_for {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder.body(Body::empty()).expect("request builds");
        let addr: SocketAddr = peer.parse().expect("peer socket addr parses");
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    fn key(extractor: &TrustedProxyIpKeyExtractor, req: &Request<Body>) -> IpAddr {
        extractor
            .extract(req)
            .expect("peer is present so a key exists")
    }

    #[test]
    fn forged_xff_from_untrusted_v4_peer_keys_to_peer() {
        let extractor = ranges(&["127.0.0.1/32"]);
        let baseline = key(&extractor, &request("203.0.113.9:41000", None));
        let forged = key(
            &extractor,
            &request("203.0.113.9:41000", Some("198.51.100.7")),
        );
        assert_eq!(baseline, "203.0.113.9".parse::<IpAddr>().expect("parses"));
        assert_eq!(forged, baseline);
    }

    #[test]
    fn xff_from_trusted_v4_peer_selects_forwarded_client() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("172.17.0.1:41000", Some("198.51.100.7")),
        );
        assert_eq!(forwarded, "198.51.100.7".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn forged_left_entries_cannot_displace_the_proxy_appended_client() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("172.17.0.1:41000", Some("1.2.3.4, 198.51.100.7")),
        );
        assert_eq!(forwarded, "198.51.100.7".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn rotating_a_forged_prefix_cannot_move_the_rate_limit_key() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let first = key(
            &extractor,
            &request("172.17.0.1:41000", Some("1.2.3.4, 198.51.100.7")),
        );
        let second = key(
            &extractor,
            &request("172.17.0.1:41000", Some("5.6.7.8, 9.9.9.9, 198.51.100.7")),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn a_forged_trusted_range_entry_is_walked_past_not_honoured() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("172.17.0.1:41000", Some("172.16.5.5, 198.51.100.7")),
        );
        assert_eq!(forwarded, "198.51.100.7".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn a_chain_of_only_trusted_hops_falls_back_to_the_peer() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("172.17.0.1:41000", Some("172.16.5.5, 172.16.6.6")),
        );
        assert_eq!(forwarded, "172.17.0.1".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn the_chain_spans_repeated_header_values_in_order() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let mut req = request("172.17.0.1:41000", Some("1.2.3.4"));
        req.headers_mut().append(
            "x-forwarded-for",
            "198.51.100.7".parse().expect("header value parses"),
        );
        assert_eq!(
            key(&extractor, &req),
            "198.51.100.7".parse::<IpAddr>().expect("parses")
        );
    }

    #[test]
    fn unparseable_entries_are_skipped_rather_than_ending_the_walk() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("172.17.0.1:41000", Some("198.51.100.7, not-an-ip")),
        );
        assert_eq!(forwarded, "198.51.100.7".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn forged_xff_from_untrusted_v6_peer_keys_to_peer() {
        let extractor = ranges(&["fd00::/8"]);
        let baseline = key(&extractor, &request("[2001:db8::9]:41000", None));
        let forged = key(
            &extractor,
            &request("[2001:db8::9]:41000", Some("2001:db8::dead")),
        );
        assert_eq!(baseline, "2001:db8::9".parse::<IpAddr>().expect("parses"));
        assert_eq!(forged, baseline);
    }

    #[test]
    fn xff_from_trusted_v6_peer_selects_forwarded_client() {
        let extractor = ranges(&["fd00::/8"]);
        let forwarded = key(
            &extractor,
            &request("[fd00::1]:41000", Some("2001:db8::dead")),
        );
        assert_eq!(
            forwarded,
            "2001:db8::dead".parse::<IpAddr>().expect("parses")
        );
    }

    #[test]
    fn empty_range_list_trusts_nobody() {
        let extractor = ranges(&[]);
        let forged = key(
            &extractor,
            &request("127.0.0.1:41000", Some("198.51.100.7")),
        );
        assert_eq!(forged, "127.0.0.1".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn v4_mapped_v6_peer_matches_v4_range() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forwarded = key(
            &extractor,
            &request("[::ffff:172.17.0.1]:41000", Some("198.51.100.7")),
        );
        assert_eq!(forwarded, "198.51.100.7".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn v4_mapped_v6_peer_outside_range_keys_to_its_v4_form() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let forged = key(
            &extractor,
            &request("[::ffff:203.0.113.9]:41000", Some("198.51.100.7")),
        );
        assert_eq!(forged, "203.0.113.9".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn trusted_peer_without_forwarding_headers_keys_to_itself() {
        let extractor = ranges(&["172.16.0.0/12"]);
        let peer_only = key(&extractor, &request("172.17.0.1:41000", None));
        assert_eq!(peer_only, "172.17.0.1".parse::<IpAddr>().expect("parses"));
    }

    #[test]
    fn trusts_request_gates_the_cf_header_rewrite() {
        let extractor = ranges(&["172.16.0.0/12"]);
        assert!(extractor.trusts_request(&request("172.17.0.1:41000", None)));
        assert!(!extractor.trusts_request(&request("203.0.113.9:41000", None)));
        let no_peer = Request::builder()
            .uri("/v1/status")
            .body(Body::empty())
            .expect("request builds");
        assert!(!extractor.trusts_request(&no_peer));
    }

    #[test]
    fn missing_connect_info_is_an_extraction_error() {
        let extractor = ranges(&["127.0.0.1/32"]);
        let req = Request::builder()
            .uri("/v1/status")
            .body(Body::empty())
            .expect("request builds");
        assert!(extractor.extract(&req).is_err());
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let cidr: IpCidr = "10.1.2.3".parse().expect("bare v4 parses");
        assert!(cidr.contains("10.1.2.3".parse().expect("parses")));
        assert!(!cidr.contains("10.1.2.4".parse().expect("parses")));
    }

    #[test]
    fn zero_prefix_matches_every_address_of_its_family() {
        let v4: IpCidr = "0.0.0.0/0".parse().expect("v4 default route parses");
        assert!(v4.contains("203.0.113.9".parse().expect("parses")));
        assert!(!v4.contains("2001:db8::1".parse().expect("parses")));
        let v6: IpCidr = "::/0".parse().expect("v6 default route parses");
        assert!(v6.contains("2001:db8::1".parse().expect("parses")));
    }

    #[test]
    fn host_bits_below_the_prefix_are_rejected() {
        let err = "10.0.0.1/8"
            .parse::<IpCidr>()
            .expect_err("host bits rejected");
        assert!(
            matches!(err, CidrParseError::HostBitsSet { prefix: 8, .. }),
            "unexpected error: {err}"
        );
        assert!(err.to_string().contains("10.0.0.0/8"), "{err}");
    }

    #[test]
    fn oversized_prefix_is_rejected_per_family() {
        let err = "10.0.0.0/33"
            .parse::<IpCidr>()
            .expect_err("v4 /33 rejected");
        assert!(
            matches!(err, CidrParseError::PrefixTooLong { max: 32, .. }),
            "unexpected error: {err}"
        );
        let err = "::/129".parse::<IpCidr>().expect_err("v6 /129 rejected");
        assert!(
            matches!(err, CidrParseError::PrefixTooLong { max: 128, .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_entries_are_rejected() {
        assert!(matches!(
            "not-an-ip/8".parse::<IpCidr>(),
            Err(CidrParseError::Address { .. })
        ));
        assert!(matches!(
            "10.0.0.0/eight".parse::<IpCidr>(),
            Err(CidrParseError::PrefixNotAnInteger { .. })
        ));
        assert!(matches!(
            "10.0.0.0/8/8".parse::<IpCidr>(),
            Err(CidrParseError::Shape { segments: 3, .. })
        ));
    }
}
