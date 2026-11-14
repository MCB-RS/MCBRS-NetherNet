//! Minimal, line-based SDP helpers used by NetherNet signaling.
//!
//! The WebRTC stack does the real SDP negotiation; these helpers only deal with
//! the parts NetherNet adds on top of it: the `a=identity` attribute (§5) and the
//! `a=fingerprint` lines it signs, `a=max-message-size` for fragmentation, and
//! `a=candidate` lines for the optional client candidate inference.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

const FINGERPRINT: &str = "a=fingerprint:";
const IDENTITY: &str = "a=identity:";
const MAX_MESSAGE_SIZE: &str = "a=max-message-size:";
const CANDIDATE: &str = "a=candidate:";
const END_OF_CANDIDATES: &str = "a=end-of-candidates";

/// Default SCTP max message size when the remote does not advertise one (RFC 8841 §6.1).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 65_536;

/// Smallest `a=max-message-size` accepted from a peer. A tiny value would make
/// every message need hundreds of fragments (or be impossible to send).
pub const MIN_MAX_MESSAGE_SIZE: usize = 1024;

/// A DTLS certificate fingerprint (`a=fingerprint:<algorithm> <digest>`).
///
/// Field order matters: it is the lexicographic order required by the
/// canonical JSON used for the detached JWS payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Hash algorithm, e.g. `sha-256`.
    pub algorithm: String,
    /// Colon separated hexadecimal digest.
    pub digest: String,
}

fn lines(sdp: &str) -> impl Iterator<Item = &str> {
    sdp.lines().map(|l| l.trim_end_matches('\r'))
}

fn line_ending(sdp: &str) -> &'static str {
    if sdp.contains("\r\n") { "\r\n" } else { "\n" }
}

/// Returns every `a=fingerprint` attribute of the SDP, in order of appearance
/// (session level and media level).
pub fn fingerprints(sdp: &str) -> Vec<Fingerprint> {
    lines(sdp)
        .filter_map(|l| l.strip_prefix(FINGERPRINT))
        .filter_map(|value| {
            let mut parts = value.split_whitespace();
            let algorithm = parts.next()?;
            let digest = parts.next()?;
            Some(Fingerprint {
                algorithm: algorithm.to_owned(),
                digest: digest.to_owned(),
            })
        })
        .collect()
}

/// Returns the value of the first `a=identity` attribute, if any.
pub fn identity(sdp: &str) -> Option<&str> {
    lines(sdp)
        .find_map(|l| l.strip_prefix(IDENTITY))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Removes every `a=identity` line. WebRTC stacks reject unknown attributes, so
/// this must be applied before `setRemoteDescription()`.
pub fn strip_identity(sdp: &str) -> String {
    let eol = line_ending(sdp);
    let mut out = String::with_capacity(sdp.len());
    for line in lines(sdp).filter(|l| !l.starts_with(IDENTITY)) {
        out.push_str(line);
        out.push_str(eol);
    }
    out
}

/// Inserts a session-level `a=identity:<value>` line, after the session-level
/// `a=fingerprint` lines and before the first `m=` line (any existing
/// `a=identity` line is replaced).
pub fn insert_identity(sdp: &str, value: &str) -> String {
    // The value is base64 in practice; never let a caller inject extra SDP lines.
    let value: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let value = value.as_str();
    let eol = line_ending(sdp);
    let stripped = strip_identity(sdp);
    let all: Vec<&str> = lines(&stripped).collect();
    let first_media = all
        .iter()
        .position(|l| l.starts_with("m="))
        .unwrap_or(all.len());
    let insert_at = all[..first_media]
        .iter()
        .rposition(|l| l.starts_with(FINGERPRINT))
        .map(|i| i + 1)
        .unwrap_or(first_media);

    let mut out = String::with_capacity(stripped.len() + value.len() + 16);
    for (i, line) in all.iter().enumerate() {
        if i == insert_at {
            out.push_str(IDENTITY);
            out.push_str(value);
            out.push_str(eol);
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if insert_at == all.len() {
        out.push_str(IDENTITY);
        out.push_str(value);
        out.push_str(eol);
    }
    out
}

/// Returns the `a=max-message-size` advertised by the SDP, if any.
/// `0` means "unlimited" per RFC 8841 and is returned as `usize::MAX`.
pub fn max_message_size(sdp: &str) -> Option<usize> {
    lines(sdp)
        .find_map(|l| l.strip_prefix(MAX_MESSAGE_SIZE))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| if v == 0 { usize::MAX } else { v })
}

/// Rejects an `a=max-message-size` that is malformed or below
/// [`MIN_MAX_MESSAGE_SIZE`] (`0`, meaning "unlimited", is accepted).
pub fn check_max_message_size(sdp: &str) -> Result<(), String> {
    let Some(raw) = lines(sdp).find_map(|l| l.strip_prefix(MAX_MESSAGE_SIZE)) else {
        return Ok(());
    };
    match raw.trim().parse::<usize>() {
        Ok(0) => Ok(()),
        Ok(v) if v < MIN_MAX_MESSAGE_SIZE => Err(format!(
            "a=max-message-size:{v} is below the minimum of {MIN_MAX_MESSAGE_SIZE} bytes"
        )),
        Ok(_) => Ok(()),
        Err(_) => Err("malformed a=max-message-size".into()),
    }
}

/// Basic sanity check performed on offers before handing them to WebRTC.
pub fn validate_offer(sdp: &str) -> Result<(), String> {
    validate_description(sdp)
}

/// Same checks as [`validate_offer`], applied by clients to answers.
pub fn validate_answer(sdp: &str) -> Result<(), String> {
    validate_description(sdp)
}

fn validate_description(sdp: &str) -> Result<(), String> {
    let mut l = lines(sdp);
    if l.next() != Some("v=0") {
        return Err("SDP must start with `v=0`".into());
    }
    if !lines(sdp).any(|l| l.starts_with("m=application") && l.contains("webrtc-datachannel")) {
        return Err("SDP has no `m=application ... webrtc-datachannel` section".into());
    }
    if fingerprints(sdp).is_empty() {
        return Err("SDP has no `a=fingerprint` attribute".into());
    }
    check_max_message_size(sdp)
}

/// An ICE candidate parsed from an `a=candidate` line (RFC 8839 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Candidate foundation.
    pub foundation: String,
    /// Component ID (1 = RTP/data, the only one used with bundling).
    pub component: u32,
    /// Transport, e.g. `udp`.
    pub transport: String,
    /// Candidate priority.
    pub priority: u32,
    /// Connection address: an IP address or an mDNS host name.
    pub address: String,
    /// Port.
    pub port: u16,
    /// Candidate type: `host`, `srflx`, `prflx` or `relay`.
    pub typ: String,
}

impl Candidate {
    /// The address as an IP, `None` for host names (mDNS `*.local`).
    pub fn ip(&self) -> Option<IpAddr> {
        self.address.parse().ok()
    }
}

fn parse_candidate(value: &str) -> Option<Candidate> {
    let mut parts = value.split_whitespace();
    let foundation = parts.next()?.to_owned();
    let component = parts.next()?.parse().ok()?;
    let transport = parts.next()?.to_ascii_lowercase();
    let priority = parts.next()?.parse().ok()?;
    let address = parts.next()?.to_owned();
    let port = parts.next()?.parse().ok()?;
    if parts.next()? != "typ" {
        return None;
    }
    let typ = parts.next()?.to_owned();
    Some(Candidate {
        foundation,
        component,
        transport,
        priority,
        address,
        port,
        typ,
    })
}

/// Returns every well-formed `a=candidate` line of the SDP.
pub fn candidates(sdp: &str) -> Vec<Candidate> {
    lines(sdp)
        .filter_map(|l| l.strip_prefix(CANDIDATE))
        .filter_map(parse_candidate)
        .collect()
}

/// Returns `true` for globally routable unicast addresses (not private,
/// loopback, link-local, CGNAT, unique-local, documentation, multicast, ...).
pub fn is_routable(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_routable_v4(v4),
        IpAddr::V6(v6) => is_routable_v6(v6),
    }
}

fn is_routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // 100.64.0.0/10, carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24, IETF protocol assignments
        || (a == 198 && (18..20).contains(&b)) // 198.18.0.0/15, benchmarking
        || a >= 240) // reserved
}

fn is_routable_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // fc00::/7, unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10, link local
        || (first == 0x2001 && ip.segments()[1] == 0x0db8)) // 2001:db8::/32, documentation
}

/// Adds `a=candidate` lines (given without the `a=candidate:` prefix) before
/// `a=end-of-candidates`, or after the last candidate, or at the end.
pub fn add_candidates(sdp: &str, new_candidates: &[String]) -> String {
    let eol = line_ending(sdp);
    let all: Vec<&str> = lines(sdp).collect();
    let insert_at = all
        .iter()
        .position(|l| *l == END_OF_CANDIDATES)
        .or_else(|| {
            all.iter()
                .rposition(|l| l.starts_with(CANDIDATE))
                .map(|i| i + 1)
        })
        .unwrap_or(all.len());
    let mut out = String::with_capacity(sdp.len() + new_candidates.len() * 96);
    for (i, line) in all.iter().enumerate() {
        if i == insert_at {
            for c in new_candidates {
                out.push_str(CANDIDATE);
                out.push_str(&c.replace(['\r', '\n'], ""));
                out.push_str(eol);
            }
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if insert_at == all.len() {
        for c in new_candidates {
            out.push_str(CANDIDATE);
            out.push_str(&c.replace(['\r', '\n'], ""));
            out.push_str(eol);
        }
    }
    out
}

/// Priority of an inferred server-reflexive candidate (RFC 8445 §5.1.2.1 with
/// type preference 100, local preference 65535, component 1).
const INFERRED_PRIORITY: u32 = (100 << 24) | (65_535 << 8) | 255;

/// Client candidate inference (see `NetherNetConfig::infer_client_candidates`).
///
/// When every UDP candidate of the offer is non-routable (private address or
/// mDNS name) and `observed` – the address the signaling request came from –
/// is routable, returns the offer with one `srflx` candidate per distinct
/// `host` port, built from `observed` and that port. Returns `None` when no
/// candidate needs to be added.
pub fn infer_client_candidates(offer: &str, observed: IpAddr) -> Option<String> {
    let observed = observed.to_canonical();
    if !is_routable(observed) {
        return None;
    }
    let udp: Vec<Candidate> = candidates(offer)
        .into_iter()
        .filter(|c| c.transport == "udp" && c.component == 1)
        .collect();
    let already_reachable = udp.iter().any(|c| {
        c.ip()
            .is_some_and(|ip| is_routable(ip) || ip.to_canonical() == observed)
    });
    if udp.is_empty() || already_reachable {
        return None;
    }

    let mut ports: Vec<u16> = udp
        .iter()
        .filter(|c| c.typ == "host")
        // An IPv4 host candidate cannot be reached through an IPv6 address and
        // vice versa; mDNS names (no IP) are assumed to match.
        .filter(|c| c.ip().is_none_or(|ip| ip.is_ipv4() == observed.is_ipv4()))
        .map(|c| c.port)
        .filter(|port| *port != 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return None;
    }

    let unspecified = if observed.is_ipv4() { "0.0.0.0" } else { "::" };
    let inferred: Vec<String> = ports
        .iter()
        .enumerate()
        .map(|(i, port)| {
            format!(
                "mcbrsinferred{i} 1 udp {INFERRED_PRIORITY} {observed} {port} typ srflx raddr {unspecified} rport 0"
            )
        })
        .collect();
    Some(add_candidates(offer, &inferred))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\n\
o=- 123456789 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC\r\n\
a=identity:eyJpZHAiOnt9fQ==\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=fingerprint:sha-256 DD:EE:FF\r\n\
a=max-message-size:262144\r\n\
a=candidate:1 1 udp 2130706431 192.168.1.100 12345 typ host\r\n";

    #[test]
    fn reads_fingerprints() {
        assert_eq!(
            fingerprints(OFFER),
            vec![
                Fingerprint {
                    algorithm: "sha-256".into(),
                    digest: "AA:BB:CC".into()
                },
                Fingerprint {
                    algorithm: "sha-256".into(),
                    digest: "DD:EE:FF".into()
                },
            ]
        );
    }

    #[test]
    fn reads_and_strips_identity() {
        assert_eq!(identity(OFFER), Some("eyJpZHAiOnt9fQ=="));
        let stripped = strip_identity(OFFER);
        assert!(!stripped.contains("a=identity"));
        assert_eq!(identity(&stripped), None);
        assert!(stripped.ends_with("typ host\r\n"));
        assert_eq!(
            stripped.len(),
            OFFER.len() - "a=identity:eyJpZHAiOnt9fQ==\r\n".len()
        );
    }

    #[test]
    fn inserts_identity_after_session_fingerprint() {
        let stripped = strip_identity(OFFER);
        let with = insert_identity(&stripped, "XYZ");
        assert_eq!(with, OFFER.replace("eyJpZHAiOnt9fQ==", "XYZ"));
    }

    #[test]
    fn inserts_identity_before_media_without_session_fingerprint() {
        let sdp = "v=0\ns=-\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n";
        let with = insert_identity(sdp, "ID");
        assert_eq!(
            with,
            "v=0\ns=-\na=identity:ID\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n"
        );
    }

    #[test]
    fn identity_value_cannot_inject_lines() {
        let with = insert_identity("v=0\nm=application 9\n", "AAA\r\na=evil:1");
        assert_eq!(with, "v=0\na=identity:AAAa=evil:1\nm=application 9\n");
    }

    #[test]
    fn max_message_size_is_parsed() {
        assert_eq!(max_message_size(OFFER), Some(262_144));
        assert_eq!(max_message_size("a=max-message-size:0"), Some(usize::MAX));
        assert_eq!(max_message_size("v=0"), None);
    }

    #[test]
    fn max_message_size_floor() {
        let with = |v: &str| {
            OFFER.replace(
                "a=max-message-size:262144",
                &format!("a=max-message-size:{v}"),
            )
        };
        assert!(validate_offer(&with("1")).is_err());
        assert!(validate_offer(&with("1023")).is_err());
        assert!(validate_offer(&with("abc")).is_err());
        assert!(validate_offer(&with("1024")).is_ok());
        assert!(validate_offer(&with("0")).is_ok()); // 0 = unlimited (RFC 8841)
        assert!(validate_answer(&with("1")).is_err());
    }

    #[test]
    fn parses_candidates() {
        let c = candidates(OFFER);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].address, "192.168.1.100");
        assert_eq!(c[0].port, 12345);
        assert_eq!(c[0].typ, "host");
        assert!(candidates("a=candidate:garbage").is_empty());
    }

    #[test]
    fn routable_addresses() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_routable(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "203.0.113.5",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_routable(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn infers_candidate_from_signaling_address() {
        let offer = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
a=candidate:1 1 udp 2130706431 192.168.1.100 12345 typ host\r\n\
a=candidate:2 1 udp 2130706431 10.0.0.7 12345 typ host\r\n\
a=candidate:3 1 udp 2130706431 abcd.local 23456 typ host\r\n\
a=end-of-candidates\r\n";
        let out = infer_client_candidates(offer, "8.8.4.4".parse().unwrap()).unwrap();
        let added: Vec<_> = candidates(&out)
            .into_iter()
            .filter(|c| c.typ == "srflx")
            .collect();
        assert_eq!(added.len(), 2, "one per distinct host port");
        assert!(added.iter().all(|c| c.address == "8.8.4.4"));
        assert_eq!(added[0].port, 12345);
        assert_eq!(added[1].port, 23456);
        assert!(out.ends_with("typ srflx raddr 0.0.0.0 rport 0\r\na=end-of-candidates\r\n"));
    }

    #[test]
    fn no_inference_when_not_needed() {
        let private = "v=0\na=candidate:1 1 udp 1 192.168.1.2 5000 typ host\n";
        // Signaling address not routable (LAN / loopback).
        assert!(infer_client_candidates(private, "192.168.1.9".parse().unwrap()).is_none());
        // Client already has a public candidate.
        let public = "v=0\na=candidate:1 1 udp 1 8.8.8.8 5000 typ srflx\n";
        assert!(infer_client_candidates(public, "1.1.1.1".parse().unwrap()).is_none());
        // Address family mismatch.
        assert!(infer_client_candidates(private, "2606:4700::1".parse().unwrap()).is_none());
        // No candidate at all.
        assert!(infer_client_candidates("v=0\n", "1.1.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn validates_offers() {
        assert!(validate_offer(OFFER).is_ok());
        assert!(validate_offer("hello").is_err());
        assert!(validate_offer("v=0\r\nm=audio 9 RTP/AVP 0\r\n").is_err());
    }
}
