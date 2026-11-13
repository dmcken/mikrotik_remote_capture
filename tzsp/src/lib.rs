//! TZSP (TaZmen Sniffer Protocol) parsing shared by the tools in this repo.
//!
//! MikroTik's packet sniffer streams each sniffed frame to a capture host
//! wrapped in a TZSP header, sent over UDP (port 37008 by default):
//!
//! ```text
//! [Ethernet][IPv4|IPv6][UDP][TZSP header][original frame]
//! ```
//!
//! - [`strip`] removes the TZSP header from a UDP payload (what a UDP socket
//!   receives).
//! - [`strip_frame`] removes the whole Ethernet/IP/UDP/TZSP wrapper from a
//!   captured Ethernet frame (what a capture file contains).
//!
//! Both return the TZSP encapsulation type along with the inner frame;
//! callers decide what to do with non-Ethernet encapsulations.
//!
//! [`pcap::PcapWriter`] writes the tools' output files.
//!
//! `clean/tzsp_strip_py/src/tzsp_strip/cli.py` is a Python port of this
//! module. Both are checked against the shared cases in
//! `testdata/tzsp_vectors.tsv`.

pub mod pcap;

/// Standard UDP port for TZSP streams.
pub const DEFAULT_PORT: u16 = 37008;

/// TZSP encapsulation value for Ethernet frames.
pub const ENCAP_ETHERNET: u16 = 1;

const ETHER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Ethertypes (TPIDs) that introduce a VLAN tag: 802.1Q, 802.1ad (QinQ
/// outer tag) and the pre-standard 0x9100 some switches use for QinQ.
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88A8, 0x9100];
const IPV4_MIN_LEN: usize = 20;
const IPV6_LEN: usize = 40;
const IPPROTO_UDP: u8 = 17;
const UDP_LEN: usize = 8;

fn read_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) | (buf[1] as u16)
}

/// Human-readable name for a TZSP encapsulation value.
pub fn encap_name(encap: u16) -> &'static str {
    match encap {
        1 => "Ethernet",
        18 => "IEEE 802.11",
        119 => "Prism header",
        127 => "802.11 AVS",
        _ => "unknown",
    }
}

/// True for the pcap link types used by Linux "any"-device captures
/// (113 = LINUX_SLL, 276 = LINUX_SLL2). Useful for explaining why a
/// non-Ethernet capture was rejected.
pub fn is_linux_cooked(linktype: i32) -> bool {
    linktype == 113 || linktype == 276
}

/// Walk a TZSP header's tag list and return the header's total length.
///
/// The fixed header is version (1) + type (1) + encapsulation (2), then a
/// list of tagged fields ending with an END tag. Tags 0 (PADDING) and
/// 1 (END) are zero-length, with no length byte of their own, unlike every
/// other tag. RouterOS does emit PADDING for alignment, and treating it as
/// a normal tagged field desyncs the rest of the walk.
///
/// Returns `None` if the header is truncated or has no END tag.
pub fn parse_header(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }

    let mut offset = 4;

    while offset < buf.len() {
        let tag = buf[offset];
        offset += 1;

        match tag {
            1 => return Some(offset), // END
            0 => continue,            // PADDING
            _ => {
                if offset >= buf.len() {
                    return None;
                }
                let tag_len = buf[offset] as usize;
                offset += 1 + tag_len;
                if offset > buf.len() {
                    return None;
                }
            }
        }
    }

    None
}

/// Strip the TZSP header from a UDP payload.
///
/// On success returns the TZSP encapsulation type (e.g. [`ENCAP_ETHERNET`],
/// 18 = 802.11) and the encapsulated frame. Returns `None` if the header
/// can't be walked cleanly or carries no frame (e.g. keepalives).
pub fn strip(tzsp: &[u8]) -> Option<(u16, &[u8])> {
    let header_len = parse_header(tzsp)?;

    if header_len >= tzsp.len() {
        return None;
    }

    // parse_header() guarantees the 4-byte fixed header exists.
    let encapsulation = read_u16(&tzsp[2..4]);

    Some((encapsulation, &tzsp[header_len..]))
}

/// Strip the Ethernet/IP/UDP/TZSP wrapper from a captured Ethernet frame.
///
/// Accepts TZSP over IPv4 or IPv6 sent to UDP port `port`, optionally inside
/// any number of VLAN tags (802.1Q, 802.1ad/QinQ). For IPv6, UDP must
/// directly follow the IPv6 header; extension headers aren't walked. Returns
/// the same as [`strip`], or `None` (never the still-wrapped frame) if any
/// layer doesn't match. Callers should drop those rather than writing them
/// through, which would put the wrapper back for exactly the packets most
/// likely to confuse later analysis.
pub fn strip_frame(data: &[u8], port: u16) -> Option<(u16, &[u8])> {
    if data.len() < ETHER_LEN {
        return None;
    }

    // Skip any VLAN tags (4 bytes each: TPID, then TCI) to reach the real
    // ethertype.
    let mut ethertype_at = 12;
    while VLAN_TPIDS.contains(&read_u16(&data[ethertype_at..ethertype_at + 2])) {
        ethertype_at += 4;
        if data.len() < ethertype_at + 2 {
            return None;
        }
    }

    let ip = &data[ethertype_at + 2..];
    let udp = match read_u16(&data[ethertype_at..ethertype_at + 2]) {
        ETHERTYPE_IPV4 => {
            if ip.len() < IPV4_MIN_LEN {
                return None;
            }
            let ihl = (ip[0] & 0x0F) as usize * 4;
            if ihl < IPV4_MIN_LEN || ip.len() < ihl || ip[9] != IPPROTO_UDP {
                return None;
            }
            &ip[ihl..]
        }
        ETHERTYPE_IPV6 => {
            if ip.len() < IPV6_LEN || ip[6] != IPPROTO_UDP {
                return None;
            }
            &ip[IPV6_LEN..]
        }
        _ => return None,
    };

    if udp.len() < UDP_LEN || read_u16(&udp[2..4]) != port {
        return None;
    }

    strip(&udp[UDP_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One case from `testdata/tzsp_vectors.tsv`.
    struct Vector<'a> {
        name: &'a str,
        function: &'a str,
        port: u16,
        input: Vec<u8>,
        expected: Option<(u16, Vec<u8>)>,
    }

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex: {}", s);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    fn vectors() -> Vec<Vector<'static>> {
        include_str!("../../testdata/tzsp_vectors.tsv")
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|line| {
                let f: Vec<&str> = line.split('\t').collect();
                assert_eq!(f.len(), 5, "malformed vector line: {}", line);
                let expected = match f[4] {
                    "reject" => None,
                    e => {
                        let (encap, frame) = e.split_once(':').expect("expected encap:hex");
                        Some((encap.parse().unwrap(), hex(frame)))
                    }
                };
                Vector {
                    name: f[0],
                    function: f[1],
                    port: f[2].parse().unwrap(),
                    input: if f[3] == "-" { vec![] } else { hex(f[3]) },
                    expected,
                }
            })
            .collect()
    }

    #[test]
    fn shared_vectors() {
        let vectors = vectors();
        assert!(vectors.len() >= 20, "only {} vectors loaded", vectors.len());
        for v in &vectors {
            let got = match v.function {
                "strip" => strip(&v.input),
                "strip_frame" => strip_frame(&v.input, v.port),
                other => panic!("{}: unknown function {}", v.name, other),
            };
            let got = got.map(|(e, f)| (e, f.to_vec()));
            assert_eq!(got, v.expected, "vector '{}'", v.name);
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(encap_name(ENCAP_ETHERNET), "Ethernet");
        assert_eq!(encap_name(18), "IEEE 802.11");
        assert_eq!(encap_name(999), "unknown");
        assert!(is_linux_cooked(113) && is_linux_cooked(276));
        assert!(!is_linux_cooked(1));
    }
}
