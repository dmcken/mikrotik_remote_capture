//! Ethernet, VLAN and IP parsing for frames read from a capture file.
//!
//! Finds the UDP datagram carrying the TZSP stream, or, if the IP packet is
//! a fragment, the fragment's details for [`crate::reassembly`].

use crate::read_u16;

const ETHER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Ethertypes (TPIDs) that introduce a VLAN tag: 802.1Q, 802.1ad (QinQ
/// outer tag) and the pre-standard 0x9100 some switches use for QinQ.
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88A8, 0x9100];
const IPV4_MIN_LEN: usize = 20;
const IPV6_LEN: usize = 40;

pub(crate) const IPPROTO_UDP: u8 = 17;
const IPPROTO_HOP_BY_HOP: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DEST_OPTS: u8 = 60;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

/// What an IP packet carries.
pub(crate) enum Network<'a> {
    /// A whole UDP datagram (header and payload).
    Udp(&'a [u8]),
    /// One fragment of a larger IP datagram.
    Fragment(Fragment<'a>),
}

/// Identifies the datagram a fragment belongs to (RFC 791, RFC 8200).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FragmentKey {
    /// IPv4 fragments are only kept for UDP, so the protocol isn't needed.
    V4 { src: [u8; 4], dst: [u8; 4], id: u16 },
    V6 { src: [u8; 16], dst: [u8; 16], id: u32 },
}

pub(crate) struct Fragment<'a> {
    pub key: FragmentKey,
    /// Byte offset of `data` in the reassembled payload.
    pub offset: usize,
    /// More fragments follow (false on the last one).
    pub more: bool,
    /// Protocol of the reassembled payload: UDP for IPv4; for IPv6, the
    /// Fragment header's Next Header (UDP, or an extension header that
    /// precedes it).
    pub next_header: u8,
    pub data: &'a [u8],
}

/// Parse an Ethernet frame down to its UDP datagram or IP fragment.
///
/// Skips VLAN tags, and walks IPv6 extension headers (Hop-by-Hop, Routing,
/// Destination Options, AH, Fragment). The IP length fields are used to drop
/// Ethernet padding or trailers. If the frame was cut short by the capture's
/// snap length, an unfragmented datagram is returned as far as it goes, but a
/// fragment is rejected, as it would corrupt the reassembled datagram.
///
/// Returns `None` for anything else: other ethertypes or protocols, ESP,
/// malformed headers.
pub(crate) fn parse(frame: &[u8]) -> Option<Network<'_>> {
    if frame.len() < ETHER_LEN {
        return None;
    }

    // Skip any VLAN tags (4 bytes each: TPID, then TCI) to reach the real
    // ethertype.
    let mut ethertype_at = 12;
    while VLAN_TPIDS.contains(&read_u16(&frame[ethertype_at..])) {
        ethertype_at += 4;
        if frame.len() < ethertype_at + 2 {
            return None;
        }
    }

    let ip = &frame[ethertype_at + 2..];
    match read_u16(&frame[ethertype_at..]) {
        ETHERTYPE_IPV4 => parse_ipv4(ip),
        ETHERTYPE_IPV6 => parse_ipv6(ip),
        _ => None,
    }
}

/// The IP payload as given by the header's length field, and whether all of
/// it was captured.
fn payload(ip: &[u8], header_len: usize, total_len: usize) -> (&[u8], bool) {
    if total_len <= ip.len() {
        (&ip[header_len..total_len], true)
    } else {
        (&ip[header_len..], false)
    }
}

fn parse_ipv4(ip: &[u8]) -> Option<Network<'_>> {
    if ip.len() < IPV4_MIN_LEN {
        return None;
    }
    let ihl = (ip[0] & 0x0F) as usize * 4;
    let total_len = read_u16(&ip[2..]) as usize;
    if ihl < IPV4_MIN_LEN || ip.len() < ihl || total_len < ihl || ip[9] != IPPROTO_UDP {
        return None;
    }
    let (data, complete) = payload(ip, ihl, total_len);

    let flags_offset = read_u16(&ip[6..]);
    let more = flags_offset & 0x2000 != 0;
    let offset = (flags_offset & 0x1FFF) as usize * 8;
    if !more && offset == 0 {
        return Some(Network::Udp(data));
    }
    if !complete {
        return None;
    }
    Some(Network::Fragment(Fragment {
        key: FragmentKey::V4 {
            src: ip[12..16].try_into().unwrap(),
            dst: ip[16..20].try_into().unwrap(),
            id: read_u16(&ip[4..]),
        },
        offset,
        more,
        next_header: IPPROTO_UDP,
        data,
    }))
}

fn parse_ipv6(ip: &[u8]) -> Option<Network<'_>> {
    if ip.len() < IPV6_LEN {
        return None;
    }
    let (data, complete) = payload(ip, IPV6_LEN, IPV6_LEN + read_u16(&ip[4..]) as usize);

    match walk_ipv6_extension_headers(ip[6], data)? {
        Ipv6Upper::Udp(udp) => Some(Network::Udp(udp)),
        Ipv6Upper::Fragment { header, rest } => {
            let next_header = header[0];
            let offset_flags = read_u16(&header[2..]);
            let offset = (offset_flags & 0xFFF8) as usize;
            let more = offset_flags & 1 != 0;
            if offset == 0 && !more {
                // An "atomic" fragment (RFC 6946): the whole datagram.
                return match walk_ipv6_extension_headers(next_header, rest)? {
                    Ipv6Upper::Udp(udp) => Some(Network::Udp(udp)),
                    Ipv6Upper::Fragment { .. } => None,
                };
            }
            if !complete {
                return None;
            }
            Some(Network::Fragment(Fragment {
                key: FragmentKey::V6 {
                    src: ip[8..24].try_into().unwrap(),
                    dst: ip[24..40].try_into().unwrap(),
                    id: u32::from_be_bytes(header[4..8].try_into().unwrap()),
                },
                offset,
                more,
                next_header,
                data: rest,
            }))
        }
    }
}

pub(crate) enum Ipv6Upper<'a> {
    /// The UDP datagram.
    Udp(&'a [u8]),
    /// A Fragment header, and what follows it.
    Fragment { header: &'a [u8], rest: &'a [u8] },
}

/// Walk IPv6 extension headers, starting with protocol `next` at the start
/// of `buf`, until reaching UDP or a Fragment header. `None` for any other
/// protocol (including ESP, which can't be looked inside) or a truncated
/// header.
pub(crate) fn walk_ipv6_extension_headers(mut next: u8, mut buf: &[u8]) -> Option<Ipv6Upper<'_>> {
    loop {
        let len = match next {
            IPPROTO_UDP => return Some(Ipv6Upper::Udp(buf)),
            IPPROTO_FRAGMENT => {
                if buf.len() < IPV6_FRAGMENT_HEADER_LEN {
                    return None;
                }
                let (header, rest) = buf.split_at(IPV6_FRAGMENT_HEADER_LEN);
                return Some(Ipv6Upper::Fragment { header, rest });
            }
            // Length in 8-octet units, not counting the first 8 octets.
            IPPROTO_HOP_BY_HOP | IPPROTO_ROUTING | IPPROTO_DEST_OPTS => {
                (*buf.get(1)? as usize + 1) * 8
            }
            // Length in 4-octet units, minus 2.
            IPPROTO_AH => (*buf.get(1)? as usize + 2) * 4,
            _ => return None,
        };
        if buf.len() < len {
            return None;
        }
        next = buf[0];
        buf = &buf[len..];
    }
}
