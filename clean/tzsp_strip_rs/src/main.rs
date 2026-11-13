// Rust TZSP stripper

use std::env;
use pcap::{Capture, Packet};

fn read_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) | (buf[1] as u16)
}

// Parse TZSP header and return its total size
fn parse_tzsp_header(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }

    // TZSP fixed header: version (1) + type (1) + proto (2)
    let mut offset = 4;

    while offset < buf.len() {
        let tag = buf[offset];
        offset += 1;

        if tag == 1 {
            // END tag -- zero-length, no value byte follows.
            return Some(offset);
        }

        if tag == 0 {
            // PADDING tag -- also zero-length (no length byte of its
            // own), unlike every other tag. Treating it like a normal
            // tagged field (as before) reads the next tag's type byte
            // as a bogus length and desyncs the rest of the walk --
            // RouterOS's sniffer does emit this tag for alignment.
            continue;
        }

        if offset >= buf.len() {
            return None;
        }

        let tag_len = buf[offset] as usize;
        offset += 1 + tag_len;

        if offset > buf.len() {
            return None;
        }
    }

    None
}

/// Strip TZSP headers from a packet, if present.
///
/// Returns `None` (never the original, still-wrapped packet) whenever
/// the frame isn't a recognisable Ethernet/IPv4-or-IPv6/UDP/TZSP
/// packet on port 37008, or its TZSP header can't be walked cleanly --
/// callers drop these rather than writing them through to the
/// "cleaned" capture, which would otherwise silently reintroduce the
/// TZSP/IP/Ethernet wrapper for exactly the packets most likely to
/// confuse downstream analysis.
fn strip_tzsp(data: &[u8]) -> Option<&[u8]> {
    const ETHER_LEN: usize = 14;
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86DD;
    const IPV4_MIN_LEN: usize = 20;
    const IPV6_LEN: usize = 40;
    const IPPROTO_UDP: u8 = 17;
    const UDP_PORT_TZSP: u16 = 37008;

    if data.len() < ETHER_LEN {
        return None;
    }

    // ----------------------------
    // Ethernet + IP
    // ----------------------------
    let ip = &data[ETHER_LEN..];
    let udp = match read_u16(&data[12..14]) {
        ETHERTYPE_IPV4 => {
            if ip.len() < IPV4_MIN_LEN {
                return None;
            }
            let ihl = (ip[0] & 0x0F) as usize * 4;
            if ihl < IPV4_MIN_LEN || ip.len() < ihl {
                return None;
            }
            if ip[9] != IPPROTO_UDP {
                return None;
            }
            &ip[ihl..]
        }
        ETHERTYPE_IPV6 => {
            if ip.len() < IPV6_LEN {
                return None;
            }
            // Next Header must be UDP directly. Extension headers
            // (hop-by-hop, routing, fragment, ...) aren't walked; a
            // TZSP stream shouldn't normally carry any, so packets
            // with them are dropped as unstrippable.
            if ip[6] != IPPROTO_UDP {
                return None;
            }
            &ip[IPV6_LEN..]
        }
        _ => return None,
    };

    // ----------------------------
    // UDP
    // ----------------------------
    if udp.len() < 8 {
        return None;
    }

    let dst_port = read_u16(&udp[2..4]);
    if dst_port != UDP_PORT_TZSP {
        return None;
    }

    // ----------------------------
    // TZSP
    // ----------------------------
    let tzsp = &udp[8..];

    let tzsp_hdr_len = parse_tzsp_header(tzsp)?;

    if tzsp_hdr_len >= tzsp.len() {
        return None;
    }

    Some(&tzsp[tzsp_hdr_len..])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // CLI args
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <input.pcap> <output.pcap>", args[0]);
        std::process::exit(1);
    }

    let input_file = &args[1];
    let output_file = &args[2];


    let mut cap = Capture::from_file(input_file)?;
    let mut output = cap.savefile(output_file)?;

    while let Ok(packet) = cap.next_packet() {
        let inner = match strip_tzsp(packet.data) {
            Some(v) => v,
            None => continue,
        };

        // ----------------------------
        // Write inner packet to output pcap
        // ----------------------------
        // Create a modified header
        let mut new_header = *packet.header;
        new_header.caplen = inner.len() as u32;
        new_header.len = inner.len() as u32;

        let new_packet = Packet {
            header: &new_header,
            data: inner,
        };

        output.write(&new_packet);
    }

    println!("Done. Extracted packets are in output.pcap");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TZSP header (version 1, type 0 "received", encap 1 Ethernet)
    /// with a PADDING tag then END, followed by the inner frame.
    fn tzsp_payload(inner: &[u8]) -> Vec<u8> {
        let mut v = vec![0x01, 0x00, 0x00, 0x01, 0x00, 0x01];
        v.extend_from_slice(inner);
        v
    }

    fn udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut v = vec![0xC0, 0x00];
        v.extend_from_slice(&dst_port.to_be_bytes());
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn ether(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v[9] = proto;
        v.extend_from_slice(payload);
        v
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 40];
        v[0] = 0x60;
        v[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        v[6] = next_header;
        v.extend_from_slice(payload);
        v
    }

    const INNER: &[u8] = b"inner ethernet frame";

    #[test]
    fn strips_ipv4() {
        let pkt = ether(0x0800, &ipv4(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), Some(INNER));
    }

    #[test]
    fn strips_ipv6() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), Some(INNER));
    }

    #[test]
    fn rejects_ipv6_with_extension_header() {
        // Next Header 0 = hop-by-hop options.
        let pkt = ether(0x86DD, &ipv6(0, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), None);
    }

    #[test]
    fn rejects_truncated_ipv6() {
        let pkt = ether(0x86DD, &[0x60; 39]);
        assert_eq!(strip_tzsp(&pkt), None);
    }

    #[test]
    fn rejects_wrong_port() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(5000, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), None);
    }

    #[test]
    fn rejects_ipv4_bad_ihl() {
        let mut ip = ipv4(17, &udp(37008, &tzsp_payload(INNER)));
        ip[0] = 0x44; // IHL 4 -> 16 bytes, below the 20-byte minimum
        assert_eq!(strip_tzsp(&ether(0x0800, &ip)), None);
    }

    #[test]
    fn rejects_other_ethertype() {
        let pkt = ether(0x0806, &ipv4(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), None);
    }
}
