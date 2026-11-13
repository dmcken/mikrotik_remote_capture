// Rust TZSP stripper

use clap::Parser;
use pcap::{Capture, Linktype, Packet};

/// Strip TZSP encapsulation from a MikroTik sniffer capture file.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Capture file to clean (pcap or pcapng)
    input: String,

    /// Output file to write (always classic pcap)
    output: String,

    /// UDP destination port the TZSP stream was sent to
    #[arg(short, long, default_value_t = 37008)]
    port: u16,
}

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

/// TZSP encapsulation value for Ethernet frames -- the only one these
/// tools write, since the output file is labelled as Ethernet.
const TZSP_ENCAP_ETHERNET: u16 = 1;

/// Strip TZSP headers from a packet, if present.
///
/// On success returns the TZSP encapsulation type (bytes 2-3 of the
/// TZSP header, e.g. 1 = Ethernet, 18 = 802.11) and the inner frame;
/// callers must check the encapsulation before writing the frame.
///
/// Returns `None` (never the original, still-wrapped packet) whenever
/// the frame isn't a recognisable Ethernet/IPv4-or-IPv6/UDP/TZSP
/// packet on `tzsp_port`, or its TZSP header can't be walked cleanly --
/// callers drop these rather than writing them through to the
/// "cleaned" capture, which would otherwise silently reintroduce the
/// TZSP/IP/Ethernet wrapper for exactly the packets most likely to
/// confuse downstream analysis.
fn strip_tzsp(data: &[u8], tzsp_port: u16) -> Option<(u16, &[u8])> {
    const ETHER_LEN: usize = 14;
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86DD;
    const IPV4_MIN_LEN: usize = 20;
    const IPV6_LEN: usize = 40;
    const IPPROTO_UDP: u8 = 17;

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
    if dst_port != tzsp_port {
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

    // parse_tzsp_header() guarantees the 4-byte fixed header exists.
    let encapsulation = read_u16(&tzsp[2..4]);

    Some((encapsulation, &tzsp[tzsp_hdr_len..]))
}

/// Human-readable name for a TZSP encapsulation value.
fn tzsp_encap_name(encap: u16) -> &'static str {
    match encap {
        1 => "Ethernet",
        18 => "IEEE 802.11",
        119 => "Prism header",
        127 => "802.11 AVS",
        _ => "unknown",
    }
}

/// Error text for an input file whose link type isn't Ethernet.
fn non_ethernet_message(input: &str, linktype: Linktype) -> String {
    let name = linktype.get_name().unwrap_or_else(|_| "unknown".to_string());
    let mut msg = format!(
        "Input '{}' has link type {} ({}); only Ethernet (1) is supported.",
        input, linktype.0, name,
    );
    // 113 = LINUX_SLL, 276 = LINUX_SLL2 (what the "any" device uses).
    if linktype.0 == 113 || linktype.0 == 276 {
        msg.push_str(" It looks like it was captured on 'any'; capture on the specific interface that receives the TZSP stream instead.");
    }
    msg
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut cap = Capture::from_file(&args.input)
        .map_err(|e| format!("Can't open input '{}': {}", args.input, e))?;

    // The parser assumes Ethernet framing; anything else (e.g. a Linux
    // cooked capture taken on "any") would make every packet
    // unstrippable, so refuse up front instead.
    let linktype = cap.get_datalink();
    if linktype != Linktype::ETHERNET {
        return Err(non_ethernet_message(&args.input, linktype).into());
    }

    let mut output = cap
        .savefile(&args.output)
        .map_err(|e| format!("Can't create output '{}': {}", args.output, e))?;

    let mut written: u64 = 0;
    let mut skipped: u64 = 0;
    let mut non_ethernet: u64 = 0;

    // Loop until a clean end of file. Any other read error (e.g. a
    // truncated or corrupt input) is reported and makes the tool exit
    // non-zero, rather than being mistaken for the end of the file.
    let read_error = loop {
        let packet = match cap.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::NoMorePackets) => break None,
            Err(e) => break Some(e),
        };

        let inner = match strip_tzsp(packet.data, args.port) {
            Some((TZSP_ENCAP_ETHERNET, v)) => v,
            Some((encap, _)) => {
                // Valid TZSP, but carrying something other than
                // Ethernet (e.g. 802.11). The output is labelled as
                // Ethernet, so writing it would mislabel the frame.
                if non_ethernet == 0 {
                    eprintln!(
                        "Warning: skipping TZSP packets with non-Ethernet encapsulation {} ({}); only Ethernet (1) is supported",
                        encap, tzsp_encap_name(encap),
                    );
                }
                non_ethernet += 1;
                continue;
            }
            None => {
                skipped += 1;
                continue;
            }
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
        written += 1;
    };

    output.flush()?;

    let summary = format!(
        "{} packets written to {}, {} skipped (not TZSP/unparseable), {} skipped (non-Ethernet encapsulation)",
        written, args.output, skipped, non_ethernet,
    );

    match read_error {
        None => {
            println!("Done. {}", summary);
            Ok(())
        }
        Some(e) => {
            eprintln!("Error reading '{}' after {} packets: {}", args.input, written + skipped + non_ethernet, e);
            eprintln!("Partial output: {}", summary);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TZSP header (version 1, type 0 "received", encap 1 Ethernet)
    /// with a PADDING tag then END, followed by the inner frame.
    fn tzsp_payload(inner: &[u8]) -> Vec<u8> {
        tzsp_payload_encap(TZSP_ENCAP_ETHERNET, inner)
    }

    fn tzsp_payload_encap(encap: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = vec![0x01, 0x00];
        v.extend_from_slice(&encap.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x01]); // PADDING, END
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
        assert_eq!(strip_tzsp(&pkt, 37008), Some((TZSP_ENCAP_ETHERNET, INNER)));
    }

    #[test]
    fn strips_ipv6() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt, 37008), Some((TZSP_ENCAP_ETHERNET, INNER)));
    }

    #[test]
    fn rejects_ipv6_with_extension_header() {
        // Next Header 0 = hop-by-hop options.
        let pkt = ether(0x86DD, &ipv6(0, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt, 37008), None);
    }

    #[test]
    fn rejects_truncated_ipv6() {
        let pkt = ether(0x86DD, &[0x60; 39]);
        assert_eq!(strip_tzsp(&pkt, 37008), None);
    }

    #[test]
    fn rejects_wrong_port() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(5000, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt, 37008), None);
    }

    #[test]
    fn rejects_ipv4_bad_ihl() {
        let mut ip = ipv4(17, &udp(37008, &tzsp_payload(INNER)));
        ip[0] = 0x44; // IHL 4 -> 16 bytes, below the 20-byte minimum
        assert_eq!(strip_tzsp(&ether(0x0800, &ip), 37008), None);
    }

    #[test]
    fn rejects_other_ethertype() {
        let pkt = ether(0x0806, &ipv4(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt, 37008), None);
    }

    #[test]
    fn honours_custom_port() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(5000, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt, 5000), Some((TZSP_ENCAP_ETHERNET, INNER)));
        assert_eq!(strip_tzsp(&pkt, 37008), None);
    }

    #[test]
    fn returns_non_ethernet_encapsulation() {
        // 18 = IEEE 802.11; returned as-is for the caller to reject.
        let pkt = ether(0x0800, &ipv4(17, &udp(37008, &tzsp_payload_encap(18, INNER))));
        assert_eq!(strip_tzsp(&pkt, 37008), Some((18, INNER)));
    }
}
