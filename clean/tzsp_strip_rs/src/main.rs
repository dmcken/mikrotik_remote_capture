// Rust TZSP stripper

use std::env;
use pcap::{Capture, Packet};

const ETHER_LEN: usize = 14;
const UDP_PORT_TZSP: u16 = 37008;

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
            // END tag
            return Some(offset);
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
        let data = packet.data;

        if data.len() < ETHER_LEN {
            continue;
        }

        // ----------------------------
        // Ethernet
        // ----------------------------
        let ether_type = read_u16(&data[12..14]);
        if ether_type != 0x0800 {
            continue; // not IPv4
        }

        // ----------------------------
        // IPv4
        // ----------------------------
        if data.len() < ETHER_LEN + 20 {
            continue;
        }

        let ip = &data[ETHER_LEN..];
        let ihl = (ip[0] & 0x0F) as usize * 4;
        if data.len() < ETHER_LEN + ihl {
            continue;
        }

        let protocol = ip[9];
        if protocol != 17 {
            continue; // not UDP
        }

        // ----------------------------
        // UDP
        // ----------------------------
        let udp = &ip[ihl..];
        if udp.len() < 8 {
            continue;
        }

        let dst_port = read_u16(&udp[2..4]);
        if dst_port != UDP_PORT_TZSP {
            continue;
        }

        // ----------------------------
        // TZSP
        // ----------------------------
        let tzsp = &udp[8..];

        let tzsp_hdr_len = match parse_tzsp_header(tzsp) {
            Some(v) => v,
            None => continue,
        };

        if tzsp_hdr_len >= tzsp.len() {
            continue;
        }

        // ----------------------------
        // Inner packet
        // ----------------------------
        let inner = &tzsp[tzsp_hdr_len..];

        if inner.is_empty() {
            continue;
        }

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
