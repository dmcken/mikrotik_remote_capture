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
    #[arg(short, long, default_value_t = tzsp::DEFAULT_PORT)]
    port: u16,
}

/// Error text for an input file whose link type isn't Ethernet.
fn non_ethernet_message(input: &str, linktype: Linktype) -> String {
    let name = linktype.get_name().unwrap_or_else(|_| "unknown".to_string());
    let mut msg = format!(
        "Input '{}' has link type {} ({}); only Ethernet (1) is supported.",
        input, linktype.0, name,
    );
    if tzsp::is_linux_cooked(linktype.0) {
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

        let inner = match tzsp::strip_frame(packet.data, args.port) {
            Some((tzsp::ENCAP_ETHERNET, v)) => v,
            Some((encap, _)) => {
                // Valid TZSP, but carrying something other than
                // Ethernet (e.g. 802.11). The output is labelled as
                // Ethernet, so writing it would mislabel the frame.
                if non_ethernet == 0 {
                    eprintln!(
                        "Warning: skipping TZSP packets with non-Ethernet encapsulation {} ({}); only Ethernet (1) is supported",
                        encap, tzsp::encap_name(encap),
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
