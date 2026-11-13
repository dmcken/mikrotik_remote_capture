// Rust TZSP stripper
//
// Reads a pcap or pcapng capture of a MikroTik sniffer stream, strips the
// Ethernet/IP/UDP/TZSP wrapper from every packet and writes the original
// frames to a nanosecond-resolution pcap file. Pure Rust: no libpcap.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom};
use std::time::Duration;

use clap::Parser;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::{DataLink, PcapError};
use tzsp::pcap::{PcapWriter, LINKTYPE_ETHERNET};

/// Strip TZSP encapsulation from a MikroTik sniffer capture file.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Capture file to clean (pcap or pcapng)
    input: String,

    /// Output file to write (pcap with nanosecond timestamps)
    output: String,

    /// UDP destination port the TZSP stream was sent to
    #[arg(short, long, default_value_t = tzsp::DEFAULT_PORT)]
    port: u16,
}

/// pcapng Section Header Block type, also the first 4 bytes of the file.
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// One item read from the input.
enum Item {
    Packet {
        timestamp: Duration,
        linktype: u32,
        data: Vec<u8>,
    },
    /// A pcapng packet block this tool can't use: a Simple Packet Block (no
    /// timestamp), an obsolete Packet Block, or one whose interface or
    /// timestamp is invalid.
    Unusable,
}

/// The per-interface details needed from a pcapng Interface Description
/// Block.
struct Interface {
    linktype: u32,
    /// if_tsresol: high bit clear = 10^-n seconds, set = 2^-n. Default 6 (µs).
    tsresol: u8,
    /// if_tsoffset: seconds to add to every timestamp.
    tsoffset: i64,
}

enum Input {
    Pcap(PcapReader<BufReader<File>>),
    PcapNg {
        reader: PcapNgReader<BufReader<File>>,
        interfaces: Vec<Interface>,
    },
}

impl Input {
    fn open(path: &str) -> Result<Self, String> {
        let err = |e: &dyn std::fmt::Display| format!("Can't read input '{}': {}", path, e);
        let mut file = File::open(path).map_err(|e| err(&e))?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| err(&e))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| err(&e))?;
        let file = BufReader::new(file);

        if magic == PCAPNG_MAGIC {
            let reader = PcapNgReader::new(file).map_err(|e| err(&e))?;
            Ok(Input::PcapNg { reader, interfaces: Vec::new() })
        } else {
            let reader = PcapReader::new(file)
                .map_err(|e| err(&format!("not a pcap or pcapng file ({})", e)))?;
            Ok(Input::Pcap(reader))
        }
    }

    /// The next packet, `None` at a clean end of file, or the read error
    /// (e.g. a truncated or corrupt file).
    fn next(&mut self) -> Option<Result<Item, PcapError>> {
        match self {
            Input::Pcap(reader) => {
                let linktype = u32::from(reader.header().datalink);
                reader.next_packet().map(|r| {
                    r.map(|p| Item::Packet {
                        timestamp: p.timestamp,
                        linktype,
                        data: p.data.into_owned(),
                    })
                })
            }
            Input::PcapNg { reader, interfaces } => loop {
                let block = match reader.next_block()? {
                    Ok(b) => b,
                    Err(e) => return Some(Err(e)),
                };
                match block {
                    // Interface ids are numbered per section.
                    Block::SectionHeader(_) => interfaces.clear(),
                    Block::InterfaceDescription(idb) => {
                        let mut iface = Interface {
                            linktype: u32::from(idb.linktype),
                            tsresol: 6,
                            tsoffset: 0,
                        };
                        for opt in &idb.options {
                            match opt {
                                InterfaceDescriptionOption::IfTsResol(r) => iface.tsresol = *r,
                                InterfaceDescriptionOption::IfTsOffset(o) => iface.tsoffset = *o as i64,
                                _ => {}
                            }
                        }
                        interfaces.push(iface);
                    }
                    Block::EnhancedPacket(epb) => {
                        let Some(iface) = interfaces.get(epb.interface_id as usize) else {
                            return Some(Ok(Item::Unusable));
                        };
                        // pcap-file stores the raw timestamp count as if it
                        // were nanoseconds, ignoring if_tsresol.
                        let raw = epb.timestamp.as_nanos() as u64;
                        let Some(timestamp) = pcapng_timestamp(raw, iface.tsresol, iface.tsoffset) else {
                            return Some(Ok(Item::Unusable));
                        };
                        return Some(Ok(Item::Packet {
                            timestamp,
                            linktype: iface.linktype,
                            data: epb.data.into_owned(),
                        }));
                    }
                    Block::SimplePacket(_) | Block::Packet(_) => return Some(Ok(Item::Unusable)),
                    _ => {} // statistics, name resolution, ...: not packets
                }
            },
        }
    }
}

/// Convert a raw pcapng timestamp count to time since the Unix epoch, using
/// the interface's if_tsresol and if_tsoffset. Returns `None` for a
/// resolution too fine to represent or a time before the epoch.
fn pcapng_timestamp(raw: u64, tsresol: u8, tsoffset: i64) -> Option<Duration> {
    let exponent = (tsresol & 0x7f) as u32;
    let units_per_sec: u128 = if tsresol & 0x80 == 0 {
        10u128.checked_pow(exponent)?
    } else {
        1u128.checked_shl(exponent)?
    };
    let raw = raw as u128;
    let secs = (raw / units_per_sec) as i128 + tsoffset as i128;
    let nanos = (raw % units_per_sec) * 1_000_000_000 / units_per_sec;
    Some(Duration::new(u64::try_from(secs).ok()?, nanos as u32))
}

/// Error text for input whose link type isn't Ethernet.
fn non_ethernet_message(input: &str, linktype: u32) -> String {
    let mut msg = format!(
        "Input '{}' has link type {} ({:?}); only Ethernet ({}) is supported.",
        input, linktype, DataLink::from(linktype), LINKTYPE_ETHERNET,
    );
    if tzsp::is_linux_cooked(linktype as i32) {
        msg.push_str(" It looks like it was captured on 'any'; capture on the specific interface that receives the TZSP stream instead.");
    }
    msg
}

fn create_output(path: &str) -> Result<PcapWriter<BufWriter<File>>, String> {
    let file = File::create(path).map_err(|e| format!("Can't create output '{}': {}", path, e))?;
    PcapWriter::new(BufWriter::new(file)).map_err(|e| format!("Can't write output '{}': {}", path, e))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut input = Input::open(&args.input)?;

    // Created on the first packet, once its link type has been checked, so
    // a rejected input doesn't leave an empty output file behind.
    let mut output: Option<PcapWriter<BufWriter<File>>> = None;

    let mut written: u64 = 0;
    let mut skipped: u64 = 0;
    let mut non_ethernet: u64 = 0;

    // Loop until a clean end of file. Any other read error (e.g. a
    // truncated or corrupt input) is reported and makes the tool exit
    // non-zero, rather than being mistaken for the end of the file.
    let read_error = loop {
        let (timestamp, linktype, data) = match input.next() {
            None => break None,
            Some(Err(e)) => break Some(e),
            Some(Ok(Item::Unusable)) => {
                skipped += 1;
                continue;
            }
            Some(Ok(Item::Packet { timestamp, linktype, data })) => (timestamp, linktype, data),
        };

        // The parser assumes Ethernet framing; anything else (e.g. a Linux
        // cooked capture taken on "any") would make every packet
        // unstrippable, so stop with a clear error instead.
        if linktype != LINKTYPE_ETHERNET {
            return Err(non_ethernet_message(&args.input, linktype).into());
        }

        let inner = match tzsp::strip_frame(&data, args.port) {
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

        let out = match &mut output {
            Some(out) => out,
            None => output.insert(create_output(&args.output)?),
        };
        out.write_packet(timestamp, inner)
            .map_err(|e| format!("Can't write output '{}': {}", args.output, e))?;
        written += 1;
    };

    // An input with no usable packets still produces a valid, empty file.
    let mut output = match output {
        Some(out) => out,
        None => create_output(&args.output)?,
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

    #[test]
    fn pcapng_timestamp_resolutions() {
        // Default resolution: microseconds.
        assert_eq!(
            pcapng_timestamp(1_700_000_000_123_456, 6, 0),
            Some(Duration::new(1_700_000_000, 123_456_000))
        );
        // Nanoseconds.
        assert_eq!(
            pcapng_timestamp(1_700_000_000_123_456_789, 9, 0),
            Some(Duration::new(1_700_000_000, 123_456_789))
        );
        // Binary fractions: 2^-10 s units, 1.5 s.
        assert_eq!(pcapng_timestamp(1536, 0x80 | 10, 0), Some(Duration::new(1, 500_000_000)));
        // Whole seconds plus an offset.
        assert_eq!(pcapng_timestamp(5, 0, 100), Some(Duration::new(105, 0)));
    }

    #[test]
    fn pcapng_timestamp_invalid() {
        // 10^-127 s units don't fit in u128.
        assert_eq!(pcapng_timestamp(0, 0x7f, 0), None);
        // An offset that puts the packet before 1970.
        assert_eq!(pcapng_timestamp(5, 0, -10), None);
    }
}
