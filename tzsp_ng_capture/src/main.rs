// TZSP capture and stripper

//  Standard
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

// External
use clap::Parser;
use pcap::{Capture, Device, Linktype};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Network interface to capture from
    #[arg(short, long)]
    interface: String,

    /// Maximum file size (bytes)
    #[arg(short, long, default_value = "1GB")]
    max_size: String,

    /// Optional output filename
    #[arg(short, long, default_value="capture")]
    output_prefix: String,
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

/// Strip TZSP headers from a packet, if present.
///
/// Returns `None` (never the original, still-wrapped packet) whenever
/// the frame isn't a recognisable Ethernet/IPv4/UDP/TZSP packet on
/// port 37008, or its TZSP header can't be walked cleanly -- callers
/// drop these rather than writing them through to the "cleaned"
/// capture, which would otherwise silently reintroduce the TZSP/IP/
/// Ethernet wrapper for exactly the packets most likely to confuse
/// downstream analysis.
fn strip_tzsp(data: &[u8]) -> Option<&[u8]> {
    const ETHER_LEN: usize = 14;
    const UDP_PORT_TZSP: u16 = 37008;

    if data.len() < ETHER_LEN {
        return None;
    }

    // ----------------------------
    // Ethernet
    // ----------------------------
    let ether_type = read_u16(&data[12..14]);
    if ether_type != 0x0800 {
        return None; // not IPv4
    }

    // ----------------------------
    // IPv4
    // ----------------------------
    if data.len() < ETHER_LEN + 20 {
        return None;
    }

    let ip = &data[ETHER_LEN..];
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if data.len() < ETHER_LEN + ihl {
        return None;
    }

    let protocol = ip[9];
    if protocol != 17 {
        return None; // not UDP
    }

    // ----------------------------
    // UDP
    // ----------------------------
    let udp = &ip[ihl..];
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

fn parse_size(input: &str) -> Result<u64, String> {
    let input = input.trim().to_uppercase();

    let (num_part, unit) = input
        .chars()
        .partition::<String, _>(|c| c.is_ascii_digit());

    let value: u64 = num_part
        .parse()
        .map_err(|_| "Invalid number")?;

    let multiplier = match unit.as_str() {
        "" | "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        "TB" => 1024 * 1024 * 1024 * 1024,
        "KIB" => 1024,
        "MIB" => 1024 * 1024,
        "GIB" => 1024 * 1024 * 1024,
        "TIB" => 1024 * 1024 * 1024 * 1024,
        _ => return Err(format!("Unknown unit: {}", unit)),
    };

    Ok(value * multiplier)
}

/// Generate a timestamped file name for rotation
fn generate_filename(prefix: &String) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}_{}.pcap", prefix, now)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args = Args::parse();
    println!("{:?}", args);

    // Size to grow to before rotating
    let max_file_size: u64 = parse_size(&args.max_size)?;

    // Start device search
    let devices = Device::list()?;

    let device = devices
        .into_iter()
        .find(|d| d.name == args.interface)
        .ok_or_else(|| format!("Network interface '{}' not found", &args.interface))?;
    // End device search


    // Open capture socket. Blocking with a short read timeout (rather
    // than non-blocking + a busy-spin loop below) -- the previous
    // non-blocking setup meant the capture thread spun at ~100% CPU
    // for the whole life of the capture, even when idle, which is
    // wasteful for a capture meant to run for hours/days and can make
    // the actual packet-drop risk below worse by starving the box.
    let mut cap = Capture::from_device(device)
        .unwrap_or_else(|e| {
            eprintln!("Error creating capture on {}: {}", &args.interface, e);
            std::process::exit(1);
        })
        .promisc(true)
        .immediate_mode(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Error opening capture on {}: {}", &args.interface, e);
            std::process::exit(1);
        });

    cap.filter("udp port 37008", true)?;

    // End capture socket


    // Start first output file

    // Dead capture for writing the output
    let linktype: Linktype = cap.get_datalink();
    let mut current_filename = generate_filename(&args.output_prefix);
    let mut savefile = Capture::dead(linktype)?.savefile(&current_filename)?;

    // Start CTRL-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nCtrl-C received, shutting down...");
        r.store(false, Ordering::SeqCst);
    })?;
    // End CTRL-C handler

    println!("Capturing UDP packets on port 37008 on {}...", &args.interface);
    let mut current_file_size: u64 = 0;
    let mut unstrippable_count: u64 = 0;

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                match strip_tzsp(packet.data) {
                    Some(stripped) => {
                        // Calculate new packet header and write
                        let mut new_header = *packet.header;
                        new_header.caplen = stripped.len() as u32;
                        new_header.len = stripped.len() as u32;

                        savefile.write(&pcap::Packet {
                            header: &new_header,
                            data: stripped,
                        });

                        // Update file size counter, rotate if needed
                        current_file_size += stripped.len() as u64;
                        if current_file_size >= max_file_size {
                            println!("Rotating file: {}", &current_filename);
                            savefile.flush()?;
                            current_filename = generate_filename(&args.output_prefix);
                            savefile = Capture::dead(linktype)?.savefile(&current_filename)?;
                            current_file_size = 0;

                            // libpcap's own drop counters (kernel/if
                            // buffer overflow) -- the only way to know
                            // after the fact whether a long capture
                            // actually missed packets under load.
                            if let Ok(stats) = cap.stats() {
                                println!(
                                    "Capture stats so far: received={} dropped={} if_dropped={}, unstrippable={}",
                                    stats.received, stats.dropped, stats.if_dropped, unstrippable_count,
                                );
                            }
                        }
                    }
                    None => {
                        // Not a strippable TZSP/UDP/IPv4/Ethernet
                        // frame (shouldn't normally happen given the
                        // "udp port 37008" capture filter, but if it
                        // does, drop it rather than writing the raw,
                        // still-wrapped packet into the "cleaned"
                        // output -- see strip_tzsp()'s own docs.
                        unstrippable_count += 1;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Just a periodic wakeup to re-check `running` --
                // expected regularly while idle, not an error.
                continue;
            }
            Err(e) => {
                eprintln!("Capture error: {}", e);
            }
        }
    }

    savefile.flush()?;
    if let Ok(stats) = cap.stats() {
        println!(
            "Final capture stats: received={} dropped={} if_dropped={}, unstrippable={}",
            stats.received, stats.dropped, stats.if_dropped, unstrippable_count,
        );
    }
    println!("Exiting cleanly...");
    Ok(())
}
