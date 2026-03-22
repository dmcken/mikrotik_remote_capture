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

/// Strip TZSP headers from a packet if present.
fn strip_tzsp(data: &[u8]) -> Option<&[u8]> {
    const ETHER_LEN: usize = 14;
    const UDP_PORT_TZSP: u16 = 37008;

    if data.len() < ETHER_LEN {
        return Some(data);
    }

    // ----------------------------
    // Ethernet
    // ----------------------------
    let ether_type = read_u16(&data[12..14]);
    if ether_type != 0x0800 {
        return Some(data); // not IPv4
    }

    // ----------------------------
    // IPv4
    // ----------------------------
    if data.len() < ETHER_LEN + 20 {
        return Some(data);
    }

    let ip = &data[ETHER_LEN..];
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if data.len() < ETHER_LEN + ihl {
        return Some(data);
    }

    let protocol = ip[9];
    if protocol != 17 {
        return Some(data); // not UDP
    }

    // ----------------------------
    // UDP
    // ----------------------------
    let udp = &ip[ihl..];
    if udp.len() < 8 {
        return Some(data);
    }

    let dst_port = read_u16(&udp[2..4]);
    if dst_port != UDP_PORT_TZSP {
        return Some(data);
    }

    // ----------------------------
    // TZSP
    // ----------------------------
    let tzsp = &udp[8..];

    let tzsp_hdr_len = match parse_tzsp_header(tzsp) {
        Some(v) => v,
        None => return Some(data),
    };

    if tzsp_hdr_len >= tzsp.len() {
        return Some(data);
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


    // Open capture socket
    let mut cap = Capture::from_device(device)
        .unwrap_or_else(|e| {
            eprintln!("Error creating capture on {}: {}", &args.interface, e);
            std::process::exit(1);
        })
        .promisc(true)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Error opening capture on {}: {}", &args.interface, e);
            std::process::exit(1);
        });
    cap = cap.setnonblock()?;

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

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                if let Some(stripped) = strip_tzsp(packet.data) {
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
                    }
                }
            }
            Err(pcap::Error::NoMorePackets) | Err(pcap::Error::TimeoutExpired)  => {
                // non-blocking: no packet right now
                continue;
            }
            Err(e) => {
                eprintln!("Capture error: {}", e);
            }
        }
    }

    savefile.flush()?;
    println!("Exiting cleanly...");
    Ok(())
}
