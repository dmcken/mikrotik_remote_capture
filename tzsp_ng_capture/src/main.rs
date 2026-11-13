// TZSP capture and stripper

//  Standard
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// packet on port 37008, or its TZSP header can't be walked cleanly --
/// callers drop these rather than writing them through to the
/// "cleaned" capture, which would otherwise silently reintroduce the
/// TZSP/IP/Ethernet wrapper for exactly the packets most likely to
/// confuse downstream analysis.
fn strip_tzsp(data: &[u8]) -> Option<(u16, &[u8])> {
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

    // parse_tzsp_header() guarantees the 4-byte fixed header exists.
    let encapsulation = read_u16(&tzsp[2..4]);

    Some((encapsulation, &tzsp[tzsp_hdr_len..]))
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

/// Pick a `<prefix>_<secs>.pcap` name that `exists` says is free,
/// falling back to `<prefix>_<secs>_1.pcap`, `_2`, ... -- so two
/// rotations within the same second (or a file left over from an
/// earlier run) never get silently overwritten.
fn unique_filename(prefix: &str, secs: u64, exists: impl Fn(&str) -> bool) -> String {
    let mut candidate = format!("{}_{}.pcap", prefix, secs);
    let mut n: u64 = 1;
    while exists(&candidate) {
        candidate = format!("{}_{}_{}.pcap", prefix, secs, n);
        n += 1;
    }
    candidate
}

/// Generate a timestamped, not-yet-existing file name for rotation
fn generate_filename(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    unique_filename(prefix, now, |p| Path::new(p).exists())
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

/// Error text for a capture interface that isn't Ethernet.
fn non_ethernet_message(interface: &str, linktype: Linktype) -> String {
    let name = linktype.get_name().unwrap_or_else(|_| "unknown".to_string());
    let mut msg = format!(
        "Interface '{}' has link type {} ({}); only Ethernet (1) is supported.",
        interface, linktype.0, name,
    );
    // 113 = LINUX_SLL, 276 = LINUX_SLL2 (what the "any" device uses).
    if linktype.0 == 113 || linktype.0 == 276 {
        msg.push_str(" Capture on the specific interface that receives the TZSP stream instead of 'any'.");
    }
    msg
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

    // The parser assumes Ethernet framing on the capture interface;
    // anything else (e.g. Linux cooked capture on "any") would make
    // every packet unstrippable, so refuse up front instead.
    let capture_linktype = cap.get_datalink();
    if capture_linktype != Linktype::ETHERNET {
        eprintln!("{}", non_ethernet_message(&args.interface, capture_linktype));
        std::process::exit(1);
    }

    // Dead capture for writing the output. Only Ethernet-encapsulated
    // TZSP frames are written, so the output is Ethernet too.
    let linktype = Linktype::ETHERNET;
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
    let mut unsupported_encap_count: u64 = 0;

    // Persistent capture errors (interface gone down/removed, etc.)
    // would otherwise make next_packet() fail instantly in a tight
    // loop, pinning a core and flooding stderr. Back off between
    // retries, and give up once errors have persisted for a while.
    const ERROR_RETRY_DELAY: Duration = Duration::from_secs(1);
    const MAX_CONSECUTIVE_ERRORS: u32 = 30;
    let mut consecutive_errors: u32 = 0;
    let mut fatal_error: Option<pcap::Error> = None;

    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                consecutive_errors = 0;
                match strip_tzsp(packet.data) {
                    Some((TZSP_ENCAP_ETHERNET, stripped)) => {
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
                                    "Capture stats so far: received={} dropped={} if_dropped={}, unstrippable={}, non_ethernet_encap={}",
                                    stats.received, stats.dropped, stats.if_dropped, unstrippable_count,
                                    unsupported_encap_count,
                                );
                            }
                        }
                    }
                    Some((encap, _)) => {
                        // Valid TZSP, but carrying something other
                        // than Ethernet (e.g. 802.11). Writing it into
                        // an Ethernet-labelled file would mislabel it.
                        if unsupported_encap_count == 0 {
                            eprintln!(
                                "Warning: skipping TZSP packets with non-Ethernet encapsulation {} ({}); only Ethernet (1) is supported",
                                encap, tzsp_encap_name(encap),
                            );
                        }
                        unsupported_encap_count += 1;
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
                consecutive_errors = 0;
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                eprintln!(
                    "Capture error ({}/{}): {}",
                    consecutive_errors, MAX_CONSECUTIVE_ERRORS, e,
                );
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    fatal_error = Some(e);
                    break;
                }
                thread::sleep(ERROR_RETRY_DELAY);
            }
        }
    }

    savefile.flush()?;
    if let Ok(stats) = cap.stats() {
        println!(
            "Final capture stats: received={} dropped={} if_dropped={}, unstrippable={}, non_ethernet_encap={}",
            stats.received, stats.dropped, stats.if_dropped, unstrippable_count,
            unsupported_encap_count,
        );
    }

    if let Some(e) = fatal_error {
        eprintln!(
            "Giving up after {} consecutive capture errors (last: {}). Output so far is in {}",
            MAX_CONSECUTIVE_ERRORS, e, current_filename,
        );
        std::process::exit(1);
    }

    println!("Exiting cleanly...");
    Ok(())
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
        assert_eq!(strip_tzsp(&pkt), Some((TZSP_ENCAP_ETHERNET, INNER)));
    }

    #[test]
    fn strips_ipv6() {
        let pkt = ether(0x86DD, &ipv6(17, &udp(37008, &tzsp_payload(INNER))));
        assert_eq!(strip_tzsp(&pkt), Some((TZSP_ENCAP_ETHERNET, INNER)));
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

    #[test]
    fn filename_uses_plain_timestamp_when_free() {
        assert_eq!(unique_filename("cap", 1700, |_| false), "cap_1700.pcap");
    }

    #[test]
    fn filename_adds_suffix_on_collision() {
        let taken = ["cap_1700.pcap", "cap_1700_1.pcap"];
        let name = unique_filename("cap", 1700, |p| taken.contains(&p));
        assert_eq!(name, "cap_1700_2.pcap");
    }

    #[test]
    fn filename_keeps_directory_prefix() {
        let name = unique_filename("/data/caps/site1", 1700, |p| p == "/data/caps/site1_1700.pcap");
        assert_eq!(name, "/data/caps/site1_1700_1.pcap");
    }

    #[test]
    fn returns_non_ethernet_encapsulation() {
        // 18 = IEEE 802.11; returned as-is for the caller to reject.
        let pkt = ether(0x0800, &ipv4(17, &udp(37008, &tzsp_payload_encap(18, INNER))));
        assert_eq!(strip_tzsp(&pkt), Some((18, INNER)));
    }
}
