// TZSP capture and stripper
//
// Receives a MikroTik sniffer stream (TZSP over UDP) on an ordinary UDP
// socket, strips the TZSP header from each datagram and writes the
// encapsulated frames to size-rotated pcap files. The kernel handles
// IPv4/IPv6, fragment reassembly and port matching, so no libpcap, raw
// sockets or root privileges are needed.

//  Standard
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, IoSliceMut, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// External
use clap::Parser;
use nix::errno::Errno;
use nix::sys::socket::{
    recvmsg, setsockopt, sockopt, ControlMessageOwned, MsgFlags,
};
use nix::sys::time::TimeSpec;
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Local IP address to listen on; the default "::" accepts both IPv4 and IPv6
    #[arg(short, long, default_value = "::")]
    listen: IpAddr,

    /// UDP port the router streams TZSP to
    #[arg(short, long, default_value_t = tzsp::DEFAULT_PORT)]
    port: u16,

    /// File size at which to rotate, e.g. 500MB, 1GB (binary units)
    #[arg(short, long, default_value = "1GB")]
    max_size: String,

    /// Prefix for output files: <PREFIX>_<unix-timestamp>.pcap
    #[arg(short, long, default_value = "capture")]
    output_prefix: String,

    /// No longer used (kept only to give a helpful error)
    #[arg(short, long, hide = true)]
    interface: Option<String>,
}

/// Requested socket receive buffer. The kernel may cap it at
/// net.core.rmem_max; the effective size is printed at startup.
const RECV_BUFFER_BYTES: usize = 8 << 20;

/// Largest possible UDP payload; also the output snaplen.
const MAX_DATAGRAM: usize = 65535;

// Classic pcap format with nanosecond timestamps: a 24-byte file
// header, then a 16-byte record header plus the data for each packet.
// See https://www.tcpdump.org/manpages/pcap-savefile.5.html
const PCAP_FILE_HEADER_LEN: u64 = 24;
const PCAP_RECORD_HEADER_LEN: u64 = 16;
const PCAP_MAGIC_NANOSECOND: u32 = 0xa1b2_3c4d;
const LINKTYPE_ETHERNET: u32 = 1;

/// The 24-byte pcap file header (native byte order, as readers detect
/// it from the magic number).
fn pcap_file_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(PCAP_FILE_HEADER_LEN as usize);
    h.extend_from_slice(&PCAP_MAGIC_NANOSECOND.to_ne_bytes());
    h.extend_from_slice(&2u16.to_ne_bytes()); // version major
    h.extend_from_slice(&4u16.to_ne_bytes()); // version minor
    h.extend_from_slice(&0i32.to_ne_bytes()); // thiszone (unused)
    h.extend_from_slice(&0u32.to_ne_bytes()); // sigfigs (unused)
    h.extend_from_slice(&(MAX_DATAGRAM as u32).to_ne_bytes()); // snaplen
    h.extend_from_slice(&LINKTYPE_ETHERNET.to_ne_bytes());
    h
}

/// The 16-byte record header for one packet.
fn pcap_record_header(timestamp: Duration, len: usize) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&(timestamp.as_secs() as u32).to_ne_bytes());
    h[4..8].copy_from_slice(&timestamp.subsec_nanos().to_ne_bytes());
    h[8..12].copy_from_slice(&(len as u32).to_ne_bytes()); // captured length
    h[12..16].copy_from_slice(&(len as u32).to_ne_bytes()); // original length
    h
}

/// Parse a size such as `500MB`, `1 GiB`, `2g` or `1048576` into bytes.
///
/// A whole number, optionally followed (with or without a space) by a
/// unit: B, K/KB/KiB, M/MB/MiB, G/GB/GiB or T/TB/TiB, case-insensitive.
/// All units are binary (1 KB = 1024 bytes). Zero, decimals and values
/// that overflow a u64 are rejected.
fn parse_size(input: &str) -> Result<u64, String> {
    let s = input.trim();
    let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(digits_end);

    if num.is_empty() {
        return Err(format!("Invalid size '{}': must start with a number, e.g. 500MB", input));
    }
    if unit.starts_with(['.', ',']) {
        return Err(format!("Invalid size '{}': decimals aren't supported, use a smaller unit (e.g. 1536MB)", input));
    }

    let too_large = || format!("Invalid size '{}': too large", input);
    // Only digits, so parse() can only fail on overflow.
    let value: u64 = num.parse().map_err(|_| too_large())?;

    let multiplier: u64 = match unit.trim_start().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1 << 10,
        "M" | "MB" | "MIB" => 1 << 20,
        "G" | "GB" | "GIB" => 1 << 30,
        "T" | "TB" | "TIB" => 1 << 40,
        _ => {
            return Err(format!(
                "Invalid size '{}': unknown unit '{}' (use B, KB, MB, GB or TB)",
                input, unit.trim_start(),
            ))
        }
    };

    let bytes = value.checked_mul(multiplier).ok_or_else(too_large)?;
    if bytes == 0 {
        return Err(format!("Invalid size '{}': must be greater than zero", input));
    }
    Ok(bytes)
}

/// Output file name for a given rotation time; `n` > 0 adds a `_<n>`
/// suffix, used when the plain name is already taken.
fn candidate_filename(prefix: &str, secs: u64, n: u64) -> String {
    if n == 0 {
        format!("{}_{}.pcap", prefix, secs)
    } else {
        format!("{}_{}_{}.pcap", prefix, secs, n)
    }
}

/// Create a new, timestamped output file. Uses `create_new`, so an
/// existing file (two rotations within the same second, or a file
/// left over from an earlier run) is never overwritten: the next free
/// `_1`, `_2`, ... name is used instead.
fn create_output_file(prefix: &str, secs: u64) -> io::Result<(String, File)> {
    let mut n = 0;
    loop {
        let name = candidate_filename(prefix, secs, n);
        match OpenOptions::new().write(true).create_new(true).open(&name) {
            Ok(file) => return Ok((name, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
            Err(e) => return Err(e),
        }
    }
}

/// The pcap file currently being written.
struct Output {
    name: String,
    writer: BufWriter<File>,
    /// Bytes on disk once buffered data is flushed.
    size: u64,
}

impl Output {
    fn create(prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (name, file) = create_output_file(prefix, secs)
            .map_err(|e| format!("Can't create output file for prefix '{}': {}", prefix, e))?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&pcap_file_header())?;
        Ok(Output { name, writer, size: PCAP_FILE_HEADER_LEN })
    }

    fn write(&mut self, timestamp: Duration, frame: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.writer.write_all(&pcap_record_header(timestamp, frame.len()))?;
        self.writer.write_all(frame)?;
        self.size += PCAP_RECORD_HEADER_LEN + frame.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// One received datagram.
struct Received {
    len: usize,
    /// Datagram was larger than the buffer (can't happen with a
    /// 64 KiB buffer, but checked rather than assumed).
    truncated: bool,
    /// Kernel receive timestamp (SO_TIMESTAMPNS).
    timestamp: Option<Duration>,
    /// Cumulative datagrams dropped by the kernel because the socket
    /// buffer was full (SO_RXQ_OVFL).
    dropped: Option<u32>,
}

fn receive(fd: RawFd, buf: &mut [u8], cmsg_buf: &mut Vec<u8>) -> nix::Result<Received> {
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(fd, &mut iov, Some(cmsg_buf), MsgFlags::empty())?;

    let mut timestamp = None;
    let mut dropped = None;
    for cmsg in msg.cmsgs()? {
        match cmsg {
            ControlMessageOwned::ScmTimestampns(ts) => {
                timestamp = Some(Duration::new(ts.tv_sec() as u64, ts.tv_nsec() as u32));
            }
            ControlMessageOwned::RxqOvfl(n) => dropped = Some(n),
            _ => {}
        }
    }

    Ok(Received {
        len: msg.bytes,
        truncated: msg.flags.contains(MsgFlags::MSG_TRUNC),
        timestamp,
        dropped,
    })
}

/// Bind the receiving UDP socket. Binding to an IPv6 address (including
/// the default "::") also accepts IPv4 via IPv4-mapped addresses.
fn open_socket(listen: IpAddr, port: u16) -> Result<Socket, Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(listen, port);
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket
        .bind(&addr.into())
        .map_err(|e| format!("Can't listen on {}: {}", addr, e))?;

    // Wake up at least once a second to check for Ctrl-C and flush.
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    // A bigger buffer absorbs bursts while the disk is busy; failure
    // here isn't fatal, the effective size is reported either way.
    let _ = socket.set_recv_buffer_size(RECV_BUFFER_BYTES);

    setsockopt(&socket, sockopt::ReceiveTimestampns, &true)?;
    setsockopt(&socket, sockopt::RxqOvfl, &1)?;
    Ok(socket)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.interface.is_some() {
        eprintln!(
            "--interface is no longer used: the capture now listens on a UDP socket \
             (port {} on all addresses by default). Use --listen <IP> to restrict it \
             to one local address.",
            args.port,
        );
        std::process::exit(2);
    }

    // Size to grow to before rotating
    let max_file_size: u64 = parse_size(&args.max_size)?;

    let socket = open_socket(args.listen, args.port)?;
    let fd = socket.as_raw_fd();

    let mut output = Output::create(&args.output_prefix)?;

    // Start CTRL-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nCtrl-C received, shutting down...");
        r.store(false, Ordering::SeqCst);
    })?;
    // End CTRL-C handler

    println!(
        "Listening for TZSP on UDP {} (receive buffer {} bytes), writing {}",
        SocketAddr::new(args.listen, args.port),
        socket.recv_buffer_size().unwrap_or(0),
        output.name,
    );

    let mut received: u64 = 0;
    let mut written: u64 = 0;
    let mut unstrippable_count: u64 = 0;
    let mut unsupported_encap_count: u64 = 0;
    let mut kernel_dropped: u32 = 0;

    let print_stats = |label: &str, received: u64, written: u64, unstrippable: u64, non_eth: u64, dropped: u32| {
        println!(
            "{}: received={} written={} kernel_dropped={} unstrippable={} non_ethernet_encap={}",
            label, received, written, dropped, unstrippable, non_eth,
        );
    };

    // Persistent receive errors would otherwise make recvmsg() fail
    // instantly in a tight loop, pinning a core and flooding stderr.
    // Back off between retries, and give up once errors have persisted
    // for a while.
    const ERROR_RETRY_DELAY: Duration = Duration::from_secs(1);
    const MAX_CONSECUTIVE_ERRORS: u32 = 30;
    let mut consecutive_errors: u32 = 0;
    let mut fatal_error: Option<Errno> = None;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut cmsg_buf = nix::cmsg_space!(TimeSpec, u32);

    while running.load(Ordering::SeqCst) {
        let datagram = match receive(fd, &mut buf, &mut cmsg_buf) {
            Ok(d) => d,
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => {
                // Read timeout (idle) or a signal: not an error. Flush
                // so the file on disk stays current while idle.
                consecutive_errors = 0;
                output.flush()?;
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                eprintln!(
                    "Receive error ({}/{}): {}",
                    consecutive_errors, MAX_CONSECUTIVE_ERRORS, e,
                );
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    fatal_error = Some(e);
                    break;
                }
                thread::sleep(ERROR_RETRY_DELAY);
                continue;
            }
        };
        consecutive_errors = 0;
        received += 1;
        if let Some(d) = datagram.dropped {
            kernel_dropped = d;
        }

        if datagram.truncated {
            unstrippable_count += 1;
            continue;
        }

        let frame = match tzsp::strip(&buf[..datagram.len]) {
            Some((tzsp::ENCAP_ETHERNET, frame)) => frame,
            Some((encap, _)) => {
                // Valid TZSP, but carrying something other than
                // Ethernet (e.g. 802.11). Writing it into an
                // Ethernet-labelled file would mislabel it.
                if unsupported_encap_count == 0 {
                    eprintln!(
                        "Warning: skipping TZSP packets with non-Ethernet encapsulation {} ({}); only Ethernet (1) is supported",
                        encap, tzsp::encap_name(encap),
                    );
                }
                unsupported_encap_count += 1;
                continue;
            }
            None => {
                // Not parseable as TZSP, or no frame inside (e.g. a
                // keepalive). Anything can be sent to the port, so
                // this is counted rather than written.
                unstrippable_count += 1;
                continue;
            }
        };

        // Rotate *before* a write that would take the file past
        // --max-size, so files never exceed it (unless one packet
        // alone is bigger than the limit, in which case it gets a file
        // to itself).
        let record_len = PCAP_RECORD_HEADER_LEN + frame.len() as u64;
        if output.size + record_len > max_file_size && output.size > PCAP_FILE_HEADER_LEN {
            output.flush()?;
            let next = Output::create(&args.output_prefix)?;
            println!("Rotating file: {} -> {}", output.name, next.name);
            output = next;
            print_stats("Capture stats so far", received, written, unstrippable_count,
                        unsupported_encap_count, kernel_dropped);
        }

        let timestamp = datagram
            .timestamp
            .unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default());
        output.write(timestamp, frame)?;
        written += 1;
    }

    output.flush()?;
    print_stats("Final capture stats", received, written, unstrippable_count,
                unsupported_encap_count, kernel_dropped);

    if let Some(e) = fatal_error {
        eprintln!(
            "Giving up after {} consecutive receive errors (last: {}). Output so far is in {}",
            MAX_CONSECUTIVE_ERRORS, e, output.name,
        );
        std::process::exit(1);
    }

    println!("Exiting cleanly...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_filenames() {
        assert_eq!(candidate_filename("cap", 1700, 0), "cap_1700.pcap");
        assert_eq!(candidate_filename("cap", 1700, 2), "cap_1700_2.pcap");
        assert_eq!(candidate_filename("/data/caps/site1", 1700, 1), "/data/caps/site1_1700_1.pcap");
    }

    #[test]
    fn create_output_file_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("tzsp_ng_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prefix = dir.join("cap").to_string_lossy().into_owned();

        std::fs::write(format!("{}_1700.pcap", prefix), b"keep me").unwrap();
        let (first, _) = create_output_file(&prefix, 1700).unwrap();
        let (second, _) = create_output_file(&prefix, 1700).unwrap();

        assert_eq!(first, format!("{}_1700_1.pcap", prefix));
        assert_eq!(second, format!("{}_1700_2.pcap", prefix));
        assert_eq!(std::fs::read(format!("{}_1700.pcap", prefix)).unwrap(), b"keep me");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_size_accepts_units_spaces_and_case() {
        assert_eq!(parse_size("1048576"), Ok(1 << 20));
        assert_eq!(parse_size("512B"), Ok(512));
        assert_eq!(parse_size("1GB"), Ok(1 << 30));
        assert_eq!(parse_size("1 GB"), Ok(1 << 30));
        assert_eq!(parse_size("1G"), Ok(1 << 30));
        assert_eq!(parse_size("1gib"), Ok(1 << 30));
        assert_eq!(parse_size("  500 mb  "), Ok(500 << 20));
        assert_eq!(parse_size("2K"), Ok(2048));
        assert_eq!(parse_size("1TiB"), Ok(1 << 40));
    }

    #[test]
    fn parse_size_rejects_bad_input() {
        for bad in ["", "GB", "1.5GB", "1,5GB", "1x2GB", "1 G B", "1PB", "-1GB", "0", "0GB"] {
            assert!(parse_size(bad).is_err(), "{:?} should be rejected", bad);
        }
    }

    #[test]
    fn parse_size_rejects_overflow() {
        assert!(parse_size("99999999999999999999").is_err()); // > u64::MAX
        assert!(parse_size("16777216TB").is_err()); // 2^24 * 2^40 = 2^64
        assert_eq!(parse_size("16777215TB"), Ok(16777215u64 << 40));
    }
}
