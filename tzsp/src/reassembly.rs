//! IP fragment reassembly for TZSP streams read from capture files.
//!
//! The router adds IP + UDP + TZSP headers to every sniffed frame, so large
//! frames (and, over tunnels, not so large ones) produce TZSP datagrams that
//! don't fit the path MTU and arrive as IP fragments. A capture file holds
//! the fragments as separate packets; [`Reassembler`] puts them back
//! together before stripping. (A UDP socket, as used by `tzsp_ng_capture`,
//! gets whole datagrams from the kernel and doesn't need this.)
//!
//! Rules, following what the Linux kernel does:
//!
//! - Fragments are matched by source, destination and IP ID (IPv4, UDP
//!   only) or Fragment header ID (IPv6).
//! - A datagram whose fragments haven't all arrived within the timeout
//!   (30 s by default, measured in capture time from its first fragment) is
//!   dropped and counted as incomplete.
//! - Exact duplicates of a fragment are ignored. Any other overlap, a
//!   conflicting or exceeded total length, a non-final fragment whose length
//!   isn't a multiple of 8, or a datagram over 65,535 bytes discards the
//!   whole datagram (RFC 5722), and its remaining fragments are rejected.
//! - Buffered fragment data is capped (64 MiB by default); when full, the
//!   oldest incomplete datagrams are dropped to make room.
//! - The stripped frame is returned with the fragment that completes it, so
//!   output timestamps are those of the last fragment received, as with the
//!   kernel's reassembly.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use crate::ip::{self, Fragment, FragmentKey, Ipv6Upper, Network};

/// How long to wait for the rest of a fragmented datagram, in capture time.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on fragment data buffered while waiting for datagrams to complete.
pub const DEFAULT_MAX_BUFFERED: usize = 64 * 1024 * 1024;

/// Largest IP datagram payload a fragment can belong to.
const MAX_DATAGRAM: usize = 65_535;

/// How often (in capture time) to look for timed-out datagrams.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// The result of [`Reassembler::push`] for one captured frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    /// A stripped frame, ready to write: the TZSP encapsulation type and the
    /// inner frame. Borrowed from the input for an unfragmented datagram,
    /// owned for a reassembled one.
    Frame { encapsulation: u16, data: Cow<'a, [u8]> },
    /// A fragment, held until its datagram is complete.
    Fragment,
    /// Not a strippable TZSP frame (or a fragment of a discarded datagram).
    Rejected,
}

/// Counts of fragmented datagrams.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams reassembled from fragments (whether or not they then turned
    /// out to be valid TZSP).
    pub reassembled: u64,
    /// Datagrams dropped before completing: timed out, evicted to make room,
    /// discarded as invalid, or still incomplete at [`Reassembler::finish`].
    pub incomplete: u64,
}

struct Pending {
    first_seen: Duration,
    /// (offset, data), in arrival order. Never overlapping.
    fragments: Vec<(usize, Vec<u8>)>,
    bytes: usize,
    /// Known once the last fragment has arrived.
    total_len: Option<usize>,
    /// From the fragment at offset 0.
    next_header: Option<u8>,
    /// The datagram was discarded; reject its fragments until it times out.
    discarded: bool,
}

impl Pending {
    fn new(first_seen: Duration) -> Self {
        Pending {
            first_seen,
            fragments: Vec::new(),
            bytes: 0,
            total_len: None,
            next_header: None,
            discarded: false,
        }
    }
}

enum Added {
    New,
    Duplicate,
    Conflict,
}

/// Strips TZSP frames from a capture, reassembling fragmented datagrams.
///
/// Feed it every frame from the capture, in order, with
/// [`push`](Self::push), then call [`finish`](Self::finish).
pub struct Reassembler {
    port: u16,
    timeout: Duration,
    max_buffered: usize,
    pending: HashMap<FragmentKey, Pending>,
    buffered: usize,
    last_sweep: Duration,
    stats: Stats,
}

impl Reassembler {
    /// A reassembler for TZSP sent to UDP `port`, with the default limits.
    pub fn new(port: u16) -> Self {
        Self::with_limits(port, DEFAULT_TIMEOUT, DEFAULT_MAX_BUFFERED)
    }

    pub fn with_limits(port: u16, timeout: Duration, max_buffered: usize) -> Self {
        Reassembler {
            port,
            timeout,
            max_buffered,
            pending: HashMap::new(),
            buffered: 0,
            last_sweep: Duration::ZERO,
            stats: Stats::default(),
        }
    }

    /// Process one captured Ethernet frame with its capture timestamp.
    pub fn push<'a>(&mut self, timestamp: Duration, frame: &'a [u8]) -> Packet<'a> {
        match ip::parse(frame) {
            Some(Network::Udp(udp)) => match crate::strip_udp(udp, self.port) {
                Some((encapsulation, data)) => Packet::Frame { encapsulation, data: Cow::Borrowed(data) },
                None => Packet::Rejected,
            },
            Some(Network::Fragment(fragment)) => self.push_fragment(timestamp, fragment),
            None => Packet::Rejected,
        }
    }

    /// Counts so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// End of input: count any datagrams still waiting for fragments as
    /// incomplete, and return the final counts.
    pub fn finish(&mut self) -> Stats {
        for (_, p) in self.pending.drain() {
            if !p.discarded {
                self.stats.incomplete += 1;
            }
        }
        self.buffered = 0;
        self.stats
    }

    fn push_fragment(&mut self, now: Duration, f: Fragment<'_>) -> Packet<'static> {
        self.sweep(now);

        // This datagram's earlier fragments may have timed out without a
        // sweep noticing yet.
        if let Some(p) = self.pending.get(&f.key) {
            if now.saturating_sub(p.first_seen) > self.timeout {
                let p = self.pending.remove(&f.key).unwrap();
                self.drop_pending(&p);
            }
        }

        let end = f.offset + f.data.len();
        let mut invalid = end > MAX_DATAGRAM || (f.more && f.data.len() % 8 != 0);
        if !invalid
            && !self.pending.get(&f.key).is_some_and(|p| p.discarded)
            && !self.make_room(f.data.len(), &f.key)
        {
            invalid = true;
        }

        let p = self.pending.entry(f.key).or_insert_with(|| Pending::new(now));
        if p.discarded {
            return Packet::Rejected;
        }
        let added = if invalid { Added::Conflict } else { add(p, &f, end) };
        match added {
            Added::Duplicate => return Packet::Fragment,
            Added::Conflict => {
                self.buffered -= p.bytes;
                *p = Pending { discarded: true, ..Pending::new(p.first_seen) };
                self.stats.incomplete += 1;
                return Packet::Rejected;
            }
            Added::New => self.buffered += f.data.len(),
        }

        if p.total_len != Some(p.bytes) {
            return Packet::Fragment;
        }

        // Complete: no overlaps and every fragment inside total_len, so the
        // fragments cover it exactly.
        let p = self.pending.remove(&f.key).unwrap();
        self.buffered -= p.bytes;
        self.stats.reassembled += 1;
        let mut payload = vec![0u8; p.bytes];
        for (offset, data) in &p.fragments {
            payload[*offset..offset + data.len()].copy_from_slice(data);
        }

        let udp_start = match f.key {
            FragmentKey::V4 { .. } => 0,
            FragmentKey::V6 { .. } => {
                match p.next_header.and_then(|nh| ip::walk_ipv6_extension_headers(nh, &payload)) {
                    Some(Ipv6Upper::Udp(udp)) => payload.len() - udp.len(),
                    _ => return Packet::Rejected,
                }
            }
        };
        let Some((encapsulation, inner)) = crate::strip_udp(&payload[udp_start..], self.port) else {
            return Packet::Rejected;
        };
        let inner_start = payload.len() - inner.len();
        payload.drain(..inner_start);
        Packet::Frame { encapsulation, data: Cow::Owned(payload) }
    }

    /// Drop datagrams that have waited longer than the timeout. Runs at most
    /// once per second of capture time.
    fn sweep(&mut self, now: Duration) {
        if now.saturating_sub(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let timeout = self.timeout;
        let expired: Vec<FragmentKey> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.first_seen) > timeout)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            let p = self.pending.remove(&key).unwrap();
            self.drop_pending(&p);
        }
    }

    /// Make room for `len` more bytes by dropping the oldest other incomplete
    /// datagrams. False if it can't fit even then.
    fn make_room(&mut self, len: usize, key: &FragmentKey) -> bool {
        if len > self.max_buffered {
            return false;
        }
        while self.buffered + len > self.max_buffered {
            let oldest = self
                .pending
                .iter()
                .filter(|(k, p)| *k != key && p.bytes > 0)
                .min_by_key(|(_, p)| p.first_seen)
                .map(|(k, _)| *k);
            let Some(oldest) = oldest else { return false };
            let p = self.pending.remove(&oldest).unwrap();
            self.drop_pending(&p);
        }
        true
    }

    fn drop_pending(&mut self, p: &Pending) {
        self.buffered -= p.bytes;
        if !p.discarded {
            self.stats.incomplete += 1;
        }
    }
}

/// Add a fragment to a pending datagram.
fn add(p: &mut Pending, f: &Fragment<'_>, end: usize) -> Added {
    for (offset, data) in &p.fragments {
        if f.offset < offset + data.len() && *offset < end {
            return if *offset == f.offset && data.as_slice() == f.data {
                Added::Duplicate
            } else {
                Added::Conflict
            };
        }
    }
    if !f.more {
        if p.total_len.is_some_and(|t| t != end) {
            return Added::Conflict;
        }
        p.total_len = Some(end);
    }
    if let Some(total) = p.total_len {
        if end > total || p.fragments.iter().any(|(o, d)| o + d.len() > total) {
            return Added::Conflict;
        }
    }
    if f.offset == 0 {
        p.next_header = Some(f.next_header);
    }
    p.fragments.push((f.offset, f.data.to_vec()));
    p.bytes += f.data.len();
    Added::New
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Runs every case in `testdata/reassembly_vectors.tsv` (also run by the
    /// Python port).
    #[test]
    fn shared_vectors() {
        let mut cases = 0;
        let mut current: Option<(String, Reassembler)> = None;
        for line in include_str!("../../testdata/reassembly_vectors.tsv").lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "case" => {
                    let max = if f[3] == "-" { DEFAULT_MAX_BUFFERED } else { f[3].parse().unwrap() };
                    let r = Reassembler::with_limits(f[2].parse().unwrap(), DEFAULT_TIMEOUT, max);
                    current = Some((f[1].to_string(), r));
                    cases += 1;
                }
                "packet" => {
                    let (name, r) = current.as_mut().expect("packet before case");
                    let data = hex(f[2]);
                    let got = match r.push(Duration::from_millis(f[1].parse().unwrap()), &data) {
                        Packet::Frame { encapsulation, data } => format!("frame:{}:{}", encapsulation,
                            data.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
                        Packet::Fragment => "fragment".to_string(),
                        Packet::Rejected => "reject".to_string(),
                    };
                    assert_eq!(got, f[3], "case '{}', packet at {} ms", name, f[1]);
                }
                "finish" => {
                    let (name, mut r) = current.take().expect("finish before case");
                    let want = Stats { reassembled: f[1].parse().unwrap(), incomplete: f[2].parse().unwrap() };
                    assert_eq!(r.finish(), want, "case '{}' stats", name);
                    assert_eq!(r.buffered, 0, "case '{}' buffered bytes", name);
                }
                other => panic!("unknown line type {}", other),
            }
        }
        assert!(cases >= 20, "only {} cases loaded", cases);
    }

    #[test]
    fn sweep_frees_timed_out_datagrams() {
        let first = hex("ffffffffffff02000000000108004500001c0001200000110000c0000202c0000201c000909000000000");
        let other = hex("ffffffffffff02000000000108004500001c0002200000110000c0000202c0000201c000909000000000");
        let mut r = Reassembler::new(37008);
        assert_eq!(r.push(Duration::ZERO, &first), Packet::Fragment);
        assert_eq!((r.pending.len(), r.buffered), (1, 8));
        // A fragment of a different datagram 40 s later triggers a sweep,
        // which drops the first datagram and its buffered bytes.
        assert_eq!(r.push(Duration::from_secs(40), &other), Packet::Fragment);
        assert_eq!((r.pending.len(), r.buffered), (1, 8));
        assert_eq!(r.stats().incomplete, 1);
    }

    #[test]
    fn buffered_bytes_tracked() {
        // A 3-fragment datagram from the shared cases' layout, built here
        // directly: check the running byte count, which the vectors can't.
        let tzsp = [&[1u8, 0, 0, 1, 1][..], &[0xAB; 100]].concat();
        let mut udp = vec![0xC0, 0, 0x90, 0x90, 0, 0, 0, 0];
        udp.extend_from_slice(&tzsp);
        let frag = |offset: usize, chunk: &[u8], more: bool| {
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + chunk.len()) as u16).to_be_bytes());
            ip[4..6].copy_from_slice(&7u16.to_be_bytes());
            ip[6..8].copy_from_slice(&(((more as u16) << 13) | (offset / 8) as u16).to_be_bytes());
            ip[9] = 17;
            let mut f = vec![0u8; 12];
            f.extend_from_slice(&[0x08, 0x00]);
            f.extend_from_slice(&ip);
            f.extend_from_slice(chunk);
            f
        };
        let mut r = Reassembler::new(37008);
        assert_eq!(r.push(Duration::ZERO, &frag(0, &udp[..64], true)), Packet::Fragment);
        assert_eq!(r.buffered, 64);
        match r.push(Duration::ZERO, &frag(64, &udp[64..], false)) {
            Packet::Frame { encapsulation: 1, data } => assert_eq!(&*data, &[0xAB; 100][..]),
            other => panic!("expected frame, got {:?}", other),
        }
        assert_eq!(r.buffered, 0);
        assert!(r.pending.is_empty());
        assert_eq!(r.stats(), Stats { reassembled: 1, incomplete: 0 });
    }
}
