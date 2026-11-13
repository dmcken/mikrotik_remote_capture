//! Minimal classic-pcap writer for the tools' output files.
//!
//! Writes the classic pcap format with nanosecond timestamps and link type
//! Ethernet: a 24-byte file header, then a 16-byte record header plus the data
//! for each packet. It's simple enough to write directly, and doing so keeps
//! the on-disk size exactly known, which the capture tool uses for rotation.
//! See <https://www.tcpdump.org/manpages/pcap-savefile.5.html>.

use std::io::{self, Write};
use std::time::Duration;

/// Size of the pcap file header.
pub const FILE_HEADER_LEN: u64 = 24;

/// Size of each packet's record header (the packet data follows it).
pub const RECORD_HEADER_LEN: u64 = 16;

/// Magic number for nanosecond-resolution pcap.
const MAGIC_NANOSECOND: u32 = 0xa1b2_3c4d;

/// pcap link type for Ethernet.
pub const LINKTYPE_ETHERNET: u32 = 1;

/// snaplen recorded in the file header. Only informational for readers;
/// 262144 is what tcpdump and Wireshark use as their maximum.
const SNAPLEN: u32 = 262_144;

/// Writes Ethernet frames to a nanosecond-resolution classic pcap stream.
///
/// Values are written in native byte order, as pcap readers detect the
/// byte order from the magic number. The writer doesn't buffer; wrap a
/// file in a `BufWriter`.
pub struct PcapWriter<W: Write> {
    inner: W,
    bytes_written: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Write the file header and return a writer for the packets.
    pub fn new(mut inner: W) -> io::Result<Self> {
        let mut h = Vec::with_capacity(FILE_HEADER_LEN as usize);
        h.extend_from_slice(&MAGIC_NANOSECOND.to_ne_bytes());
        h.extend_from_slice(&2u16.to_ne_bytes()); // version major
        h.extend_from_slice(&4u16.to_ne_bytes()); // version minor
        h.extend_from_slice(&0i32.to_ne_bytes()); // thiszone (unused)
        h.extend_from_slice(&0u32.to_ne_bytes()); // sigfigs (unused)
        h.extend_from_slice(&SNAPLEN.to_ne_bytes());
        h.extend_from_slice(&LINKTYPE_ETHERNET.to_ne_bytes());
        inner.write_all(&h)?;
        Ok(PcapWriter { inner, bytes_written: FILE_HEADER_LEN })
    }

    /// Write one frame with the given timestamp (time since the Unix epoch).
    ///
    /// Fails for timestamps after 2106 or frames over 4 GiB, which classic
    /// pcap can't represent.
    pub fn write_packet(&mut self, timestamp: Duration, frame: &[u8]) -> io::Result<()> {
        let secs = u32::try_from(timestamp.as_secs()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "timestamp after 2106 can't be stored in pcap")
        })?;
        let len = u32::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame larger than 4 GiB"))?;

        let mut h = [0u8; RECORD_HEADER_LEN as usize];
        h[0..4].copy_from_slice(&secs.to_ne_bytes());
        h[4..8].copy_from_slice(&timestamp.subsec_nanos().to_ne_bytes());
        h[8..12].copy_from_slice(&len.to_ne_bytes()); // captured length
        h[12..16].copy_from_slice(&len.to_ne_bytes()); // original length
        self.inner.write_all(&h)?;
        self.inner.write_all(frame)?;
        self.bytes_written += RECORD_HEADER_LEN + len as u64;
        Ok(())
    }

    /// Bytes written so far, including the file header (the file's size
    /// once any buffering below this writer is flushed).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_header_and_records() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        assert_eq!(w.bytes_written(), 24);
        w.write_packet(Duration::new(1_700_000_000, 123_456_789), b"abc").unwrap();
        w.write_packet(Duration::new(1_700_000_001, 5), b"").unwrap();
        assert_eq!(w.bytes_written(), 24 + 16 + 3 + 16);

        let out = w.inner;
        assert_eq!(out.len() as u64, 24 + 16 + 3 + 16);
        let u32_at = |o: usize| u32::from_ne_bytes(out[o..o + 4].try_into().unwrap());
        assert_eq!(u32_at(0), MAGIC_NANOSECOND);
        assert_eq!(u32_at(20), LINKTYPE_ETHERNET);
        assert_eq!((u32_at(24), u32_at(28), u32_at(32), u32_at(36)), (1_700_000_000, 123_456_789, 3, 3));
        assert_eq!(&out[40..43], b"abc");
        assert_eq!((u32_at(43), u32_at(47)), (1_700_000_001, 5));
    }

    #[test]
    fn rejects_timestamp_past_2106() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        assert!(w.write_packet(Duration::from_secs(1 << 32), b"x").is_err());
    }
}
