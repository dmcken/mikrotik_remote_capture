# tzsp_strip_rs

Removes the Ethernet/IP/UDP/TZSP wrapper from every packet in an existing
MikroTik sniffer capture. It writes a new pcap file containing only the
original sniffed frames, with their original timestamps.

It's pure Rust: it reads pcap and pcapng itself, with no libpcap needed to
build or run it.

## How it works

For each packet in the input file it:

1. Checks for an Ethernet frame with ethertype IPv4 (`0x0800`) or IPv6
   (`0x86DD`), skipping any VLAN tags in front of it (802.1Q `0x8100`, and
   QinQ with an outer `0x88A8` or `0x9100` tag).
2. Checks that the IP protocol (IPv6: Next Header) is UDP and the destination
   port matches `--port`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, setting the packet
   length to the stripped size and keeping the original timestamp to the
   nanosecond. For pcapng input, each interface's timestamp resolution
   (`if_tsresol`) and offset (`if_tsoffset`) are applied.

Packets that fail any of these checks are skipped and counted. Packets whose
TZSP header says they carry something other than Ethernet (e.g. 802.11) are
skipped and counted separately, with a warning when the first one is seen.

If the input isn't Ethernet (for example a capture taken on Linux `any`), the
tool exits with an error without creating the output file. An input with no
packets produces a valid, empty output file.

pcapng blocks that can't be used are counted as skipped: Simple Packet Blocks
(they have no timestamp), the obsolete Packet Block, and packets referring to an
interface that wasn't described.

## Installing

Static Linux binaries for x86-64 and arm64 are attached to each
[release](https://github.com/dmcken/mikrotik_remote_capture/releases); see
[Prebuilt binaries](../../README.md#prebuilt-binaries). To build from source
instead:

### Prerequisites

Just a Rust toolchain (`cargo`) supporting edition 2024 (Rust 1.85 or newer),
e.g. via [rustup](https://rustup.rs/). No system libraries are needed.

### Build

This tool is part of the repo's Cargo workspace. From the repo root:

```bash
cargo build --release -p tzsp_strip_rs
```

The binary is written to `target/release/tzsp_strip_rs` under the repo root. To
install it into `~/.cargo/bin` instead:

```bash
cargo install --path clean/tzsp_strip_rs
```

The Ethernet/IP/UDP/TZSP parsing lives in the shared
[`tzsp`](../../tzsp/README.md) crate.

No special privileges are needed, since it only reads and writes files.

## Usage

```
tzsp_strip_rs [-p PORT] <input> <output>
```

| Argument / flag | Default | Description |
|-----------------|---------|-------------|
| `<input>` | *(required)* | Capture to clean: pcap (µs or ns timestamps) or pcapng. Detected from the file's contents, not its extension. |
| `<output>` | *(required)* | File to write. Always classic pcap with nanosecond timestamps, whatever extension you give it. Overwritten if it exists. |
| `-p`, `--port PORT` | `37008` | UDP destination port the TZSP stream was sent to. |
| `-h`, `--help` | | Show help. |
| `-V`, `--version` | | Show version. |

When it finishes it prints a summary:

```
Done. 245312 packets written to clean.pcap, 17 skipped (not TZSP/unparseable), 0 skipped (non-Ethernet encapsulation)
```

If the input can't be read to the end (for example a truncated or corrupt
file), it prints the error and a summary of the partial output, then exits with
status 1. Everything read before the error is still written to the output.

### Example

```bash
tshark -f "udp port 37008" -w raw.pcapng       # capture the stream
./target/release/tzsp_strip_rs raw.pcapng clean.pcap
wireshark clean.pcap
```

Or straight from `cargo`:

```bash
cargo run --release -p tzsp_strip_rs -- raw.pcapng clean.pcap
```

## Limitations

- **No IP reassembly.** Frames over about 1,467 bytes (IPv4 transport) or
  1,447 bytes (IPv6) make the router fragment the TZSP datagram. Over IPv4
  the frame is written truncated; over IPv6 it is skipped. Use
  [`tzsp_ng_capture`](../../tzsp_ng_capture/README.md), or raise the MTU
  between the router and the capture host, if the traffic has full-size
  packets.
- No IPv6 extension headers, Ethernet only. See the
  [parent README](../README.md#shared-limitations).
