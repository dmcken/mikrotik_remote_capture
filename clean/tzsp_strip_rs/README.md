# tzsp_strip_rs

Removes the Ethernet/IP/UDP/TZSP wrapper from every packet in an existing
MikroTik sniffer capture. It writes a new pcap file containing only the
original sniffed frames, with their original timestamps.

## How it works

For each packet in the input file it:

1. Checks for an Ethernet frame with ethertype IPv4 (`0x0800`) or IPv6
   (`0x86DD`).
2. Checks that the IP protocol (IPv6: Next Header) is UDP and the destination
   port matches `--port`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, setting the packet
   length to the stripped size.

Packets that fail any of these checks are skipped and counted.

If the input file isn't Ethernet (for example a capture taken on Linux `any`),
the tool exits with an error before creating the output file.

## Installing

### Prerequisites

- A Rust toolchain (`cargo`) supporting edition 2024 (Rust 1.85 or newer), e.g.
  via [rustup](https://rustup.rs/).
- libpcap development headers:
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - Fedora/RHEL: `sudo dnf install libpcap-devel`
  - macOS: libpcap ships with the OS.

### Build

```bash
cd clean/tzsp_strip_rs
cargo build --release
```

The binary is written to `target/release/tzsp_strip_rs`. To install it into
`~/.cargo/bin` instead:

```bash
cargo install --path .
```

No special privileges are needed, since it only reads and writes files.

## Usage

```
tzsp_strip_rs [-p PORT] <input> <output>
```

| Argument / flag | Default | Description |
|-----------------|---------|-------------|
| `<input>` | *(required)* | Capture to clean. Anything libpcap can read: pcap or pcapng. |
| `<output>` | *(required)* | File to write. Always classic pcap, whatever extension you give it. Overwritten if it exists. |
| `-p`, `--port PORT` | `37008` | UDP destination port the TZSP stream was sent to. |
| `-h`, `--help` | | Show help. |
| `-V`, `--version` | | Show version. |

When it finishes it prints a summary:

```
Done. 245312 packets written to clean.pcap, 17 skipped (not TZSP/unparseable)
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
cargo run --release -- raw.pcapng clean.pcap
```

## Limitations

- No IPv6 extension headers, Ethernet only, no VLAN tags, no IP
  reassembly. See the
  [parent README](../README.md#shared-limitations).
