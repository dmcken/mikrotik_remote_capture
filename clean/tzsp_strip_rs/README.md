# tzsp_strip_rs

Removes the Ethernet/IPv4/UDP/TZSP wrapper from every packet in an existing
MikroTik sniffer capture. It writes a new pcap file containing only the
original sniffed frames, with their original timestamps.

## How it works

For each packet in the input file it:

1. Checks for an Ethernet frame with ethertype IPv4 (`0x0800`).
2. Checks that the IPv4 protocol is UDP and the destination port is `37008`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, setting the packet
   length to the stripped size.

Packets that fail any of these checks are skipped.

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
tzsp_strip_rs <input> <output>
```

| Argument | Description |
|----------|-------------|
| `<input>` | Capture to clean. Anything libpcap can read: pcap or pcapng. |
| `<output>` | File to write. Always classic pcap, whatever extension you give it. Overwritten if it exists. |

There are no flags. The TZSP port is fixed at `37008`, the MikroTik default.

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

- The final message always reads `Extracted packets are in output.pcap`, even
  when you gave a different output name.
- Skipped packets are not counted or reported.
- A read error partway through the input (e.g. a truncated file) ends
  processing silently, the same as reaching the end of the file.
- IPv4 only, Ethernet input only, no VLAN tags, no IP reassembly. See the
  [parent README](../README.md#shared-limitations).
