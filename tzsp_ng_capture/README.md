# tzsp_ng_capture

A small Rust tool that captures a MikroTik sniffer stream (TZSP over UDP port
37008) directly off a network interface, strips the outer
Ethernet/IPv4/UDP/TZSP wrapper from every packet, and writes the original
sniffed frames to size-rotated pcap files.

The result can be opened directly in Wireshark, tshark, Zeek and similar tools
without a separate cleanup pass (compare `../clean/`, which strips the headers
from an existing capture after the fact).

## How it works

1. Opens the given interface in promiscuous mode with the BPF filter
   `udp port 37008`.
2. For each packet, walks Ethernet → IPv4 or IPv6 → UDP → TZSP (including TZSP
   tagged fields such as padding) and keeps only the encapsulated frame.
3. Writes the stripped frame to the current output file, keeping the original
   capture timestamp.
4. When the bytes written to the current file reach `--max-size`, it closes it
   and starts a new one.
5. On Ctrl-C it flushes the current file and prints the final libpcap stats.

Packets that can't be parsed as Ethernet/IP/UDP/TZSP (other ethertypes,
truncated, malformed TZSP header) are **dropped**, not written through still wrapped. They
are counted and reported as `unstrippable` in the stats output.

## Installing

### Prerequisites

- A Rust toolchain (`cargo`), e.g. via [rustup](https://rustup.rs/).
- libpcap development headers:
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - Fedora/RHEL: `sudo dnf install libpcap-devel`
  - macOS: libpcap ships with the OS.

### Build

```bash
cd tzsp_ng_capture
cargo build --release
```

The binary is written to `target/release/tzsp_ng_rotator`.

Alternatively, install it into `~/.cargo/bin`:

```bash
cargo install --path .
```

### Permissions

Capturing packets needs root or the raw-capture capabilities. Either run it
with `sudo`, or grant the capabilities to the binary once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/tzsp_ng_rotator
```

## Usage

```
tzsp_ng_rotator --interface <INTERFACE> [--max-size <SIZE>] [--output-prefix <PREFIX>]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface <INTERFACE>` | `-i` | *(required)* | Network interface to capture on, i.e. the interface that receives the stream from the router (e.g. `eth0`). |
| `--max-size <SIZE>` | `-m` | `1GB` | Size at which the output file is rotated. A whole number with an optional unit: `B`, `KB`/`KiB`, `MB`/`MiB`, `GB`/`GiB`, `TB`/`TiB` (case-insensitive). All units are binary (1 KB = 1024 bytes). Decimals like `1.5GB` are not accepted. |
| `--output-prefix <PREFIX>` | `-o` | `capture` | Prefix for output files. Files are named `<PREFIX>_<unix-timestamp>.pcap` in the current directory; the prefix may include a path, e.g. `/data/caps/site1`. |
| `--help` | `-h` | | Show help. |
| `--version` | `-V` | | Show version. |

### Examples

Capture on `eth0` with the defaults (1 GiB files named `capture_<ts>.pcap`):

```bash
sudo ./target/release/tzsp_ng_rotator -i eth0
```

Rotate every 100 MiB and write into a specific directory:

```bash
sudo ./target/release/tzsp_ng_rotator -i eth0 -m 100MB -o /data/caps/router1
```

Stop with Ctrl-C. Example output:

```
Capturing UDP packets on port 37008 on eth0...
Rotating file: router1_1763025120.pcap
Capture stats so far: received=812345 dropped=0 if_dropped=0, unstrippable=0
^C
Ctrl-C received, shutting down...
Final capture stats: received=901234 dropped=0 if_dropped=0, unstrippable=0
Exiting cleanly...
```

A non-zero `dropped` / `if_dropped` count means the kernel or interface
dropped packets before the tool saw them, so the capture is incomplete.

## Router setup

Point the MikroTik sniffer at the host running this tool (see the top-level
[README](../README.md)):

```
/tool sniffer
set streaming-enabled=yes streaming-server=<capture-host-ip> filter-stream=yes
/tool sniffer start
```

`<capture-host-ip>` can be an IPv4 or an IPv6 address, provided your RouterOS
version accepts IPv6 for `streaming-server`.

## Notes and limitations

- TZSP over IPv4 and IPv6 are both handled. For IPv6, UDP must directly follow
  the IPv6 header; packets with extension headers are dropped as unstrippable.
- IP fragments aren't reassembled. If the router has to fragment a TZSP
  datagram (large sniffed frames on a path with a small MTU), the first fragment
  is written truncated and the rest are dropped.
- VLAN-tagged frames are not handled. The capture host must receive the stream
  untagged.
- The rotation size counts only the stripped packet bytes, not pcap
  per-packet headers, so files end up slightly larger than `--max-size`.
- File names have one-second resolution. With a very small `--max-size` and
  high traffic, two rotations in the same second would reuse the same name and
  overwrite the earlier file.
- Output is classic pcap (`.pcap`), not pcapng.
