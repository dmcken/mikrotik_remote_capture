# tzsp_ng_capture

A small Rust tool that receives a MikroTik sniffer stream (TZSP over UDP,
port 37008 by default), strips the TZSP header from every packet, and writes
the original sniffed frames to size-rotated pcap files.

The result can be opened directly in Wireshark, tshark, Zeek and similar tools
without a separate cleanup pass (compare `../clean/`, which strips the headers
from an existing capture after the fact).

It listens on an ordinary UDP socket, so it needs **no root, no capabilities
and no libpcap**.

## How it works

1. Listens on a UDP socket: by default `[::]:37008`, which accepts the stream
   over both IPv4 and IPv6. The kernel strips the Ethernet, IP and UDP layers
   and reassembles fragmented datagrams, so the tool only ever sees the TZSP
   payload.
2. Walks the TZSP header (including tagged fields such as padding) and keeps
   only the encapsulated frame.
3. Writes the frame to the current output file with the kernel's receive
   timestamp, in nanoseconds.
4. If writing the next packet would take the current file past `--max-size`
   (counting the real on-disk size, including pcap headers), it closes the file
   and starts a new one first. Files therefore never exceed `--max-size`, unless
   a single packet is larger than the limit by itself.
5. While idle it flushes the current file about once a second, so the file on
   disk stays current. On Ctrl-C it flushes the file and prints final stats.

Datagrams that aren't valid TZSP, or that carry no frame (such as keepalives),
are **dropped** and counted as `unstrippable`. Anything can send to the port,
so this protects the output from stray traffic.

Only TZSP packets carrying Ethernet frames are written. Packets whose TZSP
header says they carry something else (e.g. 802.11 from sniffing a wireless
interface) are dropped, reported as `non_ethernet_encap`, and trigger a
warning when the first one is seen. The output file is labelled as Ethernet,
so writing them would mislabel the frames.

If receiving keeps failing, it retries once a second. After 30 errors in a row
it flushes the current file, prints the stats and exits with status 1. Any
successful receive resets the count, so brief problems don't stop the capture.

## Installing

Static Linux binaries for x86-64 and arm64 are attached to each
[release](https://github.com/dmcken/mikrotik_remote_capture/releases); see
[Prebuilt binaries](../README.md#prebuilt-binaries). To build from source
instead:

### Prerequisites

- Linux.
- A Rust toolchain (`cargo`), e.g. via [rustup](https://rustup.rs/).

No libpcap or other system libraries are needed.

### Build

This tool is part of the repo's Cargo workspace. From the repo root:

```bash
cargo build --release -p tzsp_ng_rotator
```

The binary is written to `target/release/tzsp_ng_rotator` under the repo root.
To install it into `~/.cargo/bin` instead:

```bash
cargo install --path tzsp_ng_capture
```

The TZSP header parsing lives in the shared [`tzsp`](../tzsp/README.md) crate.

### Firewall

The capture host must accept incoming UDP on the listening port (37008 by
default). For example, with ufw:

```bash
sudo ufw allow from <router-ip> to any port 37008 proto udp
```

## Usage

```
tzsp_ng_rotator [--listen <IP>] [--port <PORT>] [--max-size <SIZE>] [--output-prefix <PREFIX>]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--listen <IP>` | `-l` | `::` | Local address to listen on. The default `::` accepts both IPv4 and IPv6 on every address of the host. Give a specific address (e.g. `192.0.2.10` or `2001:db8::10`) to only accept the stream sent to that address. |
| `--port <PORT>` | `-p` | `37008` | UDP port to listen on. 37008 is the standard TZSP port; change it if the stream reaches this host on a different port (e.g. through NAT/port forwarding), or if 37008 is in use. Ports below 1024 would need root. |
| `--max-size <SIZE>` | `-m` | `1GB` | Size at which the output file is rotated. A whole number with an optional unit, with or without a space: `B`, `K`/`KB`/`KiB`, `M`/`MB`/`MiB`, `G`/`GB`/`GiB`, `T`/`TB`/`TiB` (case-insensitive), e.g. `500MB`, `1 GB`, `2g`. All units are binary (1 KB = 1024 bytes). Zero and decimals like `1.5GB` are rejected; use a smaller unit instead (`1536MB`). |
| `--output-prefix <PREFIX>` | `-o` | `capture` | Prefix for output files. Files are named `<PREFIX>_<unix-timestamp>.pcap` in the current directory; the prefix may include a path, e.g. `/data/caps/site1`. Existing files are never overwritten: if the name is taken (two rotations in the same second, or a file from an earlier run), `_1`, `_2`, … is added, e.g. `capture_1763025120_1.pcap`. |
| `--help` | `-h` | | Show help. |
| `--version` | `-V` | | Show version. |

`--interface`/`-i` from earlier versions is no longer used. Passing it prints
an explanation and exits; use `--listen` to restrict to one address instead.

### Examples

Paths below are relative to the repo root. Listen on the default port with the defaults (1 GiB files named
`capture_<ts>.pcap`):

```bash
./target/release/tzsp_ng_rotator
```

Rotate every 100 MiB, write into a specific directory, and only accept the
stream sent to one IPv4 address:

```bash
./target/release/tzsp_ng_rotator -l 192.0.2.10 -m 100MB -o /data/caps/router1
```

Listen on a non-standard port:

```bash
./target/release/tzsp_ng_rotator -p 47008
```

Stop with Ctrl-C. Example output (the counts here are illustrative):

```
Listening for TZSP on UDP [::]:37008 (receive buffer 425984 bytes), writing capture_1763025120.pcap
Rotating file: capture_1763025120.pcap -> capture_1763025187.pcap
Capture stats so far: received=812345 written=812345 kernel_dropped=0 unstrippable=0 non_ethernet_encap=0
^C
Ctrl-C received, shutting down...
Final capture stats: received=901234 written=901234 kernel_dropped=0 unstrippable=0 non_ethernet_encap=0
Exiting cleanly...
```

`kernel_dropped` counts datagrams the kernel discarded because the socket's
receive buffer was full, which means the capture is incomplete. The tool asks
for an 8 MiB buffer, but the kernel caps it at `net.core.rmem_max`; the startup
line shows the size actually granted (Linux reports double the usable size).
If you see drops, raise the cap and restart:

```bash
sudo sysctl -w net.core.rmem_max=8388608
```

## Output format

Classic pcap (`.pcap`) with nanosecond timestamps and link type Ethernet.
Wireshark, tshark, tcpdump and the tools in `../clean/` all read it.

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

- The stream must be addressed to this host. Unlike a libpcap capture, a
  socket can't pick up a stream sent to another host, for example one seen on
  a mirror port.
- Timestamps are when the capture host received each datagram, not when the
  router sniffed the frame. They differ by the network delay between the two,
  which is the same as with any capture taken on the receiving host.
- Linux only, since it uses Linux socket options for kernel timestamps
  (`SO_TIMESTAMPNS`) and drop counting (`SO_RXQ_OVFL`).
