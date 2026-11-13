# tzsp_strip_py

Removes the Ethernet/IP/UDP/TZSP wrapper from every packet in an existing
MikroTik sniffer capture. It writes a new pcapng file containing only the
original sniffed frames, with their original timestamps.

This is the Python counterpart of [`tzsp_strip_rs`](../tzsp_strip_rs/README.md).
It uses scapy's raw reader and writer for file I/O only. The headers are
parsed directly from the packet bytes using the same logic as the Rust tools,
so it doesn't build scapy layer objects for every packet.

## How it works

For each packet in the input file it:

1. Checks for an Ethernet frame with ethertype IPv4 (`0x0800`) or IPv6
   (`0x86DD`).
2. Checks that the IP protocol (IPv6: Next Header) is UDP and the destination port matches
   `--port`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, keeping the original
   timestamp.

Packets that fail any of these checks are skipped and counted.

If the input isn't Ethernet (for example a capture taken on Linux `any`), the
tool exits with an error and status 1 without creating the output file.

## Installing

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/). The only
dependency is scapy.

```bash
cd clean/tzsp_strip_py
uv sync
```

This creates `.venv/` with scapy and installs the `tzsp_strip_py` command into
it.

## Usage

```
uv run tzsp_strip_py [-p PORT] <input> <output>
```

| Argument / flag | Default | Description |
|-----------------|---------|-------------|
| `<input>` | *(required)* | Capture to clean: pcapng or classic pcap (microsecond or nanosecond timestamps). |
| `<output>` | *(required)* | File to write. Always pcapng, whatever the input format. Overwritten if it exists. |
| `-p`, `--port PORT` | `37008` | UDP destination port the TZSP stream was sent to. |
| `-h`, `--help` | | Show help. |

### Example

```bash
tshark -f "udp port 37008" -w raw.pcapng       # capture the stream
uv run tzsp_strip_py raw.pcapng clean.pcapng
```

Progress is logged every 100,000 packets, followed by a summary:

```
... - INFO - 100,000
... - INFO - 200,000
... - INFO - Completed processing 245,312 packets (17 skipped, not TZSP/unparseable)
```

## Limitations

- Output timestamps have microsecond resolution, and are converted through a
  float on the way. Nanosecond detail in the input is lost.
- No IPv6 extension headers, Ethernet only, no VLAN tags, no IP
  reassembly. See the
  [parent README](../README.md#shared-limitations).
