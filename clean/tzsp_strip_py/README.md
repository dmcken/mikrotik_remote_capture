# tzsp_strip_py

Removes the Ethernet/IPv4/UDP/TZSP wrapper from every packet in an existing
MikroTik sniffer capture. It writes a new pcapng file containing only the
original sniffed frames, with their original timestamps.

This is the Python counterpart of [`tzsp_strip_rs`](../tzsp_strip_rs/README.md).
It uses scapy's raw reader and writer for file I/O only. The headers are
parsed directly from the packet bytes using the same logic as the Rust tools,
so it doesn't build scapy layer objects for every packet.

## How it works

For each packet in the input file it:

1. Checks for an Ethernet frame with ethertype IPv4 (`0x0800`).
2. Checks that the IPv4 protocol is UDP and the destination port matches
   `--port`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, keeping the original
   timestamp.

Packets that fail any of these checks are skipped and counted.

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
| `<input>` | *(required)* | pcapng capture to clean. |
| `<output>` | *(required)* | pcapng file to write. Overwritten if it exists. |
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

- **pcapng input only.** Given a classic `.pcap` file (such as the output of
  `tzsp_ng_capture` or `tzsp_strip_rs`, or `tshark -F pcap`), it crashes with
  `AttributeError: ... has no attribute 'tshigh'` on the first packet. To work
  around this, convert the file first:
  `editcap -F pcapng input.pcap input.pcapng`.
- Timestamps are converted through a float, so nanosecond-resolution captures
  lose some sub-microsecond precision.
- IPv4 only, Ethernet input only, no VLAN tags, no IP reassembly. See the
  [parent README](../README.md#shared-limitations).
