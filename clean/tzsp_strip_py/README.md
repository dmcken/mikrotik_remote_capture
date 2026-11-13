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
   (`0x86DD`), skipping any VLAN tags in front of it (802.1Q `0x8100`, and
   QinQ with an outer `0x88A8` or `0x9100` tag).
2. Checks that the IP protocol is UDP (for IPv6, after any extension
   headers) and the destination port matches `--port`.
3. Walks the TZSP header's tag list, handling the zero-length PADDING and END
   tags.
4. Writes everything after the TZSP header to the output, keeping the original
   timestamp.

TZSP datagrams that the router's packets were IP-fragmented into on the way
are reassembled first (IPv4 and IPv6, fragments in any order), using the same
rules as [`tzsp_strip_rs`](../tzsp_strip_rs/README.md#fragmented-datagrams).
The frame gets the timestamp of the fragment that completed it. Datagrams
that never complete are counted as `incomplete`.

Packets that fail any of these checks are skipped and counted. Packets whose
TZSP header says they carry something other than Ethernet (e.g. 802.11) are
skipped and counted separately, with a warning when the first one is seen.

If the input isn't Ethernet (for example a capture taken on Linux `any`), the
tool exits with an error and status 1 without creating the output file.

## Running it

Requires [uv](https://docs.astral.sh/uv/). uv fetches a suitable Python
(3.10+) and the only dependency, scapy, by itself.

### With uvx (no checkout needed)

Run it straight from GitHub:

```bash
uvx --from "git+https://github.com/dmcken/mikrotik_remote_capture#subdirectory=clean/tzsp_strip_py" \
    tzsp-strip raw.pcapng clean.pcapng
```

uv caches the build, so later runs start immediately. Add `@<tag-or-commit>`
after the repo URL to pin a version, e.g.
`git+https://github.com/dmcken/mikrotik_remote_capture@v0.2.0#subdirectory=clean/tzsp_strip_py`.

To keep `tzsp-strip` on your `PATH` instead:

```bash
uv tool install "git+https://github.com/dmcken/mikrotik_remote_capture#subdirectory=clean/tzsp_strip_py"
tzsp-strip raw.pcapng clean.pcapng
uv tool upgrade tzsp-strip      # later, to pick up changes
```

From a checkout, `uvx --from ./clean/tzsp_strip_py tzsp-strip ...` works the
same way.

### For development

```bash
cd clean/tzsp_strip_py
uv sync
uv run tzsp-strip raw.pcapng clean.pcapng
```

The code is in `src/tzsp_strip/`: `cli.py` (file handling and TZSP), `ip.py`
(Ethernet/VLAN/IP parsing) and `reassembly.py` (fragments). `uv run` always uses the working
copy, so edits take effect without reinstalling.

## Usage

```
tzsp-strip [-p PORT] <input> <output>
```

| Argument / flag | Default | Description |
|-----------------|---------|-------------|
| `<input>` | *(required)* | Capture to clean: pcapng or classic pcap (microsecond or nanosecond timestamps). |
| `<output>` | *(required)* | File to write. Always pcapng, whatever the input format. Overwritten if it exists. |
| `-p`, `--port PORT` | `37008` | UDP destination port the TZSP stream was sent to. |
| `-V`, `--version` | | Show version. |
| `-h`, `--help` | | Show help. |

### Example

```bash
tshark -f "udp port 37008" -w raw.pcapng       # capture the stream
tzsp-strip raw.pcapng clean.pcapng
```

Progress is logged every 100,000 packets, followed by a summary:

```
... - INFO - 100,000
... - INFO - 200,000
... - INFO - Completed processing 245,312 packets (17 skipped, not TZSP/unparseable; 0 skipped, non-Ethernet encapsulation; fragmented datagrams: 3,120 reassembled, 2 incomplete (dropped))
```

## Tests

The parser is checked against the shared cases in
[`testdata/tzsp_vectors.tsv`](../../testdata/tzsp_vectors.tsv), the same file
the Rust [`tzsp`](../../tzsp/README.md) crate tests against, so the two
implementations can't drift apart unnoticed:

```bash
uv run python -m unittest discover -s tests
```

## Limitations

- **Microsecond timestamps.** Output timestamps have microsecond resolution
  (scapy's pcapng writer is fixed at microseconds) and are converted through a
  float on the way, so nanosecond detail in the input is lost. Use
  [`tzsp_strip_rs`](../tzsp_strip_rs/README.md), which keeps nanoseconds, if
  you need it.
- No IPv6 ESP, Ethernet only. See the
  [parent README](../README.md#shared-limitations).
