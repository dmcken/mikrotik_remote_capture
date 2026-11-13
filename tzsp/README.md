# tzsp

Dependency-free TZSP (TaZmen Sniffer Protocol) parsing shared by the Rust tools
in this repo:

- [`tzsp_ng_capture`](../tzsp_ng_capture/README.md) uses `strip()` on each UDP
  payload it receives.
- [`tzsp_strip_rs`](../clean/tzsp_strip_rs/README.md) uses `strip_frame()` on
  each Ethernet frame in a capture file.

| Item | Purpose |
|------|---------|
| `strip(payload)` | Remove the TZSP header from a UDP payload. Returns `(encapsulation, frame)` or `None`. |
| `strip_frame(frame, port)` | Remove the whole Ethernet/IPv4-or-IPv6/UDP/TZSP wrapper from a captured frame, checking the UDP destination port. Same return value. |
| `parse_header(buf)` | Length of the TZSP header (fixed part plus tagged fields up to END), or `None`. |
| `DEFAULT_PORT`, `ENCAP_ETHERNET` | 37008 and 1. |
| `encap_name(encap)` | Readable name for an encapsulation value, for messages. |
| `is_linux_cooked(linktype)` | True for the Linux "any" capture link types, to explain why such input is rejected. |
| `pcap::PcapWriter` | Writes the tools' output: classic pcap, nanosecond timestamps, link type Ethernet, with an exact running byte count (used for rotation). |

## Tests

```bash
cargo test -p tzsp
```

Besides unit tests, this runs every case in
[`../testdata/tzsp_vectors.tsv`](../testdata/tzsp_vectors.tsv). The Python
stripper ([`clean/tzsp_strip_py`](../clean/tzsp_strip_py/README.md)) is a port
of this crate and runs the same file, so a change made to one parser and not
the other fails the tests. To add or change a case, edit
`testdata/generate_vectors.py` and re-run it.
