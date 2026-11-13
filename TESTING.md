# Testing

## Automated tests

```bash
cargo test                                   # rust: all crates, including the shared parser cases
cd clean/tzsp_strip_py && uv run python -m unittest discover -s tests
```

Both run on every push (see `.github/workflows/ci.yml`). The parser cases in
[`testdata/tzsp_vectors.tsv`](testdata/tzsp_vectors.tsv) are shared by the
rust and python code; add new cases to `testdata/generate_vectors.py`.

## Live-network checklist

Some behaviour depends on real routers, links and load, and can't be covered
by the unit tests or a loopback test. Use this list to pick parts of the
network that exercise each case. For each one, note the RouterOS version and
the transport (IPv4 or IPv6) used for the stream.

### Fragmentation (most likely to matter)

The router adds 33 bytes (IPv4) or 53 bytes (IPv6) to each sniffed frame, so
full-size frames (1514 bytes) produce TZSP datagrams over a 1500-byte MTU.

- [ ] **Full-size traffic, IPv4 stream, `tzsp_ng_capture`.** Sniff an
      interface carrying bulk transfers. Expect full 1514-byte frames in the
      output and `unstrippable` staying at 0: the kernel reassembles the
      datagrams.
- [ ] **Same, IPv6 stream.** As above, over an IPv6 `streaming-server`.
- [ ] **Same traffic captured with tshark, then run through both
      strippers.** Expect the limitation documented in
      [clean/README.md](clean/README.md#shared-limitations): large frames
      skipped. Confirms how
      RouterOS fragments (or whether it sets DF and drops instead, which
      would show as missing large frames in `tzsp_ng_capture` too).
- [ ] **Path MTU raised to 1600+ between router and capture host.** Expect
      no fragmentation and full frames from the strippers too.

### IPv6 extension headers

- [ ] **IPv6 stream captured with tshark.** Run the check in
      [clean/README.md](clean/README.md#shared-limitations) for extension
      headers. Fragment headers (44) are expected with full-size traffic.
      Others (0, 43, 51, 60) mean something on the path adds them; the
      strippers handle those, but it's worth confirming on real traffic.
      ESP (50) can't be stripped.

### Load and drops (`tzsp_ng_capture`)

- [ ] **Sustained high packet rate.** Watch `kernel_dropped` in the stats
      lines. With the default `net.core.rmem_max` the startup line shows a
      small receive buffer; compare a run before and after raising it to
      8 MiB (see [tzsp_ng_capture/README.md](tzsp_ng_capture/README.md)).
- [ ] **Forced drops.** To check the counter itself works, run with the
      default small buffer and pause the process briefly under load
      (`kill -STOP <pid>`, then `kill -CONT <pid>` a few seconds later).
      Expect `kernel_dropped` to rise.
- [ ] **Rotation under load.** Use a small `-m` (e.g. `50MB`) and check that
      each file is at most that size, opens in Wireshark, and that packet
      counts across files add up to `written`.
- [ ] **Long idle periods.** Stop the router's sniffer for a while; the
      current file should stay readable (it's flushed about once a second),
      and capture should resume when the sniffer restarts.

### Encapsulations and framing

- [ ] **Stream reaching the capture host on a VLAN trunk**, captured with
      tshark on the trunk interface and stripped. Expect full output; also
      try QinQ if any part of the network uses it.
- [ ] **Sniffing a wireless interface.** Expect the non-Ethernet
      encapsulation warning and `non_ethernet_encap` (capture tool) or the
      separate skipped count (strippers), not mislabelled frames.
- [ ] **A capture taken with `tshark -i any`.** Expect the strippers to
      refuse it with the "captured on 'any'" error and write no output.
- [ ] **Several routers streaming to the same port.** All their frames are
      interleaved in one output with no way to tell them apart afterwards.
      Check whether that's acceptable, or use a different `-p` per router.

### Platforms

- [ ] **arm64 release binaries** (e.g. Raspberry Pi OS 64-bit, an arm64 VM
      or cloud instance): run both tools from a release tarball.
- [ ] **x86-64 release binaries on a non-glibc distribution** (e.g. Alpine),
      to confirm they're fully static.
