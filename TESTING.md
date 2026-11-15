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

- [x] **Full-size traffic, IPv4 stream, `tzsp_ng_capture`.** Sniff an
      interface carrying bulk transfers. Expect full 1514-byte frames in the
      output and `unstrippable` staying at 0: the kernel reassembles the
      datagrams.
      **2026-11-14, router A (RouterOS 7.25), IPv4 stream:** sniffed the whole
      `trunk` interface (real production traffic, all VLANs) to
      `tzsp_ng_capture` over IPv4. 336,432 frames written, frames up to
      ~1970 bytes, `unstrippable=0`. Confirmed working.
- [ ] **Same, IPv6 stream.** As above, over an IPv6 `streaming-server`.
      **Not testable on this fleet currently:** RouterOS 7.25's
      `/tool sniffer streaming-server` rejects an IPv6 literal outright
      (`invalid value for argument ip`) on both router A and router B -- the
      parameter is IPv4-only on this RouterOS version. `tzsp_ng_capture`
      itself listens fine on `[::]`; the gap is entirely on the RouterOS
      sender side. Revisit if/when a RouterOS version accepts IPv6 here.
- [ ] **Same traffic captured with tshark, then run through both
      strippers.** Expect full 1514-byte frames, a non-zero `reassembled`
      count and `incomplete` at or near 0. Compare against a
      `tzsp_ng_capture` run of the same traffic: frame counts should be close.
      Also confirms how RouterOS fragments (or whether it sets DF and drops
      instead, which would show as missing large frames in both).
      **Partially attempted, inconclusive -- 2026-11-14, router A, IPv4,
      `tzsp_strip_rs` only:**
      the router A-to-capture-host path turned out to be jumbo (MTU 8000,
      confirmed by DF-bit pings up to 8000 bytes), so no fragmentation
      occurred to reassemble (295,482 packets, `0 reassembled, 0 incomplete`).
      This path can't exercise reassembly; see the MTU-1600+ item below,
      and still needs a real sub-1500 MTU path. `tzsp_strip_py` not run
      against this capture.
- [ ] **Over a tunnel** (lower MTU, so mid-size frames fragment too, possibly
      into three or more pieces). Same expectations.
      Looked for one: router A has real customer EoIP tunnels at
      actual-mtu=1458, but those are low-MTU on the
      *sniffed* side, not on the router-to-capture-host path that actually
      determines TZSP fragmentation -- using them as the sniff target
      wouldn't exercise this case. Would need a genuinely low-MTU path
      *to the capture host*, which doesn't exist naturally on this network
      (see below); building one was deliberately held off.
- [ ] **A lossy path.** If any link drops packets, `incomplete` should rise
      roughly in line with the loss; frames are never written truncated.
- [x] **Path MTU raised to 1600+ between router and capture host.** Expect
      `reassembled` to stay at 0.
      **2026-11-14, router A -> capture host:** confirmed jumbo end-to-end --
      DF-bit pings up to 8000 bytes succeed; router B -> capture host also
      succeeds at 8000 but times out at 9000, so somewhere in between, still
      well over 1600. `reassembled` stayed at 0 as expected on both the
      live capture and the offline `tzsp_strip_rs` run. No sub-1500 MTU path
      was found anywhere reachable from either router to this capture host;
      a deliberate low-MTU tunnel would be needed to test actual
      fragmentation/reassembly, and the user held off on building one for
      now (see the "Over a tunnel" item above).

### IPv6 extension headers

- [ ] **IPv6 stream captured with tshark.** Run the check in
      [clean/README.md](clean/README.md#shared-limitations) for extension
      headers. Fragment headers (44) are expected with full-size traffic.
      Others (0, 43, 51, 60) mean something on the path adds them; the
      strippers handle those, but it's worth confirming on real traffic.
      ESP (50) can't be stripped.
      Not tested -- blocked on the same IPv6 `streaming-server` gap above.

### Load and drops (`tzsp_ng_capture`)

- [x] **Sustained high packet rate.** Watch `kernel_dropped` in the stats
      lines. With the default `net.core.rmem_max` the startup line shows a
      small receive buffer; compare a run before and after raising it to
      8 MiB (see [tzsp_ng_capture/README.md](tzsp_ng_capture/README.md)).
      **2026-11-14, router A full `trunk` stream, after raising
      `net.core.rmem_max` to 8 MiB:** 7,689,906 packets written over ~100s,
      `kernel_dropped` rose from 0 to 14,499 (~0.19%) as load increased --
      confirms the counter tracks real loss under genuine sustained load.
      Did not separately re-run with the default (small) buffer to compare
      drop rates before/after raising it.
- [ ] **Forced drops.** To check the counter itself works, run with the
      default small buffer and pause the process briefly under load
      (`kill -STOP <pid>`, then `kill -CONT <pid>` a few seconds later).
      Expect `kernel_dropped` to rise.
- [x] **Rotation under load.** Use a small `-m` (e.g. `50MB`) and check that
      each file is at most that size, opens in Wireshark, and that packet
      counts across files add up to `written`.
      **2026-11-14, router A, `-m 500MB`:** rotated every ~23-25s under the
      sustained high rate above; multiple completed rotation files opened
      cleanly in tshark (the single still-open file reported "cut short"
      by tshark, as expected for a live, not-yet-flushed file -- not
      corruption). Did not explicitly sum per-file packet counts against
      the `written` stat.
- [ ] **Long idle periods.** Stop the router's sniffer for a while; the
      current file should stay readable (it's flushed about once a second),
      and capture should resume when the sniffer restarts.

### Encapsulations and framing

- [x] **Stream reaching the capture host on a VLAN trunk**, captured with
      tshark on the trunk interface and stripped. Expect full output; also
      try QinQ if any part of the network uses it.
      **2026-11-14, router A `trunk` interface:** 184,013 of 336,432 frames
      were VLAN-tagged real production traffic, parsed and stripped cleanly
      (`eth -> vlan -> ip -> udp` hierarchy intact, no mislabelled frames).
      QinQ not available on this network segment, not tested.
- [ ] **Sniffing a wireless interface.** Expect the non-Ethernet
      encapsulation warning and `non_ethernet_encap` (capture tool) or the
      separate skipped count (strippers), not mislabelled frames.
      Not tested -- router A has no wireless interfaces (`non_ethernet_encap`
      stayed 0 throughout, as expected for an all-Ethernet device, but that
      doesn't exercise this case).
- [ ] **A capture taken with `tshark -i any`.** Expect the strippers to
      refuse it with the "captured on 'any'" error and write no output.
- [ ] **Several routers streaming to the same port.** All their frames are
      interleaved in one output with no way to tell them apart afterwards.
      Check whether that's acceptable, or use a different `-p` per router.
      Deliberately avoided rather than tested: router B and router A were each
      given a distinct `-p` (37008 / 37009) specifically to keep their
      captures separable, so this interleaving behaviour itself hasn't
      actually been observed yet.

### Platforms

- [ ] **arm64 release binaries** (e.g. Raspberry Pi OS 64-bit, an arm64 VM
      or cloud instance): run both tools from a release tarball.
      Not tested -- only x86-64 builds were used/deployed so far.
- [ ] **x86-64 release binaries on a non-glibc distribution** (e.g. Alpine),
      to confirm they're fully static.
      Not tested directly on Alpine. Built via `cargo build --release
      --target x86_64-unknown-linux-musl` in a `rust:1-bookworm` (glibc)
      Docker container and confirmed `file` reports "static-pie linked" with
      no dynamic interpreter, and deployed/ran fine on the (glibc) capture
      host -- consistent with being fully static, but not actually run on a
      musl/non-glibc distro.
