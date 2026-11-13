# Clean a capture file of TZSP

A MikroTik sniffer stream captured as-is (e.g. with `tshark -f "udp port 37008"`)
contains every sniffed frame wrapped in Ethernet + IP + UDP + TZSP headers:

![Packet layout](Packet-layout.png)

To analyse the original traffic, those outer headers need to be removed. This
folder contains two tools that do that to an existing capture file, plus notes
on a quick-and-dirty `editcap` alternative.

To capture and strip in one step instead, see
[`../tzsp_ng_capture`](../tzsp_ng_capture/README.md).

## Tools

| Tool | Input | Output | Notes |
|------|-------|--------|-------|
| [`tzsp_strip_rs`](tzsp_strip_rs/README.md) | pcap or pcapng | pcap (ns timestamps) | Fastest. Pure Rust, no libpcap. |
| [`tzsp_strip_py`](tzsp_strip_py/README.md) | pcap or pcapng | pcapng (µs timestamps) | Easiest to modify. Runs with `uvx`, no build step. |

Both tools parse each packet (Ethernet → optional VLAN tags → IPv4 or IPv6 →
UDP → TZSP, including TZSP tagged fields) and only write the inner frame.
Packets that aren't valid TZSP, or don't parse cleanly, are skipped instead of
being written still wrapped.

### Shared limitations

- **No IP reassembly: large frames get lost.** The router adds IP + UDP +
  TZSP headers (33 bytes over IPv4, 53 over IPv6) to every sniffed frame, so
  any frame bigger than about 1,467 bytes (IPv4) or 1,447 bytes (IPv6) doesn't
  fit a 1500-byte MTU, and the router fragments the TZSP datagram. On busy
  links that is every full-size packet. In a capture file, the strippers then:
  - **IPv4 transport:** write the first fragment's part of the frame,
    truncated, and skip the remaining fragments.
  - **IPv6 transport:** skip the whole frame, since the fragments carry an
    IPv6 Fragment extension header (see below).

  To avoid this, either use [`tzsp_ng_capture`](../tzsp_ng_capture/README.md),
  where the kernel reassembles the datagrams before the tool sees them, or
  raise the MTU along the whole path from the router to the capture host to
  at least 1,600 so nothing is fragmented. The `skipped` count rises when it
  happens.
- **No IPv6 extension headers.** For IPv6 transport, UDP must directly follow
  the IPv6 header. RouterOS doesn't add extension headers to the stream, so in
  practice the only one seen is the Fragment header above.
- **Ethernet only.** The input must use the Ethernet link type. Anything else,
  such as a capture taken with `tshark -i any` (Linux cooked/SLL framing), is
  rejected at startup with an error, not silently skipped.
- **Ethernet-in-TZSP only.** The TZSP header says what kind of frame it
  carries. Only Ethernet (1) is written. Other types, such as 802.11 from
  sniffing a wireless interface, are skipped and counted separately, with a
  warning when the first one is seen. The output file can only be labelled with
  one link type, so mixing them would mislabel frames.

## Using rust

Test using a 1GB pcap file:

```bash
time ./target/release/tzsp_strip_rs input.pcap output.pcap
Done. <n> packets written to output.pcap, <n> skipped (not TZSP/unparseable), <n> skipped (non-Ethernet encapsulation)

real    0m3.677s
user    0m0.639s
sys     0m2.790s
```

Pros:
* Quite fast.
* Actually parses packets as a sanity check.

## Using Python

The Python tool uses scapy only to read and write the capture file. It parses
the headers directly from the raw bytes, using the same logic as the Rust tool.
An earlier version built scapy's full layer objects for every packet and took
about 13 minutes on the same 1GB file. The current version is roughly 50×
faster.

Pros:
* Easy to modify.
* Logs progress every 100,000 packets on large files.

Cons:
* Still slower than the Rust tool.

## Using editcap

The Ethernet + IP + UDP + TZSP header *should* not change in size over the
course of a capture. For a minimal TZSP header (4 fixed bytes + END tag) the
header lengths are:

* IPv4: 14 + 20 + 8 + 5 = **47** bytes
* IPv6: 14 + 40 + 8 + 5 = **67** bytes

So an alternative method is to blindly chop that many bytes off the beginning of
each packet:

```bash
time editcap -C 47 <input file>.pcap <output file>.pcap

real    0m2.855s
user    0m0.607s
sys     0m2.188s
```

Pros:
* Extremely fast, since it doesn't parse the packets at all.

Cons:
* If the header length changes for any reason (IP options, extra TZSP tags,
  non-TZSP packets in the capture), editcap keeps cropping blindly and the
  output is corrupted.

## Alternative projects

* [tzsp2pcap](https://github.com/thefloweringash/tzsp2pcap)
