# Clean a capture file of TZSP

A mikrotik capture has packets with TZSP encapsulation.


## Using scapy

Scapy is a python library for packet manipulation.

```bash
time python3 clean/clean_pcap.py
Done

real    12m51.613s
user    12m40.736s
sys     0m6.687s
```

Pros:
* Easily adapts to changes in packet format.

Cons:
* Slow (relatively speaking) - By having to parse and analyze each packet its a much slower process.

## Using editcap

The Ethernet+IP+UDP+TZSP header *should* not change in size over the course of a capture.

Header lengths:
* IPv4 - 47
* IPv6 - ???

So an alternative method could be to blindly chop the header off of the begining of each packet.

```bash
editcap.exe -C 47 <input>.pcapng <output>.pcapng

time editcap -C 47 <input file>.pcap <output file>.pcap

real    0m2.855s
user    0m0.607s
sys     0m2.188s
```

Pros:
* As shown above its extremely fast (since it ignores parsing the packet entirely).

Cons:
* If the length of the header changes length for any reason, editcap will continue to crop the packet blindly so data can get corrupted or misformatted.

## Using rust

Test using 1GB pcap file.

```bash
time cargo run --release -- input.pcap output.pcap
   Compiling tzsp_strip_rs v0.1.0 (/home/dmcken/code/mikrotik_remote_capture/clean/tzsp_strip_rs)
    Finished `release` profile [optimized] target(s) in 0.40s
     Running `target/release/tzsp_strip_rs input.pcap output.pcap`
Done. Extracted packets are in output.pcap

real    0m3.677s
user    0m0.639s
sys     0m2.790s
```

Pros:
* Quite fast
* Actually parses packets for sanity check

# Alternative projects:

* [tzsp2pacp](https://github.com/thefloweringash/tzsp2pcap)
