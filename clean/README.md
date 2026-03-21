# Clean a capture file of TZSP

A mikrotik capture has packets with TZSP encapsulation.


## Using scapy

Scapy is a pythong

```bash
time python3 clean/clean_pcap.py
Done

real    12m51.613s
user    12m40.736s
sys     0m6.687s
```

Pros:
* Adapts to changes in packet format.

Cons:
* Slow - By having to parse and analyze each packet its a much slower process.

## Using editcap

The Ethernet+IP+UDP+TZSP header *should* not change in size over the course of a capture.

Header lengths:
* IPv4 - 47
* IPv6 - ???

So an alternative method could be to blindly chop the header off of the begining of each packet.

```bash
editcap.exe -C 47 ./200909_MikroTik_TZSP.pcapng ./200909_MikroTik_TZSP_chop.pcapng

time editcap -C 47 SIL-issues_00050_20241211045848.pcap SIL-issues_00050_20241211045848-editcap.pcap

real    0m2.855s
user    0m0.607s
sys     0m2.188s
```

Pros:
* As shown above its extremely fast.

Cons:
* If the length of the header changes length for any reason, editcap will continue to crop the packet to the

# Alternative projects:

* [tzsp2pacp](https://github.com/thefloweringash/tzsp2pcap)
