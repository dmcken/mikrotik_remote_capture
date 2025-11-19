# Mikrotik Remote Capture

Mikrotik Remote packet capture


Problem definition: Mikrotik routers have a streaming packet capture feature.

The simplest way to capture this stream is with tshark:

```bash
tshark -f "udp port 37008"
```

This leaves the TZSP headers in place however, to use more advanced tools you would want the strip those headers (Frame -> Ethernet -> IP -> UDP).