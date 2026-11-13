# Mikrotik Remote Capture

Problem definition: Mikrotik routers have a streaming packet capture feature (see below)

Via winbox:

![Mikrotik capture](Mikrotik-capture.png)

Via the Mikrotik CLI:
```
/tool sniffer
set filter-interface=trunk-v0010 filter-ip-address=\
    10.16.16.15/32 filter-operator-between-entries=and filter-stream=yes \
    streaming-enabled=yes streaming-server=172.16.0.195
```

The simplest way to capture this stream is with tshark:

```bash
tshark -f "udp port 37008"
```

Or with automatic rotation:

```bash
tshark -f "udp port 37008" -w SIL-issues.pcap -b filesize:1048576
```

This leaves the TZSP headers in place however, to use more advanced tools you would want to strip those headers (Frame -> Ethernet -> IP -> UDP).


## Tools

* clean/ contains both a python and rust tools to remove the TZSP headers from an existing capture.
* tzsp_ng_capture/ is a rust program that receives the stream on a UDP socket (no root or libpcap needed) and strips the header before writing to disk.
* tzsp/ is the TZSP parsing library shared by the rust tools.
* testdata/ holds parser test cases shared by the rust and python implementations.

### Prebuilt binaries

Each [release](https://github.com/dmcken/mikrotik_remote_capture/releases)
has static Linux binaries of both rust tools (`tzsp_ng_rotator` and
`tzsp_strip_rs`) for x86-64 and arm64. They have no dependencies, so they run
on any distribution, including Alpine and Raspberry Pi OS (64-bit):

```bash
curl -LO https://github.com/dmcken/mikrotik_remote_capture/releases/download/<version>/mikrotik-tzsp-tools-<version>-linux-x86_64.tar.gz
tar -xzf mikrotik-tzsp-tools-<version>-linux-x86_64.tar.gz
```

Use `linux-arm64` in place of `linux-x86_64` for arm64. `SHA256SUMS` in each
release has the checksums.

### Running the python tool

The python stripper runs straight from this repo with
[uv](https://docs.astral.sh/uv/), no checkout or build step needed:

```bash
uvx --from "git+https://github.com/dmcken/mikrotik_remote_capture#subdirectory=clean/tzsp_strip_py" \
    tzsp-strip raw.pcapng clean.pcapng
```

See [clean/tzsp_strip_py](clean/tzsp_strip_py/README.md) for details.

### Building the rust tools

The rust code is a single Cargo workspace. From the repo root:

```bash
cargo build --release   # binaries land in target/release/
cargo test              # runs every crate's tests, including the shared parser cases
```

### Making a release

Push a version tag. The [release workflow](.github/workflows/release.yml)
runs the tests on both architectures, builds the static binaries and creates
the GitHub release:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

Every push also runs the rust and python tests ([CI workflow](.github/workflows/ci.yml)).

## Notes

* Underlying protocol - Tazmen Sniffer protocol