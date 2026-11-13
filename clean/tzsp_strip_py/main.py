'''Clean a mikrotik / TZSP capture file.

'''

# System imports
import argparse
import logging
import sys

# Scapy imports
import scapy.utils

logger = logging.getLogger(__name__)

ETHER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPV4_MIN_LEN = 20
IPV6_LEN = 40
IPPROTO_UDP = 17
LINKTYPE_ETHERNET = 1
LINKTYPES_LINUX_SLL = (113, 276)  # what captures on Linux "any" use


def _read_u16(buf: bytes, offset: int) -> int:
    return (buf[offset] << 8) | buf[offset + 1]


def parse_tzsp_header(buf: bytes) -> int | None:
    '''Walk a TZSP header's tag list and return its total size.

    Mirrors tzsp_ng_capture/clean/tzsp_strip_rs's own parse_tzsp_header
    (Rust) -- tag 0 (PADDING) and tag 1 (END) are both zero-length (no
    length byte of their own, unlike every other tag); RouterOS emits
    PADDING for alignment, and treating it like a normal tagged field
    desyncs the rest of the walk.
    '''
    if len(buf) < 4:
        return None

    # TZSP fixed header: version (1) + type (1) + proto (2)
    offset = 4
    buf_len = len(buf)

    while offset < buf_len:
        tag = buf[offset]
        offset += 1

        if tag == 1:
            # END tag -- zero-length, no value byte follows.
            return offset

        if tag == 0:
            # PADDING tag -- also zero-length.
            continue

        if offset >= buf_len:
            return None

        tag_len = buf[offset]
        offset += 1 + tag_len

        if offset > buf_len:
            return None

    return None


def strip_tzsp(data: bytes, tzsp_port: int) -> bytes | None:
    '''Strip TZSP/UDP/IP/Ethernet headers from a raw captured frame.

    Handles TZSP carried over either IPv4 or IPv6. Returns None
    whenever the frame isn't a recognisable Ethernet/IPv4-or-IPv6/UDP/
    TZSP packet on tzsp_port, or its TZSP header can't be walked
    cleanly -- callers should skip these rather than writing them
    through unstripped.
    '''
    if len(data) < ETHER_LEN:
        return None

    # ----------------------------
    # Ethernet + IP
    # ----------------------------
    ether_type = _read_u16(data, 12)
    ip = data[ETHER_LEN:]

    if ether_type == ETHERTYPE_IPV4:
        if len(ip) < IPV4_MIN_LEN:
            return None
        ihl = (ip[0] & 0x0F) * 4
        if ihl < IPV4_MIN_LEN or len(ip) < ihl:
            return None
        if ip[9] != IPPROTO_UDP:
            return None
        udp = ip[ihl:]
    elif ether_type == ETHERTYPE_IPV6:
        if len(ip) < IPV6_LEN:
            return None
        # Next Header must be UDP directly. Extension headers
        # (hop-by-hop, routing, fragment, ...) aren't walked; a TZSP
        # stream shouldn't normally carry any.
        if ip[6] != IPPROTO_UDP:
            return None
        udp = ip[IPV6_LEN:]
    else:
        return None

    # ----------------------------
    # UDP
    # ----------------------------
    if len(udp) < 8:
        return None

    dst_port = _read_u16(udp, 2)
    if dst_port != tzsp_port:
        return None

    # ----------------------------
    # TZSP
    # ----------------------------
    tzsp = udp[8:]

    tzsp_hdr_len = parse_tzsp_header(tzsp)
    if tzsp_hdr_len is None or tzsp_hdr_len >= len(tzsp):
        return None

    return tzsp[tzsp_hdr_len:]


def parse_argument() -> argparse.Namespace:
    """Parse cli arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

    parser.add_argument('input')
    parser.add_argument('output')

    parser.add_argument('-p','--port', default=37008, type=int)

    args = parser.parse_args()

    # Setup logging
    basic_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
            encoding='utf-8',
            level=logging.INFO,
            format=basic_format,
    )

    return args

def _packet_time_and_linktype(cap_file, meta) -> tuple[float | None, int]:
    '''Return a packet's timestamp (seconds since epoch) and link type.

    RawPcapNgReader transparently falls back to RawPcapReader for
    classic pcap input, and the two yield different metadata:
    pcapng has per-packet tshigh/tslow/tsresol/linktype, while classic
    pcap has sec/usec per packet and a single file-wide linktype on the
    reader. In nanosecond-resolution classic pcap files the "usec"
    field actually holds nanoseconds.
    '''
    if hasattr(meta, 'tshigh'):
        if meta.tshigh is None:
            pkt_time = None
        else:
            pkt_time = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol
        return pkt_time, meta.linktype

    frac_div = 1_000_000_000 if cap_file.nano else 1_000_000
    return meta.sec + meta.usec / frac_div, cap_file.linktype


def _open_output(path: str) -> scapy.utils.RawPcapNgWriter:
    '''Open the pcapng output, labelled as Ethernet, with its header written.

    write_packet() (unlike write(), which we can't use here since it
    doesn't accept sec=/preserve original packet timestamps) never
    writes the Section Header + Interface Description preamble itself --
    only write() does that, via write_header(). Do it ourselves, once.
    '''
    output_file = scapy.utils.RawPcapNgWriter(path)
    output_file.linktype = LINKTYPE_ETHERNET
    output_file.write_header(None)
    return output_file


def main() -> None:
    '''Main'''
    args = parse_argument()

    modulus = 100_000

    # RawPcapNgReader/RawPcapNgWriter hand back/accept plain bytes --
    # unlike PcapNgReader/PcapNgWriter (the previous approach), they
    # never build Scapy's full Ether/IP/UDP/TZSP/... layer-object
    # graph per packet, which was almost all of this tool's runtime
    # (confirmed: a ~1.3M-packet real capture was ~99% user/CPU time,
    # not I/O, and the stock Rust stripper processes the same file in
    # well under a second). Stripping is now done directly on the raw
    # bytes, the same TZSP-TLV walk the Rust tools in this repo use.
    #
    # Input may be pcapng or classic pcap (see _packet_time_and_linktype);
    # output is always pcapng.
    #
    # The writer is only opened once the first packet's link type has
    # been checked, so a rejected input doesn't leave an empty output
    # file behind.
    output_file = None
    count = 0
    skipped = 0
    with scapy.utils.RawPcapNgReader(args.input) as cap_file:
        try:
            for pkt_bytes, meta in cap_file:
                pkt_time, linktype = _packet_time_and_linktype(cap_file, meta)

                # The parser assumes Ethernet framing; anything else
                # (e.g. a Linux cooked capture taken on "any") would
                # make every packet unstrippable, so stop with a clear
                # error instead.
                if linktype != LINKTYPE_ETHERNET:
                    msg = (f"Input '{args.input}' has link type {linktype}; "
                           f"only Ethernet ({LINKTYPE_ETHERNET}) is supported.")
                    if linktype in LINKTYPES_LINUX_SLL:
                        msg += (" It looks like it was captured on 'any'; capture on the "
                                "specific interface that receives the TZSP stream instead.")
                    sys.exit(msg)

                if output_file is None:
                    output_file = _open_output(args.output)

                cleaned = strip_tzsp(pkt_bytes, args.port)
                if cleaned is None:
                    skipped += 1
                    continue

                output_file.write_packet(cleaned, sec=pkt_time)
                count += 1
                if count % modulus == 0:
                    logger.info(f"{count:,}")
        finally:
            if output_file is not None:
                output_file.close()

    if output_file is None:
        # Input had no packets at all: still produce a valid, empty
        # output file rather than nothing.
        _open_output(args.output).close()

    logger.info(f"Completed processing {count:,} packets ({skipped:,} skipped, not TZSP/unparseable)")

if __name__ == '__main__':
    main()
