'''Clean a mikrotik / TZSP capture file.

'''

# System imports
import argparse
import importlib.metadata
import logging
import sys

# Scapy imports
import scapy.utils

from tzsp_strip import ip
from tzsp_strip.ip import read_u16 as _read_u16

logger = logging.getLogger(__name__)

UDP_LEN = 8
LINKTYPE_ETHERNET = 1
LINKTYPES_LINUX_SLL = (113, 276)  # what captures on Linux "any" use

# TZSP encapsulation values (bytes 2-3 of the TZSP header). Only
# Ethernet is written, since the output is labelled as Ethernet.
TZSP_ENCAP_ETHERNET = 1
TZSP_ENCAP_NAMES = {
    1: 'Ethernet',
    18: 'IEEE 802.11',
    119: 'Prism header',
    127: '802.11 AVS',
}


def parse_tzsp_header(buf: bytes) -> int | None:
    '''Walk a TZSP header's tag list and return its total size.

    Python port of parse_header() in the Rust tzsp crate (tzsp/src/lib.rs);
    both are checked against testdata/tzsp_vectors.tsv. Tag 0 (PADDING)
    and tag 1 (END) are both zero-length (no length byte of their own,
    unlike every other tag); RouterOS emits PADDING for alignment, and
    treating it like a normal tagged field desyncs the rest of the walk.
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


def strip_tzsp_payload(tzsp: bytes) -> tuple[int, bytes] | None:
    '''Strip the TZSP header from a UDP payload.

    Python port of strip() in the Rust tzsp crate. Returns
    (encapsulation, inner_frame), or None if the header can't be walked
    cleanly or carries no frame (e.g. keepalives).
    '''
    tzsp_hdr_len = parse_tzsp_header(tzsp)
    if tzsp_hdr_len is None or tzsp_hdr_len >= len(tzsp):
        return None

    # parse_tzsp_header() guarantees the 4-byte fixed header exists.
    encapsulation = _read_u16(tzsp, 2)

    return encapsulation, tzsp[tzsp_hdr_len:]


def strip_tzsp(data: bytes, tzsp_port: int) -> tuple[int, bytes] | None:
    '''Strip TZSP/UDP/IP/Ethernet headers from a raw captured frame.

    Python port of strip_frame() in the Rust tzsp crate. Handles TZSP
    carried over either IPv4 or IPv6, optionally inside any number of
    VLAN tags (802.1Q, 802.1ad/QinQ) and with IPv6 extension headers
    (Hop-by-Hop, Routing, Destination Options, AH) before the UDP header.
    On success returns (encapsulation, inner_frame), where encapsulation
    is the TZSP encapsulation type (1 = Ethernet, 18 = 802.11, ...) that
    callers must check before writing the frame. Returns None whenever
    the frame isn't a recognisable TZSP packet on tzsp_port, or its TZSP
    header can't be walked cleanly -- callers should skip these rather
    than writing them through unstripped.

    IP fragments are rejected too, since they need reassembling first.
    '''
    udp = ip.parse(data)
    if not isinstance(udp, bytes):
        return None
    return strip_udp(udp, tzsp_port)


def strip_udp(udp: bytes, tzsp_port: int) -> tuple[int, bytes] | None:
    '''Strip the UDP and TZSP headers from a UDP datagram sent to tzsp_port.'''
    if len(udp) < UDP_LEN or _read_u16(udp, 2) != tzsp_port:
        return None
    return strip_tzsp_payload(udp[UDP_LEN:])


def parse_argument() -> argparse.Namespace:
    """Parse cli arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
                    prog='tzsp-strip',
                    description='Strip the Ethernet/IP/UDP/TZSP wrapper from a MikroTik '
                                'sniffer capture, writing only the original frames.',
                    epilog='Input may be pcap or pcapng; output is always pcapng.')

    parser.add_argument('input', help='capture file to clean (pcap or pcapng)')
    parser.add_argument('output', help='pcapng file to write (overwritten if it exists)')

    parser.add_argument('-p', '--port', default=37008, type=int,
                        help='UDP destination port the TZSP stream was sent to (default: %(default)s)')
    parser.add_argument('-V', '--version', action='version',
                        version=f"%(prog)s {importlib.metadata.version('tzsp-strip')}")

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
    non_ethernet = 0
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

                result = strip_tzsp(pkt_bytes, args.port)
                if result is None:
                    skipped += 1
                    continue

                encapsulation, cleaned = result
                if encapsulation != TZSP_ENCAP_ETHERNET:
                    # Valid TZSP, but carrying something other than Ethernet
                    # (e.g. 802.11). The output is labelled as Ethernet, so
                    # writing it would mislabel the frame.
                    if non_ethernet == 0:
                        logger.warning(
                            "Skipping TZSP packets with non-Ethernet encapsulation "
                            f"{encapsulation} ({TZSP_ENCAP_NAMES.get(encapsulation, 'unknown')}); "
                            f"only Ethernet ({TZSP_ENCAP_ETHERNET}) is supported")
                    non_ethernet += 1
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

    logger.info(f"Completed processing {count:,} packets ({skipped:,} skipped, not TZSP/unparseable; "
                f"{non_ethernet:,} skipped, non-Ethernet encapsulation)")

if __name__ == '__main__':
    main()
