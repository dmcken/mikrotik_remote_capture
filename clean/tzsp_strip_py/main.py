'''Clean a mikrotik / TZSP capture file.

'''

# System imports
import argparse
import logging

# Scapy imports
import scapy.utils

logger = logging.getLogger(__name__)

ETHER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPV4_MIN_LEN = 20
IPV6_LEN = 40
IPPROTO_UDP = 17


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
    with scapy.utils.RawPcapNgReader(args.input) as cap_file, \
        scapy.utils.RawPcapNgWriter(args.output) as output_file:
        count = 0
        skipped = 0
        for pkt_bytes, meta in cap_file:
            if meta.tshigh is None:
                pkt_time = None
            else:
                pkt_time = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol

            if not hasattr(output_file, 'linktype'):
                output_file.linktype = meta.linktype
            # write_packet() (unlike write(), which we can't use here
            # since it doesn't accept sec=/preserve original packet
            # timestamps) never writes the Section Header + Interface
            # Description preamble itself -- only write() does that,
            # via write_header(). Do it ourselves, once.
            if not output_file.header_present:
                output_file.write_header(None)

            cleaned = strip_tzsp(pkt_bytes, args.port)
            if cleaned is None:
                skipped += 1
                continue

            output_file.write_packet(cleaned, sec=pkt_time)
            count += 1
            if count % modulus == 0:
                logger.info(f"{count:,}")

    logger.info(f"Completed processing {count:,} packets ({skipped:,} skipped, not TZSP/unparseable)")

if __name__ == '__main__':
    main()
