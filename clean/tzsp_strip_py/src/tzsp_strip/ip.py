'''Ethernet, VLAN and IP parsing for frames read from a capture file.

Python port of tzsp/src/ip.rs in the Rust tzsp crate. Finds the UDP
datagram carrying the TZSP stream, or, if the IP packet is a fragment, the
fragment's details for reassembly.
'''

from typing import NamedTuple

ETHER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
# Ethertypes (TPIDs) that introduce a VLAN tag: 802.1Q, 802.1ad (QinQ outer
# tag) and the pre-standard 0x9100 some switches use for QinQ.
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
IPV4_MIN_LEN = 20
IPV6_LEN = 40

IPPROTO_UDP = 17
IPPROTO_HOP_BY_HOP = 0
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_DEST_OPTS = 60
IPV6_FRAGMENT_HEADER_LEN = 8


def read_u16(buf: bytes, offset: int) -> int:
    return (buf[offset] << 8) | buf[offset + 1]


class Fragment(NamedTuple):
    '''One fragment of a larger IP datagram.'''
    # Identifies the datagram (RFC 791, RFC 8200):
    # (4, src, dst, id) or (6, src, dst, id). IPv4 fragments are only kept
    # for UDP, so the protocol isn't needed.
    key: tuple
    # Byte offset of data in the reassembled payload.
    offset: int
    # More fragments follow (False on the last one).
    more: bool
    # Protocol of the reassembled payload: UDP for IPv4; for IPv6, the
    # Fragment header's Next Header (UDP, or an extension header before it).
    next_header: int
    data: bytes


def parse(frame: bytes) -> bytes | Fragment | None:
    '''Parse an Ethernet frame down to its UDP datagram or IP fragment.

    Returns the whole UDP datagram (header and payload) as bytes, a
    Fragment, or None for anything else (other ethertypes or protocols,
    ESP, malformed headers).

    Skips VLAN tags, and walks IPv6 extension headers (Hop-by-Hop, Routing,
    Destination Options, AH, Fragment). The IP length fields are used to drop
    Ethernet padding or trailers. If the frame was cut short by the
    capture's snap length, an unfragmented datagram is returned as far as it
    goes, but a fragment is rejected, as it would corrupt the reassembled
    datagram.
    '''
    if len(frame) < ETHER_LEN:
        return None

    # Skip any VLAN tags (4 bytes each: TPID, then TCI) to reach the real
    # ethertype.
    ether_type_at = 12
    while read_u16(frame, ether_type_at) in VLAN_TPIDS:
        ether_type_at += 4
        if len(frame) < ether_type_at + 2:
            return None

    ip = frame[ether_type_at + 2:]
    ether_type = read_u16(frame, ether_type_at)
    if ether_type == ETHERTYPE_IPV4:
        return _parse_ipv4(ip)
    if ether_type == ETHERTYPE_IPV6:
        return _parse_ipv6(ip)
    return None


def _payload(ip: bytes, header_len: int, total_len: int) -> tuple[bytes, bool]:
    '''The IP payload per the header's length field, and whether all of it
    was captured.'''
    if total_len <= len(ip):
        return ip[header_len:total_len], True
    return ip[header_len:], False


def _parse_ipv4(ip: bytes) -> bytes | Fragment | None:
    if len(ip) < IPV4_MIN_LEN:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_len = read_u16(ip, 2)
    if ihl < IPV4_MIN_LEN or len(ip) < ihl or total_len < ihl or ip[9] != IPPROTO_UDP:
        return None
    data, complete = _payload(ip, ihl, total_len)

    flags_offset = read_u16(ip, 6)
    more = bool(flags_offset & 0x2000)
    offset = (flags_offset & 0x1FFF) * 8
    if not more and offset == 0:
        return data
    if not complete:
        return None
    return Fragment((4, ip[12:16], ip[16:20], read_u16(ip, 4)), offset, more, IPPROTO_UDP, data)


def _parse_ipv6(ip: bytes) -> bytes | Fragment | None:
    if len(ip) < IPV6_LEN:
        return None
    data, complete = _payload(ip, IPV6_LEN, IPV6_LEN + read_u16(ip, 4))

    upper = walk_ipv6_extension_headers(ip[6], data)
    if upper is None or isinstance(upper, bytes):
        return upper

    header, rest = upper
    next_header = header[0]
    offset_flags = read_u16(header, 2)
    offset = offset_flags & 0xFFF8
    more = bool(offset_flags & 1)
    if offset == 0 and not more:
        # An "atomic" fragment (RFC 6946): the whole datagram.
        upper = walk_ipv6_extension_headers(next_header, rest)
        return upper if isinstance(upper, bytes) else None
    if not complete:
        return None
    return Fragment((6, ip[8:24], ip[24:40], int.from_bytes(header[4:8], 'big')),
                    offset, more, next_header, rest)


def walk_ipv6_extension_headers(next_header: int, buf: bytes) -> bytes | tuple[bytes, bytes] | None:
    '''Walk IPv6 extension headers, starting with protocol next_header at the
    start of buf, until reaching UDP or a Fragment header.

    Returns the UDP datagram as bytes, (fragment_header, rest) for a
    Fragment header, or None for any other protocol (including ESP, which
    can't be looked inside) or a truncated header.
    '''
    while True:
        if next_header == IPPROTO_UDP:
            return buf
        if next_header == IPPROTO_FRAGMENT:
            if len(buf) < IPV6_FRAGMENT_HEADER_LEN:
                return None
            return buf[:IPV6_FRAGMENT_HEADER_LEN], buf[IPV6_FRAGMENT_HEADER_LEN:]
        if len(buf) < 2:
            return None
        if next_header in (IPPROTO_HOP_BY_HOP, IPPROTO_ROUTING, IPPROTO_DEST_OPTS):
            # Length in 8-octet units, not counting the first 8 octets.
            length = (buf[1] + 1) * 8
        elif next_header == IPPROTO_AH:
            # Length in 4-octet units, minus 2.
            length = (buf[1] + 2) * 4
        else:
            return None
        if len(buf) < length:
            return None
        next_header = buf[0]
        buf = buf[length:]
