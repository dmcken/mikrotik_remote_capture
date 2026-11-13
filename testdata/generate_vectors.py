#!/usr/bin/env python3
'''Generate tzsp_vectors.tsv: shared test cases for the TZSP parsers.

The Rust `tzsp` crate and the Python stripper (clean/tzsp_strip_py) both run
every case in the generated file, so a parser change made in one language and
not the other fails the tests.

Edit the cases below, then re-run from anywhere (standard library only):

    python3 testdata/generate_vectors.py
'''

from pathlib import Path

OUT = Path(__file__).with_name('tzsp_vectors.tsv')

PORT = 37008
INNER = bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + b'inner ethernet frame'


def tzsp(encap: int = 1, inner: bytes = INNER, tags: bytes = b'\x00\x01') -> bytes:
    '''TZSP v1, type 0 (received), given encapsulation and tag list.'''
    return b'\x01\x00' + encap.to_bytes(2, 'big') + tags + inner


def udp(payload: bytes, dport: int = PORT) -> bytes:
    return (b'\xc0\x00' + dport.to_bytes(2, 'big')
            + (8 + len(payload)).to_bytes(2, 'big') + b'\x00\x00' + payload)


def ipv4(payload: bytes, proto: int = 17, ihl: int = 5) -> bytes:
    hdr = bytearray(ihl * 4)
    hdr[0] = 0x40 | ihl
    hdr[2:4] = (len(hdr) + len(payload)).to_bytes(2, 'big')
    hdr[8] = 64
    hdr[9] = proto
    hdr[12:16] = bytes([192, 0, 2, 2])
    hdr[16:20] = bytes([192, 0, 2, 1])
    return bytes(hdr) + payload


def ipv6(payload: bytes, next_header: int = 17) -> bytes:
    hdr = bytearray(40)
    hdr[0] = 0x60
    hdr[4:6] = len(payload).to_bytes(2, 'big')
    hdr[6] = next_header
    hdr[7] = 64
    hdr[8:24] = bytes.fromhex('20010db8000000000000000000000002')
    hdr[24:40] = bytes.fromhex('20010db8000000000000000000000001')
    return bytes(hdr) + payload


def ether(payload: bytes, ethertype: int) -> bytes:
    return (bytes.fromhex('020000000002') + bytes.fromhex('020000000001')
            + ethertype.to_bytes(2, 'big') + payload)


def vlan(vid: int, inner_ethertype: int) -> bytes:
    '''A VLAN tag's TCI (priority 0) followed by the next ethertype.'''
    return vid.to_bytes(2, 'big') + inner_ethertype.to_bytes(2, 'big')


def ok(frame: bytes = INNER, encap: int = 1) -> str:
    return f'{encap}:{frame.hex()}'


REJECT = 'reject'

# (name, function, port, input, expected)
CASES = [
    # --- strip(): TZSP header on a UDP payload ---------------------------
    ('padding_then_end', 'strip', PORT, tzsp(), ok()),
    ('end_only', 'strip', PORT, tzsp(tags=b'\x01'), ok()),
    ('several_padding_tags', 'strip', PORT, tzsp(tags=b'\x00\x00\x00\x01'), ok()),
    ('tagged_field_then_end', 'strip', PORT, tzsp(tags=b'\x0a\x03\xaa\xbb\xcc\x01'), ok()),
    ('tagged_field_zero_length', 'strip', PORT, tzsp(tags=b'\x0a\x00\x01'), ok()),
    ('encap_80211_returned', 'strip', PORT, tzsp(encap=18), ok(encap=18)),
    ('empty_input', 'strip', PORT, b'', REJECT),
    ('short_fixed_header', 'strip', PORT, b'\x01\x00\x00', REJECT),
    ('no_end_tag', 'strip', PORT, b'\x01\x00\x00\x01\x00\x00', REJECT),
    ('tag_missing_length_byte', 'strip', PORT, b'\x01\x00\x00\x01\x0a', REJECT),
    ('tag_longer_than_data', 'strip', PORT, b'\x01\x00\x00\x01\x0a\x09\xaa', REJECT),
    ('keepalive_no_frame', 'strip', PORT, tzsp(inner=b''), REJECT),

    # --- strip_frame(): Ethernet/IP/UDP/TZSP in a capture file -----------
    ('ipv4', 'strip_frame', PORT, ether(ipv4(udp(tzsp())), 0x0800), ok()),
    ('ipv4_with_options', 'strip_frame', PORT, ether(ipv4(udp(tzsp()), ihl=6), 0x0800), ok()),
    ('ipv6', 'strip_frame', PORT, ether(ipv6(udp(tzsp())), 0x86DD), ok()),
    ('ipv4_encap_80211', 'strip_frame', PORT, ether(ipv4(udp(tzsp(encap=18))), 0x0800), ok(encap=18)),
    ('custom_port_matches', 'strip_frame', 5000, ether(ipv6(udp(tzsp(), dport=5000)), 0x86DD), ok()),
    ('wrong_port', 'strip_frame', PORT, ether(ipv4(udp(tzsp(), dport=5000)), 0x0800), REJECT),
    ('ipv4_not_udp', 'strip_frame', PORT, ether(ipv4(udp(tzsp()), proto=6), 0x0800), REJECT),
    ('ipv4_ihl_below_minimum', 'strip_frame', PORT,
     ether(b'\x44' + ipv4(udp(tzsp()))[1:], 0x0800), REJECT),
    ('ipv6_extension_header', 'strip_frame', PORT, ether(ipv6(udp(tzsp()), next_header=0), 0x86DD), REJECT),
    ('ipv6_truncated', 'strip_frame', PORT, ether(b'\x60' * 39, 0x86DD), REJECT),
    ('ethernet_truncated', 'strip_frame', PORT, bytes(13), REJECT),
    ('arp_ethertype', 'strip_frame', PORT, ether(bytes(28), 0x0806), REJECT),
    ('vlan_8021q_ipv4', 'strip_frame', PORT,
     ether(vlan(10, 0x0800) + ipv4(udp(tzsp())), 0x8100), ok()),
    ('vlan_8021q_ipv6', 'strip_frame', PORT,
     ether(vlan(4094, 0x86DD) + ipv6(udp(tzsp())), 0x8100), ok()),
    ('vlan_qinq_8021ad', 'strip_frame', PORT,
     ether(vlan(100, 0x8100) + vlan(10, 0x0800) + ipv4(udp(tzsp())), 0x88A8), ok()),
    ('vlan_qinq_9100', 'strip_frame', PORT,
     ether(vlan(100, 0x8100) + vlan(10, 0x86DD) + ipv6(udp(tzsp())), 0x9100), ok()),
    ('vlan_then_arp', 'strip_frame', PORT, ether(vlan(10, 0x0806) + bytes(28), 0x8100), REJECT),
    ('vlan_tag_truncated', 'strip_frame', PORT, ether(b'\x00\x0a\x08', 0x8100), REJECT),
    ('vlan_tag_without_ethertype', 'strip_frame', PORT, ether(b'\x00\x0a', 0x8100), REJECT),
    ('udp_header_truncated', 'strip_frame', PORT, ether(ipv4(b'\xc0\x00\x90'), 0x0800), REJECT),
    ('malformed_tzsp_in_valid_frame', 'strip_frame', PORT,
     ether(ipv4(udp(b'\x01\x00\x00\x01\x00\x00')), 0x0800), REJECT),
]

HEADER = '''\
# Shared TZSP parser test cases. GENERATED by generate_vectors.py; edit that
# script and re-run it rather than editing this file by hand.
#
# Tab-separated columns:
#   name      unique case name
#   function  strip        TZSP header on a UDP payload
#             strip_frame  Ethernet/IP/UDP/TZSP frame from a capture file
#   port      UDP destination port to accept (strip_frame only)
#   input     hex bytes, or "-" for empty
#   expected  "reject", or "<encapsulation>:<hex of inner frame>"
'''


def main() -> None:
    names = [c[0] for c in CASES]
    assert len(names) == len(set(names)), 'duplicate case names'
    lines = [HEADER]
    for name, function, port, data, expected in CASES:
        lines.append('\t'.join([name, function, str(port), data.hex() or '-', expected]) + '\n')
    OUT.write_text(''.join(lines))
    print(f'wrote {len(CASES)} cases to {OUT}')


if __name__ == '__main__':
    main()
