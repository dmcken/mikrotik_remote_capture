#!/usr/bin/env python3
'''Generate the shared test cases for the TZSP parsers.

- tzsp_vectors.tsv: single packets through strip() / strip_frame().
- reassembly_vectors.tsv: packet sequences through the fragment Reassembler.

The Rust `tzsp` crate and the Python stripper (clean/tzsp_strip_py) both run
every case in the generated files, so a parser change made in one language and
not the other fails the tests.

Edit the cases below, then re-run from anywhere (standard library only):

    python3 testdata/generate_vectors.py
'''

from pathlib import Path

OUT = Path(__file__).with_name('tzsp_vectors.tsv')
REASSEMBLY_OUT = Path(__file__).with_name('reassembly_vectors.tsv')

PORT = 37008
INNER = bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + b'inner ethernet frame'


def tzsp(encap: int = 1, inner: bytes = INNER, tags: bytes = b'\x00\x01') -> bytes:
    '''TZSP v1, type 0 (received), given encapsulation and tag list.'''
    return b'\x01\x00' + encap.to_bytes(2, 'big') + tags + inner


def udp(payload: bytes, dport: int = PORT) -> bytes:
    return (b'\xc0\x00' + dport.to_bytes(2, 'big')
            + (8 + len(payload)).to_bytes(2, 'big') + b'\x00\x00' + payload)


def ipv4(payload: bytes, proto: int = 17, ihl: int = 5, ident: int = 0,
         frag_offset: int = 0, more: bool = False, total_len: int | None = None) -> bytes:
    '''IPv4 header + payload. frag_offset is in bytes (a multiple of 8).'''
    hdr = bytearray(ihl * 4)
    hdr[0] = 0x40 | ihl
    hdr[2:4] = (total_len if total_len is not None else len(hdr) + len(payload)).to_bytes(2, 'big')
    hdr[4:6] = ident.to_bytes(2, 'big')
    hdr[6:8] = ((0x2000 if more else 0) | (frag_offset // 8)).to_bytes(2, 'big')
    hdr[8] = 64
    hdr[9] = proto
    hdr[12:16] = bytes([192, 0, 2, 2])
    hdr[16:20] = bytes([192, 0, 2, 1])
    return bytes(hdr) + payload


def ipv6(payload: bytes, next_header: int = 17, src: str = '20010db8000000000000000000000002') -> bytes:
    '''IPv6 header + payload (which includes any extension headers).'''
    hdr = bytearray(40)
    hdr[0] = 0x60
    hdr[4:6] = len(payload).to_bytes(2, 'big')
    hdr[6] = next_header
    hdr[7] = 64
    hdr[8:24] = bytes.fromhex(src)
    hdr[24:40] = bytes.fromhex('20010db8000000000000000000000001')
    return bytes(hdr) + payload


# IPv6 extension headers. Each takes the Next Header that follows it.
HOP_BY_HOP, ROUTING, FRAGMENT, ESP, AH, DEST_OPTS = 0, 43, 44, 50, 51, 60


def ext_options(next_header: int) -> bytes:
    '''Hop-by-Hop or Destination Options: 8 bytes, PadN filling.'''
    return bytes([next_header, 0, 1, 4, 0, 0, 0, 0])


def ext_routing(next_header: int) -> bytes:
    '''Segment Routing Header (type 4) with one segment: 24 bytes.'''
    return bytes([next_header, 2, 4, 0, 0, 0, 0, 0]) + bytes.fromhex('20010db8000000000000000000000001')


def ext_ah(next_header: int) -> bytes:
    '''AH with a 96-bit ICV: 24 bytes, length field 24/4 - 2 = 4.'''
    return bytes([next_header, 4, 0, 0]) + (0x1000).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + bytes(12)


def ext_fragment(next_header: int, offset: int = 0, more: bool = False, ident: int = 0x01020304) -> bytes:
    '''Fragment header. offset is in bytes (a multiple of 8).'''
    return bytes([next_header, 0]) + (offset | (1 if more else 0)).to_bytes(2, 'big') + ident.to_bytes(4, 'big')


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
    ('ipv4_total_length_below_header', 'strip_frame', PORT,
     ether(ipv4(udp(tzsp()), total_len=19), 0x0800), REJECT),
    # Ethernet padding/trailers (e.g. an FCS) after the IP packet are dropped
    # using the IP length fields.
    ('ipv4_ethernet_trailer_dropped', 'strip_frame', PORT,
     ether(ipv4(udp(tzsp())), 0x0800) + b'\xde\xad\xbe\xef', ok()),
    ('ipv6_ethernet_trailer_dropped', 'strip_frame', PORT,
     ether(ipv6(udp(tzsp())), 0x86DD) + b'\xde\xad\xbe\xef', ok()),
    # Cut short by the capture's snap length: written as far as it goes.
    ('ipv4_truncated_by_snaplen', 'strip_frame', PORT,
     ether(ipv4(udp(tzsp())), 0x0800)[:-5], ok(INNER[:-5])),
    # IPv6 extension headers before UDP.
    ('ipv6_hop_by_hop', 'strip_frame', PORT,
     ether(ipv6(ext_options(17) + udp(tzsp()), HOP_BY_HOP), 0x86DD), ok()),
    ('ipv6_destination_options', 'strip_frame', PORT,
     ether(ipv6(ext_options(17) + udp(tzsp()), DEST_OPTS), 0x86DD), ok()),
    ('ipv6_routing_srh', 'strip_frame', PORT,
     ether(ipv6(ext_routing(17) + udp(tzsp()), ROUTING), 0x86DD), ok()),
    ('ipv6_ah', 'strip_frame', PORT,
     ether(ipv6(ext_ah(17) + udp(tzsp()), AH), 0x86DD), ok()),
    ('ipv6_header_chain', 'strip_frame', PORT,
     ether(ipv6(ext_options(ROUTING) + ext_routing(AH) + ext_ah(DEST_OPTS) + ext_options(17) + udp(tzsp()),
                HOP_BY_HOP), 0x86DD), ok()),
    ('ipv6_atomic_fragment', 'strip_frame', PORT,
     ether(ipv6(ext_fragment(17) + udp(tzsp()), FRAGMENT), 0x86DD), ok()),
    ('ipv6_esp', 'strip_frame', PORT,
     ether(ipv6(bytes(8) + udp(tzsp()), ESP), 0x86DD), REJECT),
    ('ipv6_not_udp', 'strip_frame', PORT, ether(ipv6(udp(tzsp()), 6), 0x86DD), REJECT),
    ('ipv6_extension_header_truncated', 'strip_frame', PORT,
     ether(ipv6(ext_routing(17)[:20], ROUTING), 0x86DD), REJECT),
    ('ipv6_extension_header_length_missing', 'strip_frame', PORT,
     ether(ipv6(b'\x11', HOP_BY_HOP), 0x86DD), REJECT),
    # Fragments need reassembling first, so strip_frame() rejects them rather
    # than writing a truncated frame.
    ('ipv4_first_fragment', 'strip_frame', PORT,
     ether(ipv4(udp(tzsp())[:32], ident=7, more=True), 0x0800), REJECT),
    ('ipv4_last_fragment', 'strip_frame', PORT,
     ether(ipv4(udp(tzsp())[32:], ident=7, frag_offset=32), 0x0800), REJECT),
    ('ipv6_first_fragment', 'strip_frame', PORT,
     ether(ipv6(ext_fragment(17, more=True) + udp(tzsp())[:32], FRAGMENT), 0x86DD), REJECT),
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


# --- Reassembly cases ---------------------------------------------------

# A TZSP datagram big enough to split: UDP header (8) + TZSP (5) + 200-byte
# inner frame = 213 bytes, fragmented at multiples of 8.
BIG_A = bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + bytes(range(186))
BIG_B = bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00' + bytes(range(186))[::-1]
assert len(BIG_A) == 200


def udp_a(dport: int = PORT, encap: int = 1, inner: bytes = BIG_A) -> bytes:
    return udp(tzsp(encap=encap, inner=inner), dport=dport)


def chunks(data: bytes, cuts: list[int]) -> list[tuple[int, bytes, bool]]:
    '''Split data at the given offsets: [(offset, chunk, more), ...].'''
    bounds = [0] + cuts + [len(data)]
    return [(bounds[i], data[bounds[i]:bounds[i + 1]], i + 2 < len(bounds)) for i in range(len(bounds) - 1)]


def frag4(data: bytes, cuts: list[int], ident: int = 0x1234, proto: int = 17) -> list[bytes]:
    return [ether(ipv4(c, proto=proto, ident=ident, frag_offset=o, more=m), 0x0800) for o, c, m in chunks(data, cuts)]


def frag6(data: bytes, cuts: list[int], ident: int = 0x01020304, next_header: int = 17,
          before: bytes = b'', first: int = FRAGMENT) -> list[bytes]:
    '''IPv6 fragments; `before` = unfragmentable extension headers ahead of
    the Fragment header (starting with protocol `first`).'''
    return [ether(ipv6(before + ext_fragment(next_header, o, m, ident) + c, first), 0x86DD)
            for o, c, m in chunks(data, cuts)]


def with_src4(frame: bytes, last_octet: int) -> bytes:
    '''Change an IPv4 frame's source address (no checksums are checked).'''
    return frame[:14 + 15] + bytes([last_octet]) + frame[14 + 16:]


def frame(inner: bytes = BIG_A, encap: int = 1) -> str:
    return f'frame:{encap}:{inner.hex()}'


FRAG = 'fragment'

A4 = frag4(udp_a(), [64, 128])            # 3 fragments: 0-64, 64-128, 128-213
B4 = frag4(udp_a(inner=BIG_B), [128], ident=0x9999)
A6 = frag6(udp_a(), [64, 128])

# (name, port, max_buffered or None, [(ms, frame, expected)], (reassembled, incomplete))
REASSEMBLY_CASES = [
    ('v4_in_order', PORT, None,
     [(0, A4[0], FRAG), (1, A4[1], FRAG), (2, A4[2], frame())], (1, 0)),
    ('v4_reverse_order', PORT, None,
     [(0, A4[2], FRAG), (1, A4[1], FRAG), (2, A4[0], frame())], (1, 0)),
    ('v4_unfragmented_passes_through', PORT, None,
     [(0, ether(ipv4(udp_a()), 0x0800), frame())], (0, 0)),
    ('v4_interleaved_datagrams', PORT, None,
     [(0, A4[0], FRAG), (1, B4[0], FRAG), (2, A4[1], FRAG), (3, B4[1], frame(BIG_B)),
      (4, A4[2], frame())], (2, 0)),
    ('v4_same_id_different_source', PORT, None,
     [(0, A4[0], FRAG), (1, with_src4(frag4(udp_a(inner=BIG_B), [64, 128])[0], 9), FRAG),
      (2, A4[1], FRAG), (3, A4[2], frame()),
      (4, with_src4(frag4(udp_a(inner=BIG_B), [64, 128])[1], 9), FRAG),
      (5, with_src4(frag4(udp_a(inner=BIG_B), [64, 128])[2], 9), frame(BIG_B))], (2, 0)),
    ('v4_duplicate_fragment_ignored', PORT, None,
     [(0, A4[0], FRAG), (1, A4[0], FRAG), (2, A4[1], FRAG), (3, A4[2], frame())], (1, 0)),
    ('v4_overlap_discards_datagram', PORT, None,
     [(0, A4[0], FRAG), (1, frag4(udp_a(inner=BIG_B), [32, 96])[1], 'reject'),
      (2, A4[1], 'reject'), (3, A4[2], 'reject')], (0, 1)),
    ('v4_missing_fragment', PORT, None,
     [(0, A4[0], FRAG), (1, A4[2], FRAG)], (0, 1)),
    ('v4_completes_within_timeout', PORT, None,
     [(0, A4[0], FRAG), (1, A4[1], FRAG), (29_000, A4[2], frame())], (1, 0)),
    ('v4_timeout_drops_datagram', PORT, None,
     [(0, A4[0], FRAG), (1, A4[1], FRAG), (31_000, A4[2], FRAG)], (0, 2)),
    # The periodic sweep last ran at 29.5 s, so it's this datagram's own age
    # check that drops it at 30.2 s.
    ('v4_timeout_checked_between_sweeps', PORT, None,
     [(0, frag4(udp_a(), [128])[0], FRAG), (29_500, B4[0], FRAG), (30_200, frag4(udp_a(), [128])[1], FRAG)],
     (0, 3)),
    ('v4_sweep_drops_stale_datagram', PORT, None,
     [(0, A4[0], FRAG), (40_000, B4[0], FRAG), (40_001, B4[1], frame(BIG_B))], (1, 1)),
    ('v4_reassembled_wrong_port', PORT, None,
     [(0, frag4(udp_a(dport=5000), [128])[0], FRAG), (1, frag4(udp_a(dport=5000), [128])[1], 'reject')], (1, 0)),
    ('v4_reassembled_custom_port', 5000, None,
     [(0, frag4(udp_a(dport=5000), [128])[0], FRAG), (1, frag4(udp_a(dport=5000), [128])[1], frame())], (1, 0)),
    ('v4_reassembled_80211', PORT, None,
     [(0, frag4(udp_a(encap=18), [128])[0], FRAG), (1, frag4(udp_a(encap=18), [128])[1], frame(encap=18))],
     (1, 0)),
    # TZSP header of nothing but PADDING tags: no END tag.
    ('v4_reassembled_not_tzsp', PORT, None,
     [(0, frag4(udp(b'\x01\x00\x00\x01' + bytes(196)), [128])[0], FRAG),
      (1, frag4(udp(b'\x01\x00\x00\x01' + bytes(196)), [128])[1], 'reject')], (1, 0)),
    ('v4_non_udp_fragment_rejected', PORT, None,
     [(0, frag4(udp_a(), [128], proto=6)[0], 'reject')], (0, 0)),
    ('v4_padded_last_fragment', PORT, None,
     [(0, frag4(udp_a(), [208])[0], FRAG),
      (1, frag4(udp_a(), [208])[1] + bytes(60 - len(frag4(udp_a(), [208])[1])), frame())], (1, 0)),
    ('v4_truncated_fragment_rejected', PORT, None,
     [(0, A4[0][:-10], 'reject'), (1, A4[1], FRAG), (2, A4[2], FRAG)], (0, 1)),
    ('v4_non_final_length_not_multiple_of_8', PORT, None,
     [(0, frag4(udp_a(), [60])[0], 'reject'), (1, frag4(udp_a(), [60])[1], 'reject')], (0, 1)),
    # Two "last" fragments that don't overlap but disagree on the end.
    ('v4_conflicting_total_length', PORT, None,
     [(0, ether(ipv4(bytes(16), ident=0x1234, frag_offset=136), 0x0800), FRAG),
      (1, ether(ipv4(bytes(8), ident=0x1234, frag_offset=160), 0x0800), 'reject')], (0, 1)),
    ('v4_fragment_past_end', PORT, None,
     [(0, A4[2], FRAG), (1, ether(ipv4(bytes(8), ident=0x1234, frag_offset=216, more=True), 0x0800), 'reject')],
     (0, 1)),
    ('v4_datagram_too_large', PORT, None,
     [(0, ether(ipv4(bytes(16), ident=1, frag_offset=65528, more=True), 0x0800), 'reject')], (0, 1)),
    ('v4_buffer_full_drops_oldest', PORT, 250,
     [(0, frag4(udp_a(), [128])[0], FRAG), (1, B4[0], FRAG), (2, B4[1], frame(BIG_B)),
      (3, frag4(udp_a(), [128])[1], FRAG)], (1, 2)),
    # A fragment too big for the buffer on its own is rejected without
    # evicting other datagrams.
    ('v4_oversized_fragment_keeps_others', PORT, 220,
     [(0, B4[0], FRAG), (1, frag4(udp(bytes(300)), [232], ident=3)[0], 'reject'), (2, B4[1], frame(BIG_B))],
     (1, 1)),
    ('v4_fragment_larger_than_buffer', PORT, 100,
     [(0, frag4(udp_a(), [128])[0], 'reject'), (1, frag4(udp_a(), [128])[1], 'reject')], (0, 1)),
    ('v6_in_order', PORT, None,
     [(0, A6[0], FRAG), (1, A6[1], FRAG), (2, A6[2], frame())], (1, 0)),
    ('v6_reverse_order', PORT, None,
     [(0, A6[2], FRAG), (1, A6[1], FRAG), (2, A6[0], frame())], (1, 0)),
    ('v6_hop_by_hop_before_fragment', PORT, None,
     [(0, f, FRAG if i < 1 else frame())
      for i, f in enumerate(frag6(udp_a(), [128], before=ext_options(FRAGMENT), first=HOP_BY_HOP))], (1, 0)),
    ('v6_destination_options_after_fragment', PORT, None,
     [(0, f, FRAG if i < 1 else frame())
      for i, f in enumerate(frag6(ext_options(17) + udp_a(), [128], next_header=DEST_OPTS))], (1, 0)),
    ('v6_overlap_discards_datagram', PORT, None,
     [(0, A6[0], FRAG), (1, frag6(udp_a(inner=BIG_B), [32, 96])[1], 'reject'), (2, A6[1], 'reject')], (0, 1)),
    ('v6_reassembled_esp', PORT, None,
     [(0, f, FRAG if i < 1 else 'reject')
      for i, f in enumerate(frag6(bytes(8) + udp_a(), [128], next_header=ESP))], (1, 0)),
    ('v6_different_ids', PORT, None,
     [(0, A6[0], FRAG), (1, frag6(udp_a(inner=BIG_B), [128], ident=7)[0], FRAG),
      (2, frag6(udp_a(inner=BIG_B), [128], ident=7)[1], frame(BIG_B)),
      (3, A6[1], FRAG), (4, A6[2], frame())], (2, 0)),
    ('v4_and_v6_same_id', PORT, None,
     [(0, frag4(udp_a(), [128], ident=5)[0], FRAG), (1, frag6(udp_a(inner=BIG_B), [128], ident=5)[0], FRAG),
      (2, frag4(udp_a(), [128], ident=5)[1], frame()),
      (3, frag6(udp_a(inner=BIG_B), [128], ident=5)[1], frame(BIG_B))], (2, 0)),
]

REASSEMBLY_HEADER = '''\
# Shared fragment reassembly test cases. GENERATED by generate_vectors.py;
# edit that script and re-run it rather than editing this file by hand.
#
# Each case is a "case" line, then one "packet" line per captured frame fed
# to a new Reassembler, then a "finish" line. Tab-separated:
#   case    <name> <port> <max buffered bytes, or "-" for the default>
#   packet  <capture time in ms> <hex frame> <expected>
#           expected: "fragment" (held), "reject", or
#                     "frame:<encapsulation>:<hex of inner frame>"
#   finish  <reassembled> <incomplete>   (stats after finish())
'''


def main() -> None:
    names = [c[0] for c in CASES]
    assert len(names) == len(set(names)), 'duplicate case names'
    lines = [HEADER]
    for name, function, port, data, expected in CASES:
        lines.append('\t'.join([name, function, str(port), data.hex() or '-', expected]) + '\n')
    OUT.write_text(''.join(lines))
    print(f'wrote {len(CASES)} cases to {OUT}')

    names = [c[0] for c in REASSEMBLY_CASES]
    assert len(names) == len(set(names)), 'duplicate reassembly case names'
    lines = [REASSEMBLY_HEADER]
    for name, port, max_buffered, packets, (reassembled, incomplete) in REASSEMBLY_CASES:
        lines.append(f'case\t{name}\t{port}\t{"-" if max_buffered is None else max_buffered}\n')
        for ms, data, expected in packets:
            lines.append(f'packet\t{ms}\t{data.hex()}\t{expected}\n')
        lines.append(f'finish\t{reassembled}\t{incomplete}\n')
    REASSEMBLY_OUT.write_text(''.join(lines))
    print(f'wrote {len(REASSEMBLY_CASES)} cases to {REASSEMBLY_OUT}')


if __name__ == '__main__':
    main()
