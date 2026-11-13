'''IP fragment reassembly for TZSP streams read from capture files.

Python port of tzsp/src/reassembly.rs in the Rust tzsp crate; both run the
shared cases in testdata/reassembly_vectors.tsv. See that file for the
rules, which follow the Linux kernel:

- Fragments are matched by source, destination and IP ID (IPv4, UDP only)
  or Fragment header ID (IPv6).
- A datagram whose fragments haven't all arrived within the timeout (30 s
  by default, in capture time from its first fragment) is dropped and
  counted as incomplete.
- Exact duplicates are ignored. Any other overlap, a conflicting or exceeded
  total length, a non-final fragment whose length isn't a multiple of 8, or
  a datagram over 65,535 bytes discards the whole datagram (RFC 5722), and
  its remaining fragments are rejected.
- Buffered fragment data is capped (64 MiB by default); when full, the
  oldest incomplete datagrams are dropped to make room.
- The stripped frame is returned with the fragment that completes it.
'''

from dataclasses import dataclass, field
from typing import Callable

from tzsp_strip import ip

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_BUFFERED = 64 * 1024 * 1024
MAX_DATAGRAM = 65_535
SWEEP_INTERVAL = 1.0

# Returned by push() for a fragment held until its datagram is complete.
FRAGMENT = 'fragment'


@dataclass
class _Pending:
    first_seen: float
    # [(offset, data)], in arrival order. Never overlapping.
    fragments: list = field(default_factory=list)
    nbytes: int = 0
    # Known once the last fragment has arrived.
    total_len: int | None = None
    # From the fragment at offset 0.
    next_header: int | None = None
    # The datagram was discarded; reject its fragments until it times out.
    discarded: bool = False


_NEW, _DUPLICATE, _CONFLICT = range(3)


class Reassembler:
    '''Strips TZSP frames from a capture, reassembling fragmented datagrams.

    Feed it every frame from the capture, in order, with push(), then call
    finish().
    '''

    def __init__(self, strip_udp: Callable[[bytes], tuple[int, bytes] | None],
                 timeout: float = DEFAULT_TIMEOUT, max_buffered: int = DEFAULT_MAX_BUFFERED):
        '''strip_udp: strips the UDP + TZSP headers from a UDP datagram,
        checking the port, as cli.strip_udp() does.'''
        self._strip_udp = strip_udp
        self._timeout = timeout
        self._max_buffered = max_buffered
        self._pending: dict[tuple, _Pending] = {}
        self.buffered = 0
        self._last_sweep = 0.0
        # Datagrams reassembled from fragments (whether or not they then
        # turned out to be valid TZSP).
        self.reassembled = 0
        # Datagrams dropped before completing: timed out, evicted to make
        # room, discarded as invalid, or still incomplete at finish().
        self.incomplete = 0

    def push(self, timestamp: float, frame: bytes) -> tuple[int, bytes] | str | None:
        '''Process one captured Ethernet frame with its capture timestamp.

        Returns (encapsulation, inner_frame) for a stripped frame ready to
        write, FRAGMENT for a fragment held until its datagram is complete,
        or None if it isn't a strippable TZSP frame (or is a fragment of a
        discarded datagram).
        '''
        parsed = ip.parse(frame)
        if parsed is None:
            return None
        if isinstance(parsed, bytes):
            return self._strip_udp(parsed)
        return self._push_fragment(timestamp, parsed)

    def finish(self) -> tuple[int, int]:
        '''End of input: count datagrams still waiting for fragments as
        incomplete. Returns (reassembled, incomplete).'''
        for p in self._pending.values():
            if not p.discarded:
                self.incomplete += 1
        self._pending.clear()
        self.buffered = 0
        return self.reassembled, self.incomplete

    def _push_fragment(self, now: float, f: ip.Fragment) -> tuple[int, bytes] | str | None:
        self._sweep(now)

        # This datagram's earlier fragments may have timed out without a
        # sweep noticing yet.
        p = self._pending.get(f.key)
        if p is not None and now - p.first_seen > self._timeout:
            self._drop(self._pending.pop(f.key))

        end = f.offset + len(f.data)
        invalid = end > MAX_DATAGRAM or (f.more and len(f.data) % 8 != 0)
        p = self._pending.get(f.key)
        if not invalid and not (p is not None and p.discarded) and not self._make_room(len(f.data), f.key):
            invalid = True

        p = self._pending.get(f.key)
        if p is None:
            p = self._pending[f.key] = _Pending(now)
        if p.discarded:
            return None
        added = _CONFLICT if invalid else _add(p, f, end)
        if added == _DUPLICATE:
            return FRAGMENT
        if added == _CONFLICT:
            self.buffered -= p.nbytes
            self._pending[f.key] = _Pending(p.first_seen, discarded=True)
            self.incomplete += 1
            return None
        self.buffered += len(f.data)

        if p.total_len != p.nbytes:
            return FRAGMENT

        # Complete: no overlaps and every fragment inside total_len, so the
        # fragments cover it exactly.
        del self._pending[f.key]
        self.buffered -= p.nbytes
        self.reassembled += 1
        payload = bytearray(p.nbytes)
        for offset, data in p.fragments:
            payload[offset:offset + len(data)] = data
        payload = bytes(payload)

        if f.key[0] == 6:
            upper = None
            if p.next_header is not None:
                upper = ip.walk_ipv6_extension_headers(p.next_header, payload)
            if not isinstance(upper, bytes):
                return None
            payload = upper
        return self._strip_udp(payload)

    def _sweep(self, now: float) -> None:
        '''Drop datagrams that have waited longer than the timeout. Runs at
        most once per second of capture time.'''
        if now - self._last_sweep < SWEEP_INTERVAL:
            return
        self._last_sweep = now
        expired = [k for k, p in self._pending.items() if now - p.first_seen > self._timeout]
        for key in expired:
            self._drop(self._pending.pop(key))

    def _make_room(self, length: int, key: tuple) -> bool:
        '''Make room for length more bytes by dropping the oldest other
        incomplete datagrams. False if it can't fit even then.'''
        if length > self._max_buffered:
            return False
        while self.buffered + length > self._max_buffered:
            candidates = [(p.first_seen, k) for k, p in self._pending.items() if k != key and p.nbytes > 0]
            if not candidates:
                return False
            oldest = min(candidates, key=lambda c: c[0])[1]
            self._drop(self._pending.pop(oldest))
        return True

    def _drop(self, p: _Pending) -> None:
        self.buffered -= p.nbytes
        if not p.discarded:
            self.incomplete += 1


def _add(p: _Pending, f: ip.Fragment, end: int) -> int:
    '''Add a fragment to a pending datagram.'''
    for offset, data in p.fragments:
        if f.offset < offset + len(data) and offset < end:
            if offset == f.offset and data == f.data:
                return _DUPLICATE
            return _CONFLICT
    if not f.more:
        if p.total_len is not None and p.total_len != end:
            return _CONFLICT
        p.total_len = end
    if p.total_len is not None:
        if end > p.total_len or any(o + len(d) > p.total_len for o, d in p.fragments):
            return _CONFLICT
    if f.offset == 0:
        p.next_header = f.next_header
    p.fragments.append((f.offset, f.data))
    p.nbytes += len(f.data)
    return _NEW
