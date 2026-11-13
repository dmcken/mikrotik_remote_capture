'''Run the shared fragment reassembly cases (testdata/reassembly_vectors.tsv).

The Rust tzsp crate runs the same file. Run with:

    uv run python -m unittest discover -s tests
'''

import unittest
from pathlib import Path

from tzsp_strip import cli
from tzsp_strip.reassembly import DEFAULT_MAX_BUFFERED, FRAGMENT, Reassembler

VECTORS = Path(__file__).resolve().parents[3] / 'testdata' / 'reassembly_vectors.tsv'


def _new(port: int, max_buffered: int) -> Reassembler:
    return Reassembler(lambda udp: cli.strip_udp(udp, port), max_buffered=max_buffered)


class SharedReassemblyVectors(unittest.TestCase):
    def test_vectors(self) -> None:
        cases = 0
        name, r = None, None
        for line in VECTORS.read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            f = line.split('\t')
            if f[0] == 'case':
                name = f[1]
                r = _new(int(f[2]), DEFAULT_MAX_BUFFERED if f[3] == '-' else int(f[3]))
                cases += 1
            elif f[0] == 'packet':
                got = r.push(int(f[1]) / 1000, bytes.fromhex(f[2]))
                if got is None:
                    got = 'reject'
                elif got != FRAGMENT:
                    got = f'frame:{got[0]}:{got[1].hex()}'
                with self.subTest(name=name, ms=f[1]):
                    self.assertEqual(got, f[3])
            elif f[0] == 'finish':
                with self.subTest(name=name, stage='finish'):
                    self.assertEqual(r.finish(), (int(f[1]), int(f[2])))
                    self.assertEqual(r.buffered, 0)
            else:
                self.fail(f'unknown line type {f[0]}')
        self.assertGreaterEqual(cases, 20, 'too few cases loaded')

    def test_sweep_frees_timed_out_datagrams(self) -> None:
        first = bytes.fromhex('ffffffffffff02000000000108004500001c0001200000110000c0000202c0000201c000909000000000')
        other = bytes.fromhex('ffffffffffff02000000000108004500001c0002200000110000c0000202c0000201c000909000000000')
        r = _new(37008, DEFAULT_MAX_BUFFERED)
        self.assertEqual(r.push(0.0, first), FRAGMENT)
        self.assertEqual((len(r._pending), r.buffered), (1, 8))
        # A fragment of a different datagram 40 s later triggers a sweep,
        # which drops the first datagram and its buffered bytes.
        self.assertEqual(r.push(40.0, other), FRAGMENT)
        self.assertEqual((len(r._pending), r.buffered), (1, 8))
        self.assertEqual(r.incomplete, 1)


if __name__ == '__main__':
    unittest.main()
