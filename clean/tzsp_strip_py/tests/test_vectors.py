'''Run the shared TZSP parser cases (testdata/tzsp_vectors.tsv).

The Rust tzsp crate runs the same file, so the two implementations can't
drift apart unnoticed. Run with:

    uv run python -m unittest discover -s tests
'''

import unittest
from pathlib import Path

from tzsp_strip import cli

VECTORS = Path(__file__).resolve().parents[3] / 'testdata' / 'tzsp_vectors.tsv'


def load_vectors() -> list[tuple[str, str, int, bytes, tuple[int, bytes] | None]]:
    cases = []
    for line in VECTORS.read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        name, function, port, data, expected = line.split('\t')
        if expected == 'reject':
            want = None
        else:
            encap, frame = expected.split(':')
            want = (int(encap), bytes.fromhex(frame))
        cases.append((name, function, int(port), b'' if data == '-' else bytes.fromhex(data), want))
    return cases


class SharedVectors(unittest.TestCase):
    def test_vectors(self) -> None:
        cases = load_vectors()
        self.assertGreaterEqual(len(cases), 20, 'too few vectors loaded')
        for name, function, port, data, want in cases:
            with self.subTest(name=name):
                if function == 'strip':
                    got = cli.strip_tzsp_payload(data)
                elif function == 'strip_frame':
                    got = cli.strip_tzsp(data, port)
                else:
                    self.fail(f'unknown function {function}')
                self.assertEqual(got, want)


if __name__ == '__main__':
    unittest.main()
