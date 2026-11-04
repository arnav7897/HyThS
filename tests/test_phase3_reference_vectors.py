import unittest
from pathlib import Path

from phase3_reference_vectors import vectors


class Phase3ReferenceVectorsTest(unittest.TestCase):
    def test_frozen_vector_file_matches_python_reference(self):
        fixture = Path(__file__).parent / "vectors" / "phase3-wire-vectors.tsv"
        observed = {}
        for line in fixture.read_text().splitlines():
            name, encoded = line.split("\t")
            observed[name] = bytes.fromhex(encoded)
        self.assertEqual(observed, vectors())


if __name__ == "__main__":
    unittest.main()
