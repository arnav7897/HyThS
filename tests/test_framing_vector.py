"""Draft encoding example; not a protocol or security test."""

import hashlib
import struct
import unittest


class FramingVectorTest(unittest.TestCase):
    def test_subset_and_nested_scalar_framing(self):
        frame = lambda tag, payload: bytes([tag]) + struct.pack(">I", len(payload)) + payload
        blob = lambda value: frame(2, value)
        uint = lambda value: frame(3, value.to_bytes(8, "big"))
        transcript = lambda label, *items: frame(
            1, blob(b"HTA-secp256k1-v1") + blob(label) + b"".join(items)
        )
        subset = transcript(b"SUBSET", frame(6, uint(1) + uint(2)))
        self.assertEqual(
            subset.hex(),
            "010000003f02000000104854412d736563703235366b312d7631"
            "0200000006535542534554060000001a03000000080000000000000001"
            "03000000080000000000000002",
        )
        nested = transcript(b"SCALAR", blob(subset), uint(0))
        self.assertEqual(
            hashlib.sha256(nested).hexdigest(),
            "5080236740f6e6e3c1a21df66e2692563a091966343e86c8c09a2a23b42858dc",
        )
        self.assertNotEqual(subset, transcript(b"SUBSET", frame(6, uint(2) + uint(1))))
        self.assertNotEqual(transcript(b"X", blob(b"a"), blob(b"bc")),
                            transcript(b"X", blob(b"ab"), blob(b"c")))


if __name__ == "__main__":
    unittest.main()
