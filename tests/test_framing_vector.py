"""Draft encoding example; not a protocol or security test."""

import hashlib
import struct
import unittest


class FramingVectorTest(unittest.TestCase):
    def test_draft_authorization_challenge_transcripts(self):
        frame = lambda tag, payload: bytes([tag]) + struct.pack(">I", len(payload)) + payload
        blob = lambda value: frame(2, value)
        uint = lambda value: frame(3, value.to_bytes(8, "big"))
        point = lambda value: frame(4, value)
        scalar = lambda value: frame(5, value)
        transcript = lambda label, *values: frame(
            1, blob(b"HTA-secp256k1-v1") + blob(label) + b"".join(values)
        )
        G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        cpk = bytes.fromhex("5e2d5167321e94eac08ec2e24b981f2e45d741b7a8cf35df029b06ed6a9a7fe8")
        statement = transcript(b"ST", blob(cpk), uint(1), uint(1), blob(b"abc"), point(G))
        identity = point(b"\x00")
        prefix = transcript(b"T0", blob(statement), identity, identity, identity)
        challenge = lambda value: hashlib.sha256(transcript(b"SCALAR", blob(value), uint(0))).digest()
        y = challenge(transcript(b"Y", blob(prefix)))
        z = challenge(transcript(b"Z", blob(prefix), scalar(y)))
        x = challenge(transcript(b"X", blob(prefix), scalar(y), scalar(z), identity, identity))
        self.assertEqual(y.hex(), "043299348632429ab1a0dac675ef261d1f13b0b22a1bc769d5f748126894b0be")
        self.assertEqual(z.hex(), "9f46de52da1bfbea5d265a042ea111add7452c96179171a71d1b6efdf79c1b5f")
        self.assertEqual(x.hex(), "7daead5cad16a3c94933c79d2e1c2b40557989cdd256cce065ffe026871d075d")

    def test_draft_roster_and_signing_transcripts(self):
        frame = lambda tag, payload: bytes([tag]) + struct.pack(">I", len(payload)) + payload
        blob = lambda value: frame(2, value)
        uint = lambda value: frame(3, value.to_bytes(8, "big"))
        point = lambda value: frame(4, value)
        vector = lambda *values: frame(6, b"".join(values))
        transcript = lambda label, *values: frame(
            1, blob(b"HTA-secp256k1-v1") + blob(label) + b"".join(values)
        )
        G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        roster = transcript(b"ROSTER", uint(1), vector(point(G)))
        cpk = hashlib.sha256(roster).digest()
        self.assertEqual(cpk.hex(), "5e2d5167321e94eac08ec2e24b981f2e45d741b7a8cf35df029b06ed6a9a7fe8")
        subset = transcript(b"SUBSET", vector(uint(1)))
        ctx = transcript(b"CTX", blob(b"session-1"), blob(cpk), uint(1), blob(b"abc"), point(G), blob(subset))
        self.assertEqual(hashlib.sha256(ctx).hexdigest(), "59a8aa1e1601843b088e82447496e92729f03a8806cb29574d691b2c70255146")
        non = transcript(b"NON", blob(ctx), point(G), point(G))
        sig = transcript(b"SIG", blob(cpk), point(G), uint(1), point(G), blob(b"abc"))
        st = transcript(b"ST", blob(cpk), uint(1), uint(1), blob(b"abc"), point(G))
        challenge = lambda value: hashlib.sha256(transcript(b"SCALAR", blob(value), uint(0))).hexdigest()
        self.assertEqual(challenge(non), "544a18eddb7876dc63accdd0ce9b1400c01170201fdb08270a931246ee3b5240")
        self.assertEqual(challenge(sig), "57aba68fb85a43b2dbbf1723ab35d3bd63e0ee855075c0bcef09b65dac321593")
        self.assertEqual(hashlib.sha256(st).hexdigest(), "22021ddd7e72493c0f53bc0bc4aad37a0d3d76b5eb6943eb3b9fa004d0e4495b")

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
