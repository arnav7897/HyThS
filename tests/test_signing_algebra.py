"""Audit v5 signing equations in an insecure toy group; not protocol code."""

import random
import unittest


class SigningAlgebraTest(unittest.TestCase):
    def test_two_nonce_masked_signature(self):
        rng = random.Random(20261104)
        q = 1019
        for count in range(1, 17):
            with self.subTest(signers=count):
                keys = rng.sample(range(1, q), count)
                nonces1 = [rng.randrange(1, q) for _ in keys]
                nonces2 = [rng.randrange(1, q) for _ in keys]
                R1, R2 = sum(nonces1) % q, sum(nonces2) % q
                self.assertNotEqual(R1, 0)
                self.assertNotEqual(R2, 0)
                beta, c, xi = 17, 23, 29
                R = (R1 + beta * R2) % q
                Qe = (sum(keys) + xi) % q
                self.assertNotEqual(R, 0)
                self.assertNotEqual(Qe, 0)
                shares = [(r1 + beta*r2 + c*key) % q
                          for r1, r2, key in zip(nonces1, nonces2, keys)]
                s = sum(shares) % q
                se = (s + c*xi) % q
                self.assertEqual(se, (R + c*Qe) % q)
                self.assertNotEqual(s, (R + c*Qe) % q)
                self.assertNotEqual((se + 1) % q, (R + c*Qe) % q)


if __name__ == "__main__":
    unittest.main()
