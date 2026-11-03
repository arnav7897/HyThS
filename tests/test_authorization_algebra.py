"""Audit v5 algebra sanity only: tiny group with known discrete logarithms.

This is not cryptography, an implementation, a test vector, or a security proof.
The oracle challenges are fixed rather than derived from a transcript.
"""

import random
import unittest


class AuthorizationAlgebraTest(unittest.TestCase):
    def test_audit_v5_authorization_equations(self):
        rng = random.Random(20261103)
        q = 1019
        dot = lambda a, b: sum(x * y for x, y in zip(a, b)) % q
        for n in range(1, 9):
            ell = n.bit_length()
            N = n + ell + 1
            for threshold in range(1, n + 1):
                for count in range(threshold, n + 1):
                    with self.subTest(n=n, threshold=threshold, count=count):
                        b = [1] * count + [0] * (n - count)
                        rng.shuffle(b)
                        surplus = count - threshold
                        ds = [(surplus >> j) & 1 for j in range(ell)]
                        xi = rng.randrange(q)
                        pk = rng.sample(range(1, q), n)
                        pkpad = pk + [0] * ell + [1]
                        chi = [1] * (n + ell) + [0]
                        w = [1] * n + [-(1 << j) for j in range(ell)] + [0]
                        aL = b + ds + [xi]
                        aR = [v - 1 for v in b + ds] + [0]
                        sL = [rng.randrange(q) for _ in range(N)]
                        sR = [rng.randrange(q) for _ in range(N)]
                        gens = [rng.randrange(1, q) for _ in range(N)]
                        hs = [rng.randrange(1, q) for _ in range(N)]
                        h0, alpha, rho, tau1, tau2 = [rng.randrange(1, q) for _ in range(5)]
                        y, z, x = [rng.randrange(1, q) for _ in range(3)]
                        powers = [pow(y, i, q) for i in range(N)]
                        A = (alpha * h0 + dot(aL, gens) + dot(aR, hs)) % q
                        S = (rho * h0 + dot(sL, gens) + dot(sR, hs)) % q
                        Qs, Qe = dot(sL, pkpad), dot(aL, pkpad)
                        l0 = [(aL[i] - z * chi[i]) % q for i in range(N)]
                        r0 = [(powers[i] * (aR[i] + z * chi[i]) + z*z*w[i]) % q for i in range(N)]
                        r1 = [powers[i] * sR[i] % q for i in range(N)]
                        t1 = (dot(l0, r1) + dot(sL, r0)) % q
                        t2 = dot(sL, r1)
                        T1, T2 = (t1 + tau1*h0) % q, (t2 + tau2*h0) % q
                        vL = [(aL[i] + x*sL[i]) % q for i in range(N)]
                        vR = [(aR[i] + x*sR[i]) % q for i in range(N)]
                        mu, taux = (alpha + x*rho) % q, (x*tau1 + x*x*tau2) % q
                        that = dot([(vL[i] - z*chi[i]) % q for i in range(N)],
                                   [(powers[i]*(vR[i] + z*chi[i]) + z*z*w[i]) % q for i in range(N)])
                        theta = (z*z*threshold + (z-z*z)*dot(chi, powers) - z**3*dot(chi, w)) % q
                        self.assertEqual(dot(l0, r0), theta)
                        self.assertEqual((A + x*S) % q, (mu*h0 + dot(vL, gens) + dot(vR, hs)) % q)
                        self.assertEqual((Qe + x*Qs) % q, dot(vL, pkpad))
                        self.assertEqual(that, (dot(l0, r0) + x*t1 + x*x*t2) % q)
                        self.assertEqual(that, (theta + x*T1 + x*x*T2 - taux*h0) % q)
                        self.assertNotEqual((A + 1 + x*S) % q, (mu*h0 + dot(vL, gens) + dot(vR, hs)) % q)
                        self.assertNotEqual((Qe + 1 + x*Qs) % q, dot(vL, pkpad))
                        self.assertNotEqual((that + 1) % q, (dot(l0, r0) + x*t1 + x*x*t2) % q)
                        self.assertNotEqual(that, (theta + z*z + x*T1 + x*x*T2 - taux*h0) % q)
                        self.assertNotEqual(that, (theta + x*(T1 + 1) + x*x*T2 - taux*h0) % q)


if __name__ == "__main__":
    unittest.main()
