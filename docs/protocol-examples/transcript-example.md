# Draft transcript example

This example checks encoding and hashing only. It is self-generated, is not a complete signature or independently reviewed known-answer test, and must not be used as evidence of protocol security.

For n = 1, t = 1, roster `[G]`, message ASCII `abc`, session ID ASCII `session-1`, subset `[1]`, and Qe = R1 = R2 = R = G, use the compressed secp256k1 base point:

```
G = 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

The draft roster encoding, split only for display, is:

```
0100000058
02000000104854412d736563703235366b312d7631
0200000006524f53544552
03000000080000000000000001
06000000260400000021
0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

Its SHA-256 digest is `5e2d5167321e94eac08ec2e24b981f2e45d741b7a8cf35df029b06ed6a9a7fe8`. This digest was cross-checked with OpenSSL; the framing construction itself has not been independently validated. The nonce and signature challenge outputs and authorization challenge examples are recorded in `tests/test_framing_vector.py`. Those examples use counter zero and do not exercise hash rejection.

Before freezing the suite, an independent reviewer should regenerate every encoded byte and challenge from the draft, check all point and scalar boundaries, and provide distinct malformed-input and rejection-path vectors. The example makes no claim that these public values form a valid signature or proof.
