# Manual framing check

This check was assembled from the suite framing rules without calling repository encoding code, then hashed with OpenSSL SHA-256. It is an AI-generated cross-check, not independent human review or complete suite validation.

For `T("SUBSET", V())`, the transcript payload has 37 bytes: a 21-byte framed suite ID, an 11-byte framed label, and an empty 5-byte framed vector. The exact bytes are:

```text
010000002502000000104854412d736563703235366b312d763102000000065355425345540600000000
```

OpenSSL SHA-256: `870fc33e099ba48d5e73e077255609b40034006f556f932c680a86ab0abfe422`.

This is a framing boundary example only. An empty signer subset is invalid for a signing request, since the suite requires `t >= 1` and `|S| >= t`. It does not test a signing implementation, parser rejection, hash-to-curve, or proof serialization.
