# Analytic sizes

33-byte nonidentity points; 32-byte scalars. These are fixed-width cryptographic payload counts, not the typed transport format. Identity commitments may shorten actual encoded payloads.

`signature=33*(7+2*r)+32*(5+2*N//2**r)`; `certificate=signature-98`. Signer responses contain 66 B and 32 B before framing. Public setup point payload is `33*(n+2*N+3)`, excluding metadata/PoPs.

| n | t | N | kappa | r | Signature B | Certificate B | Roster + generators B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 64 | 43 | 128 | 7 | 0 | 8,583 | 8,485 | 10,659 |
| 64 | 43 | 128 | 7 | 4 | 1,167 | 1,069 | 10,659 |
| 64 | 43 | 128 | 7 | 7 | 917 | 819 | 10,659 |
| 256 | 171 | 512 | 9 | 0 | 33,159 | 33,061 | 42,339 |
| 256 | 171 | 512 | 9 | 6 | 1,299 | 1,201 | 42,339 |
| 256 | 171 | 512 | 9 | 9 | 1,049 | 951 | 42,339 |
| 1024 | 683 | 2048 | 11 | 0 | 131,463 | 131,365 | 169,059 |
| 1024 | 683 | 2048 | 11 | 8 | 1,431 | 1,333 | 169,059 |
| 1024 | 683 | 2048 | 11 | 11 | 1,181 | 1,083 | 169,059 |
| 2048 | 1366 | 4096 | 12 | 0 | 262,535 | 262,437 | 338,019 |
| 2048 | 1366 | 4096 | 12 | 9 | 1,497 | 1,399 | 338,019 |
| 2048 | 1366 | 4096 | 12 | 12 | 1,247 | 1,149 | 338,019 |
| 4096 | 2731 | 8192 | 13 | 0 | 524,679 | 524,581 | 675,939 |
| 4096 | 2731 | 8192 | 13 | 10 | 1,563 | 1,465 | 675,939 |
| 4096 | 2731 | 8192 | 13 | 13 | 1,313 | 1,215 | 675,939 |

At n=2048, generators alone occupy 270,435 B; roster keys add 67,584 B, giving 338,019 B total. The fully folded certificate is 1,149 B; the signature is 1,247 B. “About 1.2 KB” is a certificate estimate, not a full request estimate.

The specified subset representation uses 13 bytes per framed index plus its enclosing transcript. With t=1366 at n=2048, indices alone consume 17,758 B. A complete request also includes message, certificate, key, IDs, mode and framing. Report measured request sizes; do not label them 1.2 KB.

Resource check: maximum N=131072. At r=0, terminal scalar vectors occupy 2*N*37=9,699,328 framed bytes, below the 10 MiB proof cap with remaining proof fields. A 16 MiB message plus maximum subset (65535*13=851,955 B) and maximum proof fits below the 28 MiB Round-1 cap.
