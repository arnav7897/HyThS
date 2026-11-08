#!/usr/bin/env python3
"""Render protocol matrix means from the saved JSON lines."""
import json
from pathlib import Path
import sys

rows = {}
for argument in sys.argv[1:]:
    directory = Path(argument)
    for line in (directory / "summary.jsonl").read_text().splitlines():
        row = json.loads(line)
        key = (row["n"], row["t"], row["k"])
        rows.setdefault(key, {})[row["stage"]] = row["mean_ns"] / 1e6
    for line in (directory / "raw.jsonl").read_text().splitlines():
        row = json.loads(line)
        if row["stage"] == "serialized_signature_size":
            key = (row["n"], row["threshold"], row["signers"])
            rows.setdefault(key, {})["bytes"] = row["output_bytes"]

print("| n | t | k | Round 1 | Round 2 | Prove | Verify | Signature bytes |")
print("|---:|---:|---:|---:|---:|---:|---:|---:|")
for (n, t, k), row in sorted(rows.items()):
    print(f"| {n} | {t} | {k} | {row['signer_round1']:.3f} | {row['signer_round2']:.3f} | "
          f"{row['authorization_prove']:.3f} | {row['full_verify']:.3f} | {row['bytes']} |")
