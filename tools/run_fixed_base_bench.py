#!/usr/bin/env python3
"""Collect public generator fixed-base ablation samples from two benchmark builds."""
import hashlib
import json
from pathlib import Path
import subprocess

output = Path("docs/benchmarks/phase5-fixed-base-20261108.jsonl")
binaries = {"on": Path("build/bench/primitive_bench"),
            "off": Path("build/bench-reference/primitive_bench")}
with output.open("x") as result:
    for launch in range(1, 6):
        order = ("on", "off") if launch % 2 else ("off", "on")
        for mode in order:
            binary = binaries[mode]
            command = [str(binary), "5"]
            completed = subprocess.run(command, capture_output=True, text=True, check=True)
            for line in completed.stdout.splitlines():
                row = json.loads(line)
                if row["name"] != "secp256k1_generator_mul_full_width":
                    continue
                row.update({"mode": mode, "launch": launch,
                            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
                result.write(json.dumps(row) + "\n")
            result.flush()
            print(f"launch={launch} mode={mode} complete", flush=True)
