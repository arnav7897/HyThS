#!/usr/bin/env python3
"""Run the Zcash FROST example in the local Rust container, saving each result."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
checkout = root / "another_implementation" / "frost"
output = root / "docs" / "benchmarks" / "phase5-zcash-frost-20261112.jsonl"
sizes = [int(value) for value in sys.argv[1:]] or [2, 4, 8, 32, 64, 128, 256, 512, 1024, 2048]
with output.open("a", encoding="utf-8") as stream:
    for n in sizes:
        command = ["docker", "run", "--rm", "--network", "none", "-v", f"{checkout}:/work",
                   "-w", "/work", "rust:1", "target/release/examples/hta_matrix", str(n)]
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        row = json.loads(result.stdout)
        stream.write(json.dumps(row, sort_keys=True) + "\n")
        stream.flush()
        print(f"n={n} complete", flush=True)
