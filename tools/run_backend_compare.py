#!/usr/bin/env python3
"""Collect repeated public-operation and MSM samples from the backend comparator."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--launches", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--library-dir", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if args.library_dir:
        env["LD_LIBRARY_PATH"] = str(args.library_dir.resolve()) + os.pathsep + env.get(
            "LD_LIBRARY_PATH", ""
        )

    with args.output.open("w", encoding="utf-8") as output:
        metadata = {
            "type": "metadata",
            "binary": str(binary),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "platform": platform.platform(),
            "cpu": platform.processor(),
            "launches": args.launches,
            "iterations": args.iterations,
            "note": "public operations and public MSM only; libsecp256k1 MSM is per-term multiply plus combine",
        }
        output.write(json.dumps(metadata, sort_keys=True) + "\n")
        for launch in range(args.launches):
            result = subprocess.run(
                [str(binary), str(args.iterations)],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            for line in result.stdout.splitlines():
                record = json.loads(line)
                record["launch"] = launch
                output.write(json.dumps(record, sort_keys=True) + "\n")
            print(f"launch={launch + 1}/{args.launches}", flush=True)
    print(args.output)


if __name__ == "__main__":
    main()
