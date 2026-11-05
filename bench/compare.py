#!/usr/bin/env python3
"""Interleaved wall-clock comparison of bench binaries against bench/server.c.
Usage: compare.py <server> <bench-a> [<bench-b> ...] [--runs N]"""
import argparse
import re
import statistics
import subprocess
import time

MODES = [("http-small", 20000), ("http-large", 100), ("http-large-stream", 100),
         ("http-chunked", 500), ("ws-small", 20000), ("ws-large", 500), ("ws-frag", 2000)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("server")
    parser.add_argument("benches", nargs="+")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--port", type=int, default=9181)
    args = parser.parse_args()
    server = subprocess.Popen([args.server, str(args.port)])
    time.sleep(0.3)
    try:
        print("| mode | " + " | ".join(args.benches) + " |")
        print("| --- |" + " --- |" * len(args.benches))
        for mode, n in MODES:
            samples = {b: [] for b in args.benches}
            for _ in range(args.runs):
                for b in args.benches:
                    out = subprocess.run([b, str(args.port), mode, str(n)], capture_output=True,
                                         text=True, check=True, timeout=300).stdout
                    samples[b].append(int(re.search(r"ns/op=(\d+)", out).group(1)))
            cells = []
            for b in args.benches:
                s = samples[b]
                cells.append(f"{statistics.median(s) / 1000:.1f} µs (±{(max(s) - min(s)) / 2000:.1f})")
            print(f"| {mode} | " + " | ".join(cells) + " |", flush=True)
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
