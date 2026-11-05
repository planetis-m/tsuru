#!/usr/bin/env python3
"""Sum cachegrind Ir per run, excluding the scheduler (threadpool, ioring) and
the bench's own setup, whose counts vary with thread timing."""
import re
import sys

SCHEDULER = re.compile(r"_(thr|iou|ioQ|ior)[A-Za-z0-9_]{6,}$")
TSURU = re.compile(r"_(web|fra|pro|han|htt|hea|tra|ent|buf|end|net)[A-Za-z0-9_]{6,}$")


def totals(path):
    per_fn = {}
    fn = None
    with open(path) as f:
        for line in f:
            if line.startswith("fn="):
                fn = line[3:].strip()
            elif line[:1].isdigit() and fn is not None:
                parts = line.split()
                if len(parts) >= 2:
                    per_fn[fn] = per_fn.get(fn, 0) + int(parts[1])
    return per_fn


for path in sys.argv[1:]:
    per_fn = totals(path)
    total = sum(per_fn.values())
    sched = sum(v for k, v in per_fn.items() if SCHEDULER.search(k))
    own = sum(v for k, v in per_fn.items() if TSURU.search(k))
    print(f"{path}: total={total:,} scheduler={sched:,} client={total - sched:,} tsuru-self={own:,}")
