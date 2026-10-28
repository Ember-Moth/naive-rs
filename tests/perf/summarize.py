#!/usr/bin/env python3
"""Print medians/ranges from run.py's raw JSON, without hiding individual runs."""
import argparse
import collections
import json
import statistics


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result")
    args=parser.parse_args()
    data=json.load(open(args.result))
    groups=collections.defaultdict(list)
    for run in data["runs"]:
        groups[run["protocol"],run["case"],run["variant"]].append(run)
    print("| Protocol | Case | Variant | Runs | MiB/s median [min, max] | CPU s median | P50 / P99 µs | RSS MiB |")
    print("|---|---|---|---:|---:|---:|---:|---:|")
    for (protocol,case,variant),runs in sorted(groups.items()):
        speeds=[r.get("payload_mib_per_second",0) for r in runs]
        cpu=statistics.median(r["cpu_seconds"] for r in runs)
        p50=statistics.median(r.get("p50_us",0) for r in runs)
        p99=statistics.median(r.get("p99_us",0) for r in runs)
        rss=statistics.median(r.get("rss_blocked_bytes",r["peak_rss_bytes"]) for r in runs)/1048576
        print(f"| {protocol} | {case} | {variant} | {len(runs)} | {statistics.median(speeds):.2f} [{min(speeds):.2f}, {max(speeds):.2f}] | {cpu:.4f} | {p50:.1f} / {p99:.1f} | {rss:.2f} |")


if __name__=="__main__": main()
