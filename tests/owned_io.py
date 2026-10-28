#!/usr/bin/env python3
"""Repeat bounded owned-IO regressions on this host with loopback-only fixtures.

Requires an already-built native library and the pinned Caddy fixture from
tests/build_caddy.py. Never starts an application, simulator, emulator or VM.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def source_hashes():
    paths = [ROOT / name for name in ["Cargo.toml", "Cargo.lock", "upstream.lock.json",
             ".cargo/config.toml", "patches/series", "crates/naive-sys/native-version.json",
             "tests/caddy/go.mod", "tests/caddy/go.sum"]]
    for directory in ["crates", "native", "patches", "tests", "xtask/src"]:
        paths.extend(p for p in (ROOT / directory).rglob("*")
                     if p.is_file() and p.suffix in {".rs", ".cc", ".h", ".py", ".patch", ".gn", ".toml"})
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


def run_case(name, command, output):
    start = time.monotonic()
    entry = {"name": name, "command": command, "log": name + ".log"}
    with (output / entry["log"]).open("w") as log:
        proc = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=os.name != "nt")
        try:
            entry["exit_code"] = proc.wait(timeout=240)
        except subprocess.TimeoutExpired:
            entry["timed_out"] = True
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            entry["exit_code"] = proc.returncode
    entry["seconds"] = round(time.monotonic() - start, 3)
    text = re.sub(r"\x1b\[[0-9;]*m", "", (output / entry["log"]).read_text(errors="replace"))
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    entry["passed_tests"] = sum(int(summary[0]) for summary in summaries)
    entry["ignored_tests"] = sum(int(summary[2]) for summary in summaries)
    entry["passed"] = entry["exit_code"] == 0 and entry["passed_tests"] > 0
    print(f"{name}: {'passed' if entry['passed'] else 'FAILED'} ({entry['seconds']}s)", flush=True)
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "target/owned-runtime/final")
    parser.add_argument("--caddy", type=Path,
                        default=ROOT / ("target/test-tools/caddy.exe" if os.name == "nt" else "target/test-tools/caddy"))
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100:
        parser.error("--repeat must be between 1 and 100")
    if not args.caddy.is_file():
        parser.error("build the pinned Caddy fixture first: python3 tests/build_caddy.py")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    rustc = subprocess.check_output(["rustc", "-vV"], cwd=ROOT, text=True)
    target = next(line.removeprefix("host: ") for line in rustc.splitlines() if line.startswith("host: "))
    record = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": "host library runtime tests using loopback only",
        "target": target, "system": platform.system(), "machine": platform.machine(),
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "rustc": rustc.strip(), "source_sha256": source_hashes(),
        "native_manifest": json.loads((ROOT / "target/native/lib" / target / "manifest.json").read_text()),
        "caddy_sha256": hashlib.sha256(args.caddy.read_bytes()).hexdigest(),
        "application_or_emulator_execution": False, "repeat": args.repeat, "cases": [],
    }
    commands = [
        ("owned", ["cargo", "test", "--locked", "-p", "naive-rs", "--all-features", "--test", "owned",
                   "--", "--test-threads=1", "--nocapture"]),
        ("adapters", ["cargo", "test", "--locked", "-p", "naive-monoio", "-p", "naive-compio",
                      "--all-features", "--test", "runtime", "--", "--test-threads=1", "--nocapture"]),
        ("h2-h3", [sys.executable, str(ROOT / "tests/interop.py"), "--owned-io", "--caddy", str(args.caddy.resolve())]),
    ]
    for iteration in range(1, args.repeat + 1):
        for label, command in commands:
            result = run_case(f"{iteration:02d}-{label}", command, output)
            record["cases"].append(result)
            (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
            if not result["passed"]:
                raise SystemExit(f"regression failed; inspect {output / result['log']}")
    record["source_unchanged"] = source_hashes() == record["source_sha256"]
    record["passed"] = record["source_unchanged"]
    (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    if not record["source_unchanged"]:
        raise SystemExit("source changed while regressions ran; discard this result")
    print(f"All {len(record['cases'])} regression batches passed; record: {output / 'results.json'}")


if __name__ == "__main__":
    main()
