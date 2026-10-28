#!/usr/bin/env python3
"""Optional macOS arm64 cronet-go reference (different Chromium/build settings).

Fetch only its pinned source/header/native-library paths. Go's proxy does not
need to resolve the large binary-bearing branch. No production dependency.
"""
from pathlib import Path
import hashlib
import json
import platform
import subprocess

ROOT=Path(__file__).resolve().parents[2]
COMMIT="0d28acc44093df24b2526dea3d6ffefd6b0a54f0"

def run(args,cwd):
    subprocess.run(args,cwd=cwd,check=True)

def main():
    if platform.system()!="Darwin" or platform.machine()!="arm64":
        raise SystemExit("This reference recipe currently targets macOS arm64")
    source=ROOT/"target/perf/cronet-go-src"
    if not source.exists():
        source.mkdir(parents=True)
        run(["git","init","-q"],source)
        run(["git","remote","add","origin","https://github.com/SagerNet/cronet-go.git"],source)
        run(["git","fetch","--depth=1","--filter=blob:none","origin",COMMIT],source)
        run(["git","sparse-checkout","set","include","internal","lib/darwin_arm64"],source)
        run(["git","checkout","--detach",COMMIT],source)
    head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=source,text=True).strip()
    if head!=COMMIT: raise SystemExit("Reference source HEAD mismatch")
    run(["git","diff","--exit-code"],source)
    package=ROOT/"tests/perf/cronet"
    run(["go","build","-mod=readonly","-ldflags=-extldflags=-Wl,-dead_strip","-o",str(ROOT/"target/perf/cronet-go"),"."],package)
    metadata={"repository":"https://github.com/SagerNet/cronet-go","commit":head,
              "native_archive_sha256":hashlib.sha256((source/"lib/darwin_arm64/libcronet.a").read_bytes()).hexdigest(),
              "go":subprocess.check_output(["go","version"],text=True).strip(),
              "caveat":"Reference has Chromium 150 and different native flags/protocol defaults; not a controlled language comparison."}
    (ROOT/"target/perf/reference-build.json").write_text(json.dumps(metadata,indent=2)+"\n")

if __name__=="__main__": main()
