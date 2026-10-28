#!/usr/bin/env python3
"""Build the pinned upstream Naive Caddy fixture, including its required patches.

Uses Go's verified module cache as immutable input. All modifications and build
output are isolated below target/test-tools. Does not install anything globally.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FORWARD = "github.com/klzgrad/forwardproxy@v0.0.0-20261022172731-e747854e7874"
CADDY = "github.com/caddyserver/caddy/v2@v2.11.7"


def download(module):
    result = subprocess.run(["go", "mod", "download", "-json", module], cwd=ROOT,
                            check=True, capture_output=True, text=True)
    return Path(json.loads(result.stdout)["Dir"])


def main():
    forward, caddy = download(FORWARD), download(CADDY)
    assert (forward / "CADDY_VERSION").read_text().strip() == CADDY.split("@")[1]
    dest = ROOT / "target/test-tools"
    dest.mkdir(parents=True, exist_ok=True)
    native = dest / "caddy-v2.11.7-e747854"
    if not (native / ".prepared").exists():
        if native.exists():
            raise RuntimeError(f"incomplete Caddy preparation at {native}; remove this generated directory before retrying")
        shutil.copytree(caddy, native)
        for path in [native, *native.rglob("*")]:
            path.chmod(path.stat().st_mode | 0o200)
        subprocess.run(["git", "init", "-q"], cwd=native, check=True)
        for name in ["caddy-sing-quic-bbrv1.patch", "caddy-read-idle-timeout.patch"]:
            subprocess.run(["git", "apply", "--check", str(forward / name)], cwd=native, check=True)
            subprocess.run(["git", "apply", str(forward / name)], cwd=native, check=True)
        (native / ".prepared").write_text(FORWARD)
    build = dest / "caddy-build"
    build.mkdir(exist_ok=True)
    for name in ["main.go", "go.mod", "go.sum"]:
        shutil.copyfile(ROOT / "tests/caddy" / name, build / name)
    subprocess.run(["go", "mod", "edit", f"-replace=github.com/caddyserver/caddy/v2={native}"], cwd=build, check=True)
    subprocess.run(["go", "mod", "tidy"], cwd=build, check=True)
    binary = dest / ("caddy.exe" if os.name == "nt" else "caddy")
    subprocess.run(["go", "build", "-o", str(binary), "."], cwd=build, check=True)
    print(binary)


if __name__ == "__main__":
    main()
