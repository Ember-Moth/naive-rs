#!/usr/bin/env python3
"""Validate release assets and reuse only equivalent, fully built SDK snapshots."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def targets():
    return {line.split()[0] for line in run("cargo", "xtask", "targets").splitlines()}


def relevant(path):
    return (path.startswith(("crates/", "native/", "patches/", "xtask/", "tests/", ".cargo/"))
            or (path.startswith("tools/") and path != "tools/release-assets.py")
            or path in {"Cargo.toml", "Cargo.lock", "upstream.lock.json", ".gitmodules"})


def snapshot(ref):
    result = {}
    for path in run("git", "ls-tree", "-r", "--name-only", ref).splitlines():
        if not relevant(path):
            continue
        data = subprocess.check_output(["git", "show", f"{ref}:{path}"], cwd=ROOT)
        if path.endswith("Cargo.toml"):
            value = tomllib.loads(data.decode())
            value.get("package", {}).pop("rust-version", None)
            value.get("workspace", {}).get("package", {}).pop("rust-version", None)
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        result[path] = hashlib.sha256(data).hexdigest()
    return result


def check_source(previous):
    previous = run("git", "rev-parse", "--verify", f"{previous}^{{commit}}")
    subprocess.run(["git", "merge-base", "--is-ancestor", previous, "HEAD"], cwd=ROOT, check=True)
    before, after = snapshot(previous), snapshot("HEAD")
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    if changed:
        raise RuntimeError("SDK promotion requires identical code, dependencies and tests: " + ", ".join(changed))
    print("Equivalent source snapshot verified:", previous)


def check_run(repository, run_id):
    info = json.loads(run("gh", "api", f"repos/{repository}/actions/runs/{run_id}"))
    if info["path"] != ".github/workflows/native-artifacts.yml":
        raise RuntimeError("source run is not the native-artifacts workflow")
    jobs = json.loads(run("gh", "api", f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"))["jobs"]
    built = {}
    for job in jobs:
        if job["name"].startswith("build ("):
            target = job["name"].split("(", 1)[1].split(",", 1)[0]
            if target in built:
                raise RuntimeError("duplicate target in source run: " + target)
            built[target] = job["conclusion"]
    if set(built) != targets() or any(result != "success" for result in built.values()):
        raise RuntimeError("every native target in the source run must pass: " + repr(built))
    check_source(info["head_sha"])
    print("All native target jobs passed in run", run_id)


def restore_sdk(repository, run_id, target, install_to=None):
    if target not in targets():
        raise RuntimeError("unsupported target: " + target)
    info = json.loads(run("gh", "api", f"repos/{repository}/actions/runs/{run_id}"))
    if info["path"] != ".github/workflows/native-artifacts.yml":
        raise RuntimeError("source run is not the native-artifacts workflow")
    jobs = json.loads(run("gh", "api", f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"))["jobs"]
    passed = any(job["name"].startswith(f"build ({target},") and job["conclusion"] == "success" for job in jobs)
    if not passed:
        print("No successful source job; build native SDK:", target)
        return False
    with tempfile.TemporaryDirectory(prefix="native-cache-") as temporary:
        subprocess.run(["gh", "run", "download", str(run_id), "--repo", repository,
                        "--name", "native-" + target, "--dir", temporary], cwd=ROOT, check=True)
        verify_assets(Path(temporary), [target], install_to or ROOT / "target/native/lib")
    return True


def verify_assets(directory, selected, install_to=None):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    selected = set(selected) if selected else targets()
    if not selected <= targets():
        raise RuntimeError("unsupported target")
    directory = directory.resolve()
    expected = {f"naive-rs-native-{version}-{target}.tar.gz" for target in selected}
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != expected | {name + ".sha256" for name in expected}:
        raise RuntimeError("unexpected release asset set: " + repr(actual))

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass

    with tempfile.TemporaryDirectory(prefix="release-sdk-") as temporary:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(directory))) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                for target in sorted(selected):
                    name = f"naive-rs-native-{version}-{target}.tar.gz"
                    archive = directory / name
                    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    checksum = (directory / (name + ".sha256")).read_text().split()
                    if len(checksum) not in (1, 2) or checksum[0] != digest or (len(checksum) == 2 and checksum[1].lstrip("*") != name):
                        raise RuntimeError("published checksum mismatch: " + name)
                    destination = (install_to.resolve() if install_to else Path(temporary)) / target
                    subprocess.run([
                        "cargo", "xtask", "fetch", "--target", target,
                        "--url", f"http://127.0.0.1:{server.server_address[1]}/{name}",
                        "--sha256", digest, "--allow-http", "--destination", str(destination),
                    ], cwd=ROOT, check=True)
                    print("Validated release bundle:", target, digest)
            finally:
                server.shutdown()
                worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source")
    source.add_argument("previous")
    previous_run = commands.add_parser("run")
    previous_run.add_argument("run_id", type=int)
    previous_run.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    restore = commands.add_parser("restore")
    restore.add_argument("run_id", type=int)
    restore.add_argument("target")
    restore.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    restore.add_argument("--install-to", type=Path)
    assets = commands.add_parser("assets")
    assets.add_argument("directory", type=Path)
    assets.add_argument("--target", action="append")
    assets.add_argument("--install-to", type=Path, help="retain verified SDKs below this directory")
    args = parser.parse_args()
    if args.command == "source":
        check_source(args.previous)
    elif args.command == "run":
        if not args.repository or args.run_id <= 0:
            parser.error("repository and a positive run ID are required")
        check_run(args.repository, args.run_id)
    elif args.command == "restore":
        if not args.repository or args.run_id <= 0:
            parser.error("repository and a positive run ID are required")
        reused = restore_sdk(args.repository, args.run_id, args.target, args.install_to)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("reused=" + str(reused).lower() + "\n")
    else:
        verify_assets(args.directory, args.target, args.install_to)


if __name__ == "__main__":
    main()
