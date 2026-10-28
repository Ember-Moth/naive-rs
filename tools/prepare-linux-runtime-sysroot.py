#!/usr/bin/env python3
"""Create a separate final-link sysroot for Rust completion runtimes.

Chromium deliberately hides glibc defaults newer than 2.26. A Rust runtime
using statx needs the ordinary glibc exports instead. Keep the native-build
sysroot untouched and overlay checksum-pinned, unmodified Debian libraries
into a separate copy. No package scripts or target executables are run.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open("rb") as source:
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
        return digest.hexdigest()


def main():
    metadata = json.loads((ROOT / "tools/linux-runtime-libs.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=metadata["targets"])
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    entry = metadata["targets"][args.target]
    stamp = source / ".naive-prebuilt-sha256"
    base_digest = stamp.read_text().strip()
    if base_digest != entry["native_sysroot_sha256"]:
        raise SystemExit("source sysroot does not match the pinned target")
    provenance = {
        "native_sysroot_sha256": base_digest,
        "libc_package_sha256": entry["sha256"],
        "libc_version": entry["version"],
        "target": args.target,
        "purpose": "Rust final linking; not the Chromium native-build sysroot",
    }
    destination = ROOT / "target/native/runtime-sysroots" / args.target
    marker = destination / ".naive-runtime-sysroot.json"
    if destination.exists():
        if marker.is_file() and json.loads(marker.read_text()) == provenance:
            print(destination)
            return
        raise SystemExit(f"move the old generated runtime sysroot aside: {destination}")

    cache = ROOT / "target/native/runtime-libc"
    cache.mkdir(parents=True, exist_ok=True)
    package = cache / entry["url"].rsplit("/", 1)[1]
    if not package.is_file():
        temporary = package.with_suffix(".download")
        try:
            subprocess.run([
                "curl", "--fail", "--location", "--retry", "3", "--max-time", "120",
                "--output", str(temporary), entry["url"]
            ], check=True, stdout=sys.stderr)
            if sha256(temporary) != entry["sha256"]:
                raise RuntimeError("runtime libc download SHA-256 mismatch")
            temporary.rename(package)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256(package) != entry["sha256"]:
        raise SystemExit(f"runtime libc package SHA-256 mismatch: {package}")

    members = subprocess.check_output(["ar", "t", str(package)], text=True).splitlines()
    payloads = [name for name in members if name.startswith("data.tar")]
    if len(payloads) != 1:
        raise SystemExit("unexpected Debian package payload")
    payload = subprocess.check_output(["ar", "p", str(package), payloads[0]])
    staging = destination.with_name(destination.name + ".staging")
    if staging.exists():
        raise SystemExit(f"stale generated staging directory: {staging}")
    staging.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(source, staging, symlinks=True)
        copied = set()
        directory = PurePosixPath("lib") / entry["triple"]
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                # Keep the already-relativized sysroot symlinks. Only replace
                # ordinary library files in this exact architecture directory.
                if not member.isfile() or name.parent != directory:
                    continue
                if ".." in name.parts or name.is_absolute():
                    raise RuntimeError("unsafe package library path")
                output = staging / str(name)
                if output.is_symlink():
                    raise RuntimeError("refusing to overwrite a sysroot symlink")
                with archive.extractfile(member) as data, output.open("wb") as target:
                    shutil.copyfileobj(data, target)
                output.chmod(member.mode & 0o777)
                copied.add(name.name)
        if "libc-2.31.so" not in copied:
            raise RuntimeError("package did not supply the pinned libc")
        (staging / ".naive-prebuilt-sha256").unlink()
        (staging / ".naive-runtime-sysroot.json").write_text(json.dumps(provenance, indent=2) + "\n")
        staging.rename(destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    print(destination)


if __name__ == "__main__":
    main()
