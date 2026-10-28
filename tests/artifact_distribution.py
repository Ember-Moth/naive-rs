#!/usr/bin/env python3
"""Exercise real native package installation and adversarial archive rejection."""
import functools
import argparse
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]


def run(*args, env=None, success=True):
    result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != success:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite(source, output, *, mutate=None, extra=None):
    with tarfile.open(source, "r:gz") as archive:
        members = [(member.name, archive.extractfile(member).read()) for member in archive.getmembers()]
    if mutate:
        members = mutate(members)
    with tarfile.open(output, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if extra:
            extra(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="native/Rust target to link; defaults to the rustc host")
    args = parser.parse_args()
    target = args.target or next(line[6:] for line in run("rustc", "-vV").stdout.splitlines() if line.startswith("host: "))
    with tempfile.TemporaryDirectory(prefix="artifacts-", dir=ROOT / "target") as work:
        work = Path(work)
        archive = work / "native.tar.gz"
        run("cargo", "xtask", "package", "--target", target, "--output", str(archive))
        repeat = work / "repeat.tar.gz"
        run("cargo", "xtask", "package", "--target", target, "--output", str(repeat))
        assert sha(archive) == sha(repeat), "packaging is not deterministic"
        with tarfile.open(archive, "r:gz") as contents:
            names = contents.getnames()
        assert any(name.startswith("licenses/upstream/") for name in names)
        assert "include/naive_network.h" in names

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(work))) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                destination = work / "installed"

                def fetch(path, *, target=target, digest=None, success=True, replace=False):
                    args = ["cargo", "xtask", "fetch", "--target", target, "--url", f"{base}/{path.name}", "--sha256", digest or sha(path), "--allow-http", "--destination", str(destination)]
                    if replace:
                        args.append("--replace")
                    return run(*args, success=success)

                fetch(archive)
                manifest = json.loads((destination / "manifest.json").read_text())
                library = destination / manifest["archive"]
                expected_library = sha(library)
                marker = destination / "keep-me"
                marker.write_text("existing installation")
                fetch(archive, success=False)
                fetch(archive, digest="0" * 64, success=False, replace=True)
                other = "x86_64-unknown-linux-gnu" if target != "x86_64-unknown-linux-gnu" else "aarch64-apple-darwin"
                fetch(archive, target=other, success=False, replace=True)

                cases = []
                for field in ["fingerprint", "wrapper_version", "abi", "upstream", "libs"]:
                    path = work / f"wrong-{field}.tar.gz"
                    def mutate(members, field=field):
                        result = []
                        for name, data in members:
                            if name == "manifest.json":
                                value = json.loads(data)
                                value[field] = ["bad\ncargo:rustc-link-arg=unexpected"] if field == "libs" else "wrong-version"
                                data = json.dumps(value).encode()
                            result.append((name, data))
                        return result
                    rewrite(archive, path, mutate=mutate)
                    cases.append(path)
                path = work / "corrupt-member.tar.gz"
                rewrite(archive, path, mutate=lambda members: [(name, b"corrupt" if name == manifest["archive"] else data) for name, data in members])
                cases.append(path)
                path = work / "traversal.tar.gz"
                def traversal(archive):
                    info = tarfile.TarInfo("../../escape")
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
                rewrite(archive, path, extra=traversal)
                cases.append(path)
                path = work / "symlink.tar.gz"
                def symlink(archive):
                    info = tarfile.TarInfo("link")
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/tmp"
                    archive.addfile(info)
                rewrite(archive, path, extra=symlink)
                cases.append(path)
                path = work / "duplicate.tar.gz"
                rewrite(archive, path, mutate=lambda members: members + [members[0]])
                cases.append(path)
                for path in cases:
                    fetch(path, success=False, replace=True)
                    assert marker.read_text() == "existing installation"
                    assert sha(library) == expected_library
                    assert not (work.parent / "escape").exists()
                fetch(archive, replace=True)
                assert not marker.exists()
                assert sha(library) == expected_library

                consumer = work / "consumer"
                (consumer / "src").mkdir(parents=True)
                (consumer / "Cargo.toml").write_text(f'''[package]
name = "native-package-consumer"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
naive-rs = {{ path = {json.dumps(str(ROOT / 'crates/naive'))}, default-features = false }}
futures-executor = "0.3"
''')
                (consumer / "src/main.rs").write_text('''fn main() {
    futures_executor::block_on(async {
        let client = naive::NaiveClient::new(naive::Config::new("http://127.0.0.1:9")).await.unwrap();
        assert!(!naive::native_version().is_empty());
        client.shutdown().await.unwrap();
        let mut config = naive::browser::BrowserConfig::default();
        config.ech.insert("localhost".into(), naive::EchOptions {
            mode: naive::EchMode::Disabled, ..Default::default()
        });
        config.certificate_verifier = Some(std::sync::Arc::new(
            |_: naive::CertificateInfo, done: naive::CertificateVerification| {
                let cancellation = done.cancellation();
                let _ = cancellation.is_cancelled();
                done.complete(naive::CertificateDecision::UseDefault);
            }
        ));
        let browser = naive::browser::BrowserClient::new(config).await.unwrap();
        let _ = browser.connect_tls("localhost", 9).await;
        let _ = browser.get("http://localhost:9/").await;
        let _ = browser.connect_websocket(naive::browser::WebSocketRequest::new(
            "ws://localhost:9/", "http://localhost")).await;
        browser.shutdown().await.unwrap();
    });
}
''')
                run("cargo", "build", "--offline", "--target", target, "--manifest-path", str(consumer / "Cargo.toml"), env={**os.environ, "NAIVE_NATIVE_DIR": str(destination), "CARGO_TARGET_DIR": str(work / "consumer-build")})
                print(f"{target}: deterministic package, install/replace, {len(cases)+3} rejection cases, and real Rust consumer link passed")
            finally:
                server.shutdown()
                worker.join()


if __name__ == "__main__":
    main()
