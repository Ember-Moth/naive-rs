#!/usr/bin/env python3
"""Run native Chromium clients against isolated loopback origins, never a browser app."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from owned_io import source_hashes
from network_profile import extract

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/browser-runtime")
    parser.add_argument("--build-fixture", action="store_true")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--cert", type=Path, help="optional existing certificate for a manual browser baseline")
    parser.add_argument("--key", type=Path, help="private key paired with --cert")
    parser.add_argument("--serve-only", action="store_true", help="serve local origins for a manually supplied browser baseline; never launches a browser")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key): parser.error("--cert and --key must be supplied together")
    if not 1 <= args.repeat <= 100: parser.error("--repeat must be 1..100")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = ROOT / "target/test-tools/browser-origin"
    if args.build_fixture or not binary.is_file():
        binary.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["go", "build", "-o", str(binary), "."], cwd=ROOT / "tests/browser_fixture", check=True)
    with tempfile.TemporaryDirectory(prefix="native-browser-") as temp:
        temp = Path(temp)
        cert, key = (args.cert.resolve(), args.key.resolve()) if args.cert else (temp / "cert.pem", temp / "key.pem")
        if not args.cert:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:secret.ech.test,DNS:public.ech.test,DNS:other.ech.test",
                            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            key.chmod(0o600)
        with (output / "origin.log").open("w") as log:
            server = subprocess.Popen([str(binary), "-cert", str(cert), "-key", str(key), "-capture", str(output / "capture.jsonl")],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            try:
                selector = selectors.DefaultSelector()
                selector.register(server.stdout, selectors.EVENT_READ)
                if not selector.select(15):
                    raise RuntimeError("origin fixture startup timed out")
                ports = json.loads(server.stdout.readline())
                selector.close()
                env = {**os.environ, "BROWSER_CA": cert.read_text()}
                env.setdefault("MACOSX_DEPLOYMENT_TARGET", "13.0")
                env.update({"BROWSER_" + key.upper(): str(value) for key, value in ports.items()})
                (output / "ports.json").write_text(json.dumps(ports, indent=2) + "\n")
                if args.serve_only:
                    print(json.dumps({**ports, "capture":str(output / "capture.jsonl"), "certificate":str(cert)}, indent=2), flush=True)
                    print("Local origins ready. Stop with Ctrl-C after your manual baseline capture.", flush=True)
                    try:
                        while True: time.sleep(30)
                    except KeyboardInterrupt:
                        return
                command = ["cargo", "test", "-p", "naive-rs", "--all-features", "--locked", "--test", "browser", "--test", "security", "--", "--ignored", "--nocapture", "--test-threads=1"]
                inputs = source_hashes()
                for path in (ROOT / "tests/browser_fixture").iterdir():
                    if path.is_file(): inputs[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
                started = time.monotonic()
                codes = []
                with (output / "tests.log").open("w") as tests:
                    for iteration in range(args.repeat):
                        tests.write(f"\nRuntime iteration {iteration + 1}\n"); tests.flush()
                        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=tests, stderr=subprocess.STDOUT,
                                                start_new_session=os.name != "nt")
                        try:
                            code = proc.wait(timeout=240)
                        except (subprocess.TimeoutExpired, KeyboardInterrupt):
                            if os.name == "nt": subprocess.run(["taskkill","/F","/T","/PID",str(proc.pid)],check=False)
                            else: os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait()
                            raise
                        codes.append(code)
                        if code: break
                print((output / "tests.log").read_text())
                manifest = json.loads((ROOT / "target/native/lib" / subprocess.check_output(["rustc","-vV"], text=True).split("host: ")[1].splitlines()[0] / "manifest.json").read_text())
                receipt = {"base_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
                           "uncommitted_changes":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
                           "native_manifest":manifest,"source_sha256":inputs,"iterations":codes,
                           "fixture_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                           "seconds":round(time.monotonic()-started,3),"browser_baseline":"not provided",
                           "application_or_emulator_execution":False,"passed":False}
                (output / "results.json").write_text(json.dumps(receipt,indent=2)+"\n")
                if code: raise SystemExit(code)
                server.stdin.close()
                server.wait(timeout=10)
                observations = [json.loads(line) for line in (output / "capture.jsonl").read_text().splitlines()]
                accepted = [item for item in observations if item.get("kind") == "security-tls" and item.get("ech_accepted")]
                protocols = sorted({item.get("alpn") for item in accepted})
                if not {"h2", "h3", "http/1.1"}.issubset(protocols):
                    raise RuntimeError("server did not confirm ECH for every tested transport: " + repr(protocols))
                receipt["server_confirmed_ech"] = {"handshakes": len(accepted), "alpn": protocols}
                for protocol, name in [("HTTP/1.1","http1-profile.json"),("HTTP/2.0","http2-profile.json")]:
                    profile = extract(output / "capture.jsonl", "/profile", protocol,
                                      "native Chromium "+manifest["upstream"]["chromium"], ("sec-fetch-mode","navigate"))
                    (output / name).write_text(json.dumps(profile,indent=2)+"\n")
                for path,digest in inputs.items():
                    if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
                        raise RuntimeError("source changed during runtime validation: "+path)
                receipt["passed"] = True
                receipt["profiles"] = ["http1-profile.json","http2-profile.json"]
                (output / "results.json").write_text(json.dumps(receipt,indent=2)+"\n")
            finally:
                server.stdin.close()
                try: server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
