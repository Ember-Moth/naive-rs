#!/usr/bin/env python3
"""Run Rust interop tests against pinned Caddy/Naive on loopback only.

Build the fixture first: python3 tests/build_caddy.py
Or supply --caddy /path/to/caddy-with-naive-forwardproxy.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy", type=Path, default=ROOT / ("target/test-tools/caddy.exe" if os.name == "nt" else "target/test-tools/caddy"))
    parser.add_argument("--target", default=os.environ.get("NAIVE_TEST_TARGET"))
    args = parser.parse_args()
    if not args.caddy.is_file():
        parser.error("Caddy fixture missing; see the build command in --help")
    with tempfile.TemporaryDirectory(prefix="naive-rs-interop-") as temp:
        temp = Path(temp)
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        key.chmod(0o600)
        unrelated_cert, unrelated_key = temp / "unrelated.pem", temp / "unrelated-key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "1", "-subj", "/CN=unrelated-test-root",
            "-keyout", str(unrelated_key), "-out", str(unrelated_cert),
        ], check=True, capture_output=True)
        unrelated_key.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        credentials = base64.b64encode(base64.b64encode(b"test:test")).decode()
        config = {
            "admin": {"disabled": True, "config": {"persist": False}},
            "apps": {
                "tls": {"certificates": {"load_files": [{"certificate": str(cert), "key": str(key)}]}},
                "http": {"servers": {"test": {
                    "listen": [f"127.0.0.1:{port}"], "protocols": ["h1", "h2", "h3"],
                    "automatic_https": {"disable": True},
                    # Present the localhost certificate even for wrong.invalid,
                    # so the client verifier (not server SNI selection) rejects it.
                    "tls_connection_policies": [{"fallback_sni": "localhost"}],
                    "routes": [{"handle": [
                        {"handler": "forward_proxy", "auth_credentials": [credentials],
                         "hide_ip": True, "hide_via": True,
                         "acl": [{"subjects": ["127.0.0.1"], "allow": True}]},
                        {"handler": "static_response", "body": "<!doctype html><title>Local interop</title>"},
                    ]}],
                }}},
            },
        }
        path = temp / "caddy.json"
        path.write_text(json.dumps(config))
        with EchoServer(("127.0.0.1", 0), Echo) as origin, (temp / "caddy.log").open("w+") as log:
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            proc = subprocess.Popen([str(args.caddy.resolve()), "run", "--config", str(path)],
                                    cwd=temp, stdout=log, stderr=subprocess.STDOUT,
                                    env={**os.environ, "XDG_DATA_HOME": str(temp / "data"), "XDG_CONFIG_HOME": str(temp / "config")})
            try:
                deadline = time.monotonic() + 15
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError(f"Caddy exited before startup: {proc.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Caddy startup timed out")
                        time.sleep(0.05)
                subprocess.run(["cargo", "test", "--locked", "-p", "naive-rs", "--features", "tokio", *(["--target", args.target] if args.target else []), "--test", "interop", "--", "--ignored", "--nocapture", "--test-threads=1"],
                               cwd=ROOT, check=True, timeout=180,
                               env={**os.environ, "NAIVE_TEST_PROXY_PORT": str(port),
                                    "NAIVE_TEST_ORIGIN_PORT": str(origin.server_address[1]),
                                    "NAIVE_TEST_TRACE_DIR": str(temp),
                                    "NAIVE_TEST_UNRELATED_CA": unrelated_cert.read_text(),
                                    "NAIVE_TEST_CA_PEM": cert.read_text()})
            except BaseException:
                log.flush()
                print((temp / "caddy.log").read_text())
                raise
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                origin.shutdown()
                thread.join()


if __name__ == "__main__":
    main()
