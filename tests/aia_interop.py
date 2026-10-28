#!/usr/bin/env python3
"""Verify proxy certificate validation does not fetch omitted issuers."""
import base64
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from interop import Echo, EchoServer, ROOT


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)


def main():
    caddy = ROOT / ("target/test-tools/caddy.exe" if os.name == "nt" else "target/test-tools/caddy")
    if not caddy.is_file():
        raise RuntimeError("run python3 tests/build_caddy.py first")
    with tempfile.TemporaryDirectory(prefix="naive-rs-aia-") as temp_dir:
        temp = Path(temp_dir)
        root, issuer, leaf = [temp / name for name in ("root", "issuer", "leaf")]
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", "1", "-subj", "/CN=naive-rs-aia-root",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", root.with_suffix(".key"), "-out", root.with_suffix(".pem"))
        for path in (issuer, leaf):
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", f"/CN={path.name}", "-keyout", path.with_suffix(".key"), "-out", path.with_suffix(".csr"))
        issuer.with_suffix(".ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        openssl("x509", "-req", "-in", issuer.with_suffix(".csr"), "-CA", root.with_suffix(".pem"),
                "-CAkey", root.with_suffix(".key"), "-CAcreateserial", "-days", "1",
                "-extfile", issuer.with_suffix(".ext"), "-out", issuer.with_suffix(".pem"))
        openssl("x509", "-in", issuer.with_suffix(".pem"), "-outform", "DER", "-out", issuer.with_suffix(".der"))
        issuer_bytes = issuer.with_suffix(".der").read_bytes()

        requests = []
        class Issuer(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path != "/issuer.der":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-cert")
                self.send_header("Content-Length", str(len(issuer_bytes)))
                self.end_headers()
                self.wfile.write(issuer_bytes)

            def log_message(self, *_):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Issuer) as aia, EchoServer(("127.0.0.1", 0), Echo) as origin:
            aia_port = aia.server_address[1]
            leaf.with_suffix(".ext").write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:aia-proxy.test\nauthorityInfoAccess=caIssuers;URI:http://127.0.0.1:{aia_port}/issuer.der\n")
            openssl("x509", "-req", "-in", leaf.with_suffix(".csr"), "-CA", issuer.with_suffix(".pem"),
                    "-CAkey", issuer.with_suffix(".key"), "-CAcreateserial", "-days", "1",
                    "-extfile", leaf.with_suffix(".ext"), "-out", leaf.with_suffix(".pem"))
            for key in temp.glob("*.key"):
                key.chmod(0o600)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            credentials = base64.b64encode(base64.b64encode(b"test:test")).decode()
            config = {"admin": {"disabled": True, "config": {"persist": False}}, "apps": {
                "tls": {"certificates": {"load_files": [{"certificate": str(leaf.with_suffix(".pem")), "key": str(leaf.with_suffix(".key"))}]}},
                "http": {"servers": {"test": {"listen": [f"127.0.0.1:{port}"], "protocols": ["h1", "h2", "h3"],
                    "automatic_https": {"disable": True}, "tls_connection_policies": [{}],
                    "routes": [{"handle": [{"handler": "forward_proxy", "auth_credentials": [credentials],
                        "hide_ip": True, "hide_via": True, "acl": [{"subjects": ["127.0.0.1"], "allow": True}]},
                        {"handler": "static_response", "body": "local AIA fixture"}]}]}}}}}
            path = temp / "caddy.json"
            path.write_text(json.dumps(config))
            workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in (aia, origin)]
            for worker in workers:
                worker.start()
            with (temp / "caddy.log").open("w+") as log:
                proc = subprocess.Popen([str(caddy), "run", "--config", str(path)], cwd=temp,
                    stdout=log, stderr=subprocess.STDOUT,
                    env={**os.environ, "XDG_DATA_HOME": str(temp / "data"), "XDG_CONFIG_HOME": str(temp / "config")})
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        if proc.poll() is not None:
                            raise RuntimeError("Caddy exited before startup")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("Caddy startup timed out")
                            time.sleep(.05)
                    subprocess.run(["cargo", "test", "--locked", "-p", "naive-rs", *(["--target", os.environ["NAIVE_TEST_TARGET"]] if os.environ.get("NAIVE_TEST_TARGET") else []), "--test", "aia", "--", "--ignored", "--nocapture"],
                        cwd=ROOT, check=True, timeout=120, env={**os.environ,
                            "NAIVE_AIA_PROXY_PORT": str(port), "NAIVE_AIA_PORT": str(aia_port),
                            "NAIVE_AIA_ORIGIN_PORT": str(origin.server_address[1]), "NAIVE_AIA_ROOT": root.with_suffix(".pem").read_text(),
                            "NAIVE_AIA_ISSUER": issuer.with_suffix(".pem").read_text(), "NAIVE_AIA_TRACE": str(temp)})
                    assert not requests, f"certificate verification made unexpected AIA requests: {requests}"
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
                    aia.shutdown()
                    origin.shutdown()
                    for worker in workers:
                        worker.join()


if __name__ == "__main__":
    main()
