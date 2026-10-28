#!/usr/bin/env python3
"""Reproducible loopback benchmarks. Throughput is one-way payload echoed back.

Use --variant name=/absolute/benchmark-binary repeatedly for interleaved A/B runs.
All variants use the same pinned Caddy, origin, TLS certificate, and Rust workload.
Raw JSON contains per-run results; do not treat a single sample as a speed claim.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import socket
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
CASES=[
    {"name":"bulk-1-64k","mode":"bulk","connections":1,"clients":1,"block":65536,"bytes":134217728},
    {"name":"bulk-16-64k","mode":"bulk","connections":16,"clients":1,"block":65536,"bytes":134217728},
    {"name":"bulk-128-64k","mode":"bulk","connections":128,"clients":4,"block":65536,"bytes":134217728},
    {"name":"small-16-1k","mode":"small-writes","connections":16,"clients":1,"block":1024,"bytes":33554432},
    {"name":"ping-1-64b","mode":"latency","connections":1,"clients":1,"block":64,"iterations":1000},
    {"name":"ping-16-64b","mode":"latency","connections":16,"clients":1,"block":64,"iterations":500},
    {"name":"idle-128","mode":"idle","connections":128,"clients":4},
    {"name":"churn-100","mode":"churn","connections":1,"clients":1,"iterations":100},
]
EXTRA_CASES=[
    {"name":"churn-parallel-32","mode":"churn-parallel","connections":1,"clients":1,"iterations":320,"parallel":32},
    {"name":"idle-512","mode":"idle","connections":512,"clients":8},
    {"name":"ping-128-64b","mode":"latency","connections":128,"clients":4,"block":64,"iterations":250},
    {"name":"soak-60","mode":"soak","connections":32,"clients":4,"block":4096,"seconds":60},
]

def stop(proc):
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", action="append", required=True)
    parser.add_argument("--caddy",type=Path,default=ROOT/"target/test-tools/caddy")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--repeats",type=int,default=3)
    parser.add_argument("--protocols",default="https,quic")
    parser.add_argument("--cases",default="")
    parser.add_argument("--io-workers",type=int,default=1)
    parser.add_argument("--variant-io-workers",action="append",default=[])
    parser.add_argument("--bytes-scale",type=int,default=1)
    parser.add_argument("--iterations-scale",type=int,default=1)
    args=parser.parse_args()
    variants={name:Path(binary).resolve() for name,binary in (v.split("=",1) for v in args.variant)}
    cases=CASES if not args.cases else [c for c in CASES+EXTRA_CASES if c["name"] in args.cases.split(",")]
    if not cases: parser.error("no matching benchmark cases")
    if args.bytes_scale < 1 or args.iterations_scale < 1: parser.error("scales must be positive")
    cases=[{**c, **({"bytes":c["bytes"]*args.bytes_scale} if "bytes" in c else {}),
                 **({"iterations":c["iterations"]*args.iterations_scale} if "iterations" in c else {})} for c in cases]
    worker_counts={name:int(width) for name,width in (v.split("=",1) for v in args.variant_io_workers)}
    out={"host":platform.platform(),"machine":platform.machine(),"date":time.strftime("%Y-%m-%dT%H:%M:%S%z"),
         "note":"loopback; four Rust executor workers; Caddy GOMAXPROCS=4; echo GOMAXPROCS=2; one-way payload throughput",
         "variants":{k:str(v) for k,v in variants.items()},
         "variant_sha256":{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in variants.items()},
         "proxy_host":"127.0.0.1", "bytes_scale":args.bytes_scale,
         "iterations_scale":args.iterations_scale,"repeats":args.repeats,"runs":[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="naive-perf-") as directory:
        directory=Path(directory)
        cert,key=directory/"cert.pem",directory/"key.pem"
        subprocess.run(["openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1",
                        "-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout",str(key),"-out",str(cert)],check=True,capture_output=True)
        key.chmod(0o600)
        with socket.socket() as s:
            s.bind(("127.0.0.1",0)); port=s.getsockname()[1]
        config={"admin":{"disabled":True,"config":{"persist":False}},"logging":{"logs":{"default":{"level":"ERROR"}}},
                "apps":{"tls":{"certificates":{"load_files":[{"certificate":str(cert),"key":str(key)}]}},
                        "http":{"servers":{"test":{"listen":[f"127.0.0.1:{port}"],"protocols":["h1","h2","h3"],
                           "automatic_https":{"disable":True},"tls_connection_policies":[{"default_sni":"localhost"}],
                           "routes":[{"handle":[{"handler":"forward_proxy","auth_credentials":[base64.b64encode(base64.b64encode(b"test:test")).decode()],
                              "hide_ip":True,"hide_via":True,"acl":[{"subjects":["127.0.0.1"],"allow":True}]},
                              {"handler":"static_response","body":"<!doctype html><title>Local benchmark</title>"}]}]}}}}}
        (directory/"caddy.json").write_text(json.dumps(config))
        origin=subprocess.Popen([str(ROOT/"target/perf/echo")],stdout=subprocess.PIPE,text=True,env={**os.environ,"GOMAXPROCS":"2"})
        origin_port=origin.stdout.readline().strip()
        with (directory/"server.log").open("w+") as log:
            server=subprocess.Popen([str(args.caddy.resolve()),"run","--config",str(directory/"caddy.json")],
                                    stdout=log,stderr=subprocess.STDOUT,env={**os.environ,"GOMAXPROCS":"4",
                                    "XDG_DATA_HOME":str(directory/"data"),"XDG_CONFIG_HOME":str(directory/"config")})
            try:
                deadline=time.monotonic()+15
                while True:
                    if server.poll() is not None: raise RuntimeError("Caddy exited")
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.2): break
                    except OSError:
                        if time.monotonic()>deadline: raise RuntimeError("Caddy did not start")
                        time.sleep(.05)
                rng=random.Random(42)
                for protocol in args.protocols.split(","):
                    for case in cases:
                        for repeat in range(args.repeats):
                            names=list(variants); rng.shuffle(names)
                            for name in names:
                                command=[str(variants[name])]
                                for k,v in case.items():
                                    if k!="name": command.extend(["--"+k,str(v)])
                                workers=worker_counts.get(name,args.io_workers)
                                command.extend(["--io-workers",str(workers)])
                                result=subprocess.run(command,capture_output=True,text=True,timeout=100,
                                    env={**os.environ,"NAIVE_BENCH_PROXY":f"{protocol}://test:test@127.0.0.1:{port}",
                                         "NAIVE_BENCH_CA":str(cert),"NAIVE_BENCH_ORIGIN_PORT":origin_port})
                                if result.returncode:
                                    log.flush()
                                    server_log=args.output.with_suffix(f".{name}-{protocol}-{case['name']}.server.log")
                                    shutil.copyfile(directory/"server.log",server_log)
                                    diagnostic={"caddy_returncode":server.poll(),"origin_returncode":origin.poll()}
                                    try:
                                        with socket.create_connection(("127.0.0.1",int(origin_port)),timeout=.2):
                                            diagnostic["origin_connect"]="ok"
                                    except OSError as error:
                                        diagnostic["origin_connect"]={"errno":error.errno,"error":str(error)}
                                    state=subprocess.run(["netstat","-an","-p","tcp"],capture_output=True,text=True)
                                    diagnostic["origin_time_wait"]=sum("TIME_WAIT" in line and f".{origin_port}" in line for line in state.stdout.splitlines())
                                    args.output.with_suffix(".failure.json").write_text(json.dumps(diagnostic,indent=2)+"\n")
                                    raise RuntimeError(f"{name}/{protocol}/{case['name']} (Caddy={server.poll()}, origin={origin.poll()}, server log={server_log}): {result.stderr}")
                                record=json.loads(result.stdout.strip().splitlines()[-1])
                                record.update(variant=name,protocol=protocol,case=case["name"],repeat=repeat,io_workers=workers,workload=case)
                                out["runs"].append(record)
                                args.output.write_text(json.dumps(out,indent=2)+"\n")
                                print(name,protocol,case["name"],"MiB/s",round(record.get("payload_mib_per_second",0),2),
                                      "cpu",round(record["cpu_seconds"],4),"p99_us",round(record.get("p99_us",0),1),flush=True)
            finally:
                stop(server); stop(origin)

if __name__=="__main__": main()
