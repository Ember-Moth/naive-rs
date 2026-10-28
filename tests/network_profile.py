#!/usr/bin/env python3
"""Extract/compare observed TLS and HTTP profiles from the loopback origin.

No browser identity is inferred from a User-Agent string. A comparison only
reports equality of the recorded fields, never whole-browser equivalence.
"""
import argparse
import base64
from collections import Counter
import json
from pathlib import Path


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError("truncated TLS structure")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def number(self, size):
        return int.from_bytes(self.take(size), "big")

    def vector(self, length_bytes):
        return self.take(self.number(length_bytes))


def grease(value):
    return "GREASE" if value & 0x0f0f == 0x0a0a and value >> 8 == value & 255 else f"0x{value:04x}"


def numbers(data):
    if len(data) % 2:
        raise ValueError("odd TLS number vector")
    return [grease(int.from_bytes(data[i:i+2], "big")) for i in range(0, len(data), 2)]


def client_hello(wire):
    records = Reader(wire)
    handshake = bytearray()
    while records.offset < len(records.data):
        kind = records.number(1)
        records.take(2)
        payload = records.vector(2)
        if kind != 22:
            continue
        handshake.extend(payload)
        if len(handshake) >= 4 and len(handshake) >= 4 + int.from_bytes(handshake[1:4], "big"):
            break
    message = Reader(handshake)
    if message.number(1) != 1:
        raise ValueError("first handshake is not ClientHello")
    hello = Reader(message.vector(3))
    result = {"legacy_version": f"0x{hello.number(2):04x}"}
    hello.take(32)  # handshake nonce, intentionally not compared
    result["session_id_length"] = len(hello.vector(1))
    result["cipher_suites"] = numbers(hello.vector(2))
    result["compression_methods"] = list(hello.vector(1))
    extensions = Reader(hello.vector(2))
    if hello.offset != len(hello.data):
        raise ValueError("unexpected trailing ClientHello bytes")
    order = []
    for_grease = []
    while extensions.offset < len(extensions.data):
        kind = extensions.number(2)
        body = extensions.vector(2)
        order.append(grease(kind))
        r = Reader(body)
        if grease(kind) == "GREASE":
            for_grease.append(len(body))
        elif kind == 0:
            names = Reader(r.vector(2))
            result["server_names"] = []
            while names.offset < len(names.data):
                name_type = names.number(1)
                result["server_names"].append([name_type, names.vector(2).decode("ascii")])
        elif kind == 10:
            result["supported_groups"] = numbers(r.vector(2))
        elif kind == 11:
            result["point_formats"] = list(r.vector(1))
        elif kind == 13:
            result["signature_algorithms"] = numbers(r.vector(2))
        elif kind == 16:
            protocols = Reader(r.vector(2))
            result["alpn"] = []
            while protocols.offset < len(protocols.data):
                result["alpn"].append(protocols.vector(1).decode("ascii"))
        elif kind == 27:
            result["certificate_compression"] = numbers(r.vector(1))
        elif kind == 43:
            result["supported_versions"] = numbers(r.vector(1))
        elif kind == 45:
            result["psk_modes"] = list(r.vector(1))
        elif kind == 51:
            shares = Reader(r.vector(2))
            result["key_shares"] = []
            while shares.offset < len(shares.data):
                group = grease(shares.number(2))
                result["key_shares"].append([group, len(shares.vector(2))])
        elif kind in (17513, 17613):
            result[f"alps_{kind}"] = body.hex()
        elif kind == 21:
            result["padding_length"] = len(body)
        elif kind not in (35, 41, 44, 65037):
            # Session tickets, binders, HRR cookies and ECH ciphertext vary.
            # Keep other extension content, including Trust Anchor IDs.
            result.setdefault("extension_payloads", {})[f"0x{kind:04x}"] = body.hex()
    if len(order) != len(set(order)) and any(count > 1 for name, count in Counter(order).items() if name != "GREASE"):
        raise ValueError("duplicate non-GREASE extension")
    result["extensions"] = sorted(order)
    result["grease_extension_lengths"] = sorted(for_grease)
    return result, order


def headers(values):
    normalized = []
    for name, value in values:
        name = name.lower()
        if name in ("host", ":authority"):
            value = "<origin>"
        elif name == "sec-websocket-key":
            if len(base64.b64decode(value, validate=True)) != 16:
                raise ValueError("invalid WebSocket key")
            value = "<16-byte nonce>"
        normalized.append([name, value])
    return normalized


def extract(path, request_path, protocol, label, required_header=None):
    for line in Path(path).read_text().splitlines():
        record = json.loads(line)
        if record.get("kind") != "request" or record.get("path") != request_path or record.get("protocol") != protocol:
            continue
        observed = record.get("http2", {})
        fields = None
        end_stream = None
        if protocol == "HTTP/2.0":
            for block in observed.get("headers") or []:
                if [":path", request_path] in block["fields"]:
                    fields = block["fields"]
                    end_stream = block.get("end_stream")
                    break
        else:
            data = base64.b64decode(record["http_bytes"])
            first, _, _ = data.partition(b"\r\n\r\n")
            rows = first.decode("latin1").split("\r\n")
            if len(rows[0].split()) < 2 or rows[0].split()[1] != request_path:
                continue
            fields = [row.split(":", 1) for row in rows[1:] if ":" in row]
            fields = [[name, value.lstrip()] for name, value in fields]
        if fields is None:
            continue
        if required_header and not any(name.lower() == required_header[0].lower() and value == required_header[1]
                                       for name, value in fields):
            continue
        hello, order = client_hello(base64.b64decode(record["client_bytes"]))
        profile = {"label": label, "protocol": protocol, "path": request_path,
                   "tls": hello, "headers": headers(fields),
                   "observed_extension_order": order,
                   "normalization": ["TLS nonce/session-id/key-share bytes omitted; lengths/groups retained",
                                     "GREASE values normalized; extension order recorded but not compared",
                                     "HTTP authority and WebSocket nonce normalized"],
                   "baseline_status": "not_provided"}
        if protocol == "HTTP/2.0":
            if not observed.get("settings"):
                raise ValueError("HTTP/2 SETTINGS missing from capture")
            profile["http2_settings"] = observed["settings"]
            profile["http2_initial_window_increment"] = observed.get("initial_connection_window_increment")
            profile["http2_headers_end_stream"] = end_stream
        return profile
    raise ValueError("no complete matching request and TLS capture; use a fresh connection")


def compare(baseline, actual):
    required = ["protocol", "path", "tls", "headers"]
    if actual.get("protocol") == "HTTP/2.0":
        required.extend(["http2_settings", "http2_initial_window_increment", "http2_headers_end_stream"])
    differences = {}
    for field in required:
        if field not in baseline or field not in actual or baseline[field] is None or actual[field] is None:
            raise ValueError(f"required comparison field missing: {field}")
        if field in ("protocol", "path", "tls", "headers", "http2_settings") and (not baseline[field] or not actual[field]):
            raise ValueError(f"required comparison field empty: {field}")
        if baseline[field] != actual[field]:
            differences[field] = {"baseline": baseline[field], "actual": actual[field]}
    return {"observed_fields_match": not differences, "differences": differences,
            "baseline_label": baseline.get("label"), "actual_label": actual.get("label"),
            "scope": "Recorded TLS/HTTP fields only; not proof of complete Chrome fingerprint equivalence",
            "not_compared": ["extension permutation distribution", "TLS resumption/0-RTT", "QUIC transport parameters",
                             "timing, packetization, HTTP priorities and browser request-context policy"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    observe = commands.add_parser("extract")
    observe.add_argument("capture", type=Path)
    observe.add_argument("--path", default="/profile")
    observe.add_argument("--protocol", default="HTTP/2.0", choices=["HTTP/2.0", "HTTP/1.1"])
    observe.add_argument("--label", required=True)
    observe.add_argument("--require-header", help="select an explicit request scenario, e.g. sec-fetch-mode=navigate")
    observe.add_argument("--output", type=Path, required=True)
    comparison = commands.add_parser("compare")
    comparison.add_argument("baseline", type=Path)
    comparison.add_argument("actual", type=Path)
    comparison.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "extract":
        required = tuple(args.require_header.split("=", 1)) if args.require_header else None
        if required and len(required) != 2:
            parser.error("--require-header must be name=value")
        result = extract(args.capture, args.path, args.protocol, args.label, required)
    else:
        result = compare(json.loads(args.baseline.read_text()), json.loads(args.actual.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.command == "compare" and not result["observed_fields_match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
