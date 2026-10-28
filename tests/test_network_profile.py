import json
import tempfile
import unittest
from pathlib import Path

from network_profile import client_hello, compare, extract


def vector(data, size=2):
    return len(data).to_bytes(size, "big") + data


def hello(random_byte=1, reverse=False, alpn=b"h2"):
    extensions = [
        (0, vector(b"\0" + vector(b"localhost"))),
        (10, vector(b"\x0a\x0a\x00\x1d")),
        (13, vector(b"\x04\x03\x08\x04")),
        (16, vector(vector(alpn, 1) + vector(b"http/1.1", 1))),
        (43, vector(b"\x0a\x0a\x03\x04\x03\x03", 1)),
        (51, vector(b"\x00\x1d" + vector(bytes([random_byte]) * 32))),
        (0x1a1a, b""),
    ]
    if reverse:
        extensions.reverse()
    extension_bytes = b"".join(kind.to_bytes(2, "big") + vector(body) for kind, body in extensions)
    body = b"\x03\x03" + bytes([random_byte]) * 32 + vector(bytes([random_byte]) * 32, 1)
    body += vector(b"\x0a\x0a\x13\x01\x13\x02") + vector(b"\0", 1) + vector(extension_bytes)
    message = b"\x01" + vector(body, 3)
    return b"\x16\x03\x01" + vector(message)


class Profiles(unittest.TestCase):
    def test_random_material_and_permutation_are_not_fixed_identity(self):
        first, order = client_hello(hello())
        second, changed_order = client_hello(hello(2, True))
        self.assertEqual(first, second)
        self.assertNotEqual(order, changed_order)
        self.assertEqual(first["alpn"], ["h2", "http/1.1"])
        self.assertEqual(first["key_shares"], [["0x001d", 32]])

    def test_real_protocol_difference_is_retained(self):
        first, _ = client_hello(hello())
        second, _ = client_hello(hello(alpn=b"h3"))
        base = {"protocol": "HTTP/2.0", "path": "/profile", "tls": first,
                "headers": [[":method", "GET"]], "http2_settings": [[2, 0]],
                "http2_initial_window_increment": 1000, "http2_headers_end_stream": True}
        actual = {**base, "tls": second}
        result = compare(base, actual)
        self.assertFalse(result["observed_fields_match"])
        self.assertIn("tls", result["differences"])

    def test_truncated_and_empty_inputs_are_not_matches(self):
        with self.assertRaises(ValueError):
            client_hello(hello()[:-1])
        with self.assertRaises(ValueError):
            compare({}, {})
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "capture.jsonl"
            source.write_text(json.dumps({"kind": "tls"}) + "\n")
            with self.assertRaises(ValueError):
                extract(source, "/profile", "HTTP/2.0", "missing")


if __name__ == "__main__":
    unittest.main()
