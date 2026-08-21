import importlib.util
import os
import struct
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "iotad_endpoint", os.path.join(ROOT, "endpoint", "server.py"))
endpoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(endpoint)


def query(name):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return (b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) +
            labels + struct.pack("!HH", 1, 1))


class EndpointTests(unittest.TestCase):
    def test_dns_a_response_uses_endpoint_ip(self):
        response = endpoint.dns_response(query("beacon.example"))
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)
        self.assertTrue(response.endswith(b"\xc0\xa8\x07\x14"))

    def test_invalid_and_local_are_nxdomain(self):
        for name in ("missing.invalid", "plc.operations.local"):
            with self.subTest(name=name):
                response = endpoint.dns_response(query(name))
                flags = struct.unpack("!H", response[2:4])[0]
                answers = struct.unpack("!H", response[6:8])[0]
                self.assertEqual(flags & 0xF, 3)
                self.assertEqual(answers, 0)

    def test_malformed_dns_is_ignored(self):
        self.assertEqual(endpoint.dns_response(b"short"), b"")


if __name__ == "__main__":
    unittest.main()
