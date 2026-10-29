import unittest

from app.fingerprint import compute_fingerprint
from app.parser import parse_single_line


class TestFingerprint(unittest.TestCase):
    def test_same_line_different_names(self):
        base = "trojan://trojanpass@trojan.example.com:443?sni=trojan.example.com"
        p1 = parse_single_line(base + "#名字A", vps_tag="", prepend_vps_tag=False, auto_emoji=False)
        p2 = parse_single_line(base + "#名字B", vps_tag="", prepend_vps_tag=False, auto_emoji=False)
        self.assertIsNotNone(p1)
        self.assertIsNotNone(p2)
        # 改名不影响指纹
        self.assertEqual(p1["fingerprint"], p2["fingerprint"])
        self.assertNotEqual(p1["name"], p2["name"])

    def test_different_port_different_fingerprint(self):
        p1 = parse_single_line("trojan://pw@h.example.com:443", auto_emoji=False, prepend_vps_tag=False)
        p2 = parse_single_line("trojan://pw@h.example.com:8443", auto_emoji=False, prepend_vps_tag=False)
        self.assertNotEqual(p1["fingerprint"], p2["fingerprint"])

    def test_server_case_insensitive(self):
        p1 = parse_single_line("trojan://pw@H.EXAMPLE.COM:443", auto_emoji=False, prepend_vps_tag=False)
        p2 = parse_single_line("trojan://pw@h.example.com:443", auto_emoji=False, prepend_vps_tag=False)
        self.assertEqual(p1["fingerprint"], p2["fingerprint"])

    def test_fingerprint_is_sha256_hex(self):
        p = parse_single_line("trojan://pw@h.example.com:443", auto_emoji=False, prepend_vps_tag=False)
        fp = p["fingerprint"]
        self.assertEqual(len(fp), 64)
        int(fp, 16)  # 有效十六进制


if __name__ == "__main__":
    unittest.main()
