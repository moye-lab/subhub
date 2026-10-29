import base64
import json
import unittest

from app.parser import parse_single_line, decorate_name


VLESS_REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome"
    "&pbk=PUBLICKEY123&sid=abcd&type=tcp&flow=xtls-rprx-vision#%E7%BE%8E%E5%9B%BDVPS"
)
HY2 = "hysteria2://secretpass@hy2.example.com:8443?sni=hy2.example.com&insecure=1#%E9%A6%99%E6%B8%AFHy2"
TUIC = "tuic://uuid123:pass456@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr#%E6%97%A5%E6%9C%ACTUIC"
TROJAN = "trojan://trojanpass@trojan.example.com:443?sni=trojan.example.com#%E6%96%B0%E5%8A%A0%E5%9D%A1"
SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8388#SS%E8%8A%82%E7%82%B9"
SOCKS5 = "socks5://user:pass@socks.example.com:1080#SOCKS5"


def _vmess_uri():
    obj = {
        "v": "2", "ps": "VMess测试", "add": "vmess.example.com", "port": "443",
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aid": "0",
        "net": "ws", "type": "none", "host": "vmess.example.com",
        "path": "/ws", "tls": "tls",
    }
    b64 = base64.b64encode(json.dumps(obj).encode()).decode()
    return "vmess://" + b64


class TestParser(unittest.TestCase):
    def test_vless_reality(self):
        p = parse_single_line(VLESS_REALITY, vps_tag="VPS-A")
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "vless")
        self.assertEqual(p["server"], "example.com")
        self.assertEqual(p["port"], 443)
        self.assertTrue(p["tls"])
        self.assertEqual(p["flow"], "xtls-rprx-vision")
        self.assertEqual(p["reality-opts"]["public-key"], "PUBLICKEY123")
        self.assertEqual(p["servername"], "www.microsoft.com")
        self.assertIn("[VPS-A]", p["name"])
        self.assertIn("🇺🇸", p["name"])
        self.assertIn("fingerprint", p)

    def test_hysteria2(self):
        p = parse_single_line(HY2)
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "hysteria2")
        self.assertEqual(p["password"], "secretpass")
        self.assertTrue(p["skip-cert-verify"])
        self.assertIn("🇭🇰", p["name"])

    def test_tuic(self):
        p = parse_single_line(TUIC)
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "tuic")
        self.assertEqual(p["uuid"], "uuid123")
        self.assertIn("🇯🇵", p["name"])

    def test_trojan(self):
        p = parse_single_line(TROJAN)
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "trojan")
        self.assertIn("🇸🇬", p["name"])

    def test_ss(self):
        p = parse_single_line(SS)
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "ss")
        self.assertEqual(p["cipher"], "aes-256-gcm")
        self.assertEqual(p["password"], "password")

    def test_vmess(self):
        p = parse_single_line(_vmess_uri())
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "vmess")
        self.assertTrue(p["tls"])
        self.assertEqual(p["ws-opts"]["path"], "/ws")

    def test_socks5(self):
        p = parse_single_line(SOCKS5)
        self.assertIsNotNone(p)
        self.assertEqual(p["type"], "socks5")
        self.assertEqual(p["username"], "user")

    def test_invalid_and_comment(self):
        self.assertIsNone(parse_single_line(""))
        self.assertIsNone(parse_single_line("# 注释行"))
        self.assertIsNone(parse_single_line("not-a-uri"))
        self.assertIsNone(parse_single_line("http://example.com/x"))

    def test_decorate_name_idempotent(self):
        once = decorate_name("美国VPS", vps_tag="VPS-A")
        twice = decorate_name(once, vps_tag="VPS-A")
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main()
