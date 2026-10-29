import json
import unittest

from app.singbox import convert_proxy, generate_singbox_config
from app.generator import generate_subscription_output


def _make_store():
    return {
        "settings": {
            "test_url": "https://www.gstatic.com/generate_204",
            "test_interval": 300,
            "test_tolerance": 50,
        },
        "nodes": [
            {
                "id": "1", "vps_tag": "VPS-A", "name": "", "priority": 10, "enabled": True,
                "uri": "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
                       "?security=reality&pbk=PUBKEY123&sid=abcd&sni=example.com&fp=chrome#VLESS-Reality",
            },
            {
                "id": "2", "vps_tag": "VPS-A", "name": "", "priority": 10, "enabled": True,
                "uri": "hysteria2://secretpass@2.3.4.5:8443?sni=hy.example.com#Hy2",
            },
            {
                "id": "3", "vps_tag": "VPS-B", "name": "", "priority": 10, "enabled": True,
                "uri": "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@3.4.5.6:8388#SS",
            },
            {
                "id": "4", "vps_tag": "VPS-B", "name": "", "priority": 10, "enabled": True,
                "uri": "trojan://trojanpass@4.5.6.7:443?sni=tj.example.com#Trojan",
            },
            {
                "id": "5", "vps_tag": "VPS-C", "name": "", "priority": 10, "enabled": True,
                "uri": "tuic://tuic-uuid-1234:tuicpass@5.6.7.8:443?sni=tuic.example.com#TUIC",
            },
            {
                "id": "6", "vps_tag": "VPS-C", "name": "", "priority": 10, "enabled": True,
                "uri": "socks5://user1:pass1@6.7.8.9:1080#Socks5",
            },
        ],
        "subscriptions": [],
    }


class TestSingboxConvert(unittest.TestCase):
    def test_vless_reality(self):
        ob = convert_proxy({
            "name": "VLESS-Reality", "type": "vless", "server": "1.2.3.4",
            "port": 443, "uuid": "11111111-2222-3333-4444-555555555555",
            "tls": True, "servername": "example.com",
            "client-fingerprint": "chrome", "flow": "xtls-rprx-vision",
            "reality-opts": {"public-key": "PUBKEY123", "short-id": "abcd"},
        })
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["server_port"], 443)
        self.assertEqual(ob["flow"], "xtls-rprx-vision")
        self.assertTrue(ob["tls"]["enabled"])
        self.assertEqual(ob["tls"]["server_name"], "example.com")
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "chrome")
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PUBKEY123")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "abcd")

    def test_hysteria2(self):
        ob = convert_proxy({
            "name": "Hy2", "type": "hysteria2", "server": "2.3.4.5",
            "port": "8443", "password": "secretpass", "sni": "hy.example.com",
        })
        self.assertEqual(ob["type"], "hysteria2")
        self.assertEqual(ob["server_port"], 8443)
        self.assertEqual(ob["tls"]["server_name"], "hy.example.com")

    def test_trojan_tls_always_on(self):
        ob = convert_proxy({
            "name": "T", "type": "trojan", "server": "4.5.6.7",
            "port": 443, "password": "p", "sni": "tj.example.com",
        })
        self.assertTrue(ob["tls"]["enabled"])
        self.assertEqual(ob["tls"]["server_name"], "tj.example.com")

    def test_tuic(self):
        ob = convert_proxy({
            "name": "TUIC", "type": "tuic", "server": "5.6.7.8", "port": 443,
            "uuid": "tuic-uuid-1234", "password": "tuicpass",
            "sni": "tuic.example.com", "congestion-controller": "bbr",
            "udp-relay-mode": "native",
        })
        self.assertEqual(ob["type"], "tuic")
        self.assertEqual(ob["congestion_control"], "bbr")
        self.assertEqual(ob["udp_relay_mode"], "native")
        self.assertIn("h3", ob["tls"].get("alpn", ["h3"]))

    def test_socks5_auth(self):
        ob = convert_proxy({
            "name": "S5", "type": "socks5", "server": "6.7.8.9", "port": 1080,
            "username": "user1", "password": "pass1",
        })
        self.assertEqual(ob["type"], "socks")
        self.assertEqual(ob["version"], "5")
        self.assertEqual(ob["username"], "user1")

    def test_ss(self):
        ob = convert_proxy({
            "name": "SS", "type": "ss", "server": "3.4.5.6", "port": 8388,
            "cipher": "aes-256-gcm", "password": "password",
        })
        self.assertEqual(ob["type"], "shadowsocks")
        self.assertEqual(ob["method"], "aes-256-gcm")

    def test_vmess_ws(self):
        ob = convert_proxy({
            "name": "VM", "type": "vmess", "server": "7.8.9.0", "port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "alterId": 0,
            "cipher": "auto", "tls": True, "network": "ws",
            "servername": "vm.example.com",
            "ws-opts": {"path": "/v2", "headers": {"Host": "vm.example.com"}},
        })
        self.assertEqual(ob["type"], "vmess")
        self.assertEqual(ob["alter_id"], 0)
        self.assertEqual(ob["transport"]["type"], "ws")
        self.assertEqual(ob["transport"]["path"], "/v2")

    def test_unknown_type_skipped(self):
        self.assertIsNone(convert_proxy({"name": "X", "type": "wireguard",
                                         "server": "1.1.1.1", "port": 1234}))

    def test_missing_server_skipped(self):
        self.assertIsNone(convert_proxy({"name": "X", "type": "ss",
                                         "server": "", "port": 8388,
                                         "cipher": "aes-256-gcm", "password": "p"}))


class TestSingboxConfig(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(generate_singbox_config(_make_store()))

    def test_top_level_sections(self):
        for key in ("log", "dns", "inbounds", "outbounds", "route"):
            self.assertIn(key, self.cfg, f"missing section: {key}")

    def test_all_nodes_converted(self):
        types = {o["type"] for o in self.cfg["outbounds"]}
        for t in ("vless", "hysteria2", "shadowsocks", "trojan", "tuic", "socks"):
            self.assertIn(t, types, f"missing outbound type: {t}")

    def test_outbound_required_fields(self):
        for o in self.cfg["outbounds"]:
            if o["type"] in ("selector", "urltest", "direct", "block", "dns"):
                continue
            self.assertTrue(o.get("tag"), "outbound missing tag")
            self.assertTrue(o.get("server"), "outbound missing server")
            self.assertTrue(o.get("server_port"), "outbound missing server_port")

    def test_selector_and_urltest(self):
        by_tag = {o["tag"]: o for o in self.cfg["outbounds"]}
        selector = by_tag["🚀 节点选择"]
        self.assertEqual(selector["type"], "selector")
        self.assertIn("direct", selector["outbounds"])
        # 嵌套组引用不断
        self.assertIn("♻️ 自动选择", selector["outbounds"])
        self.assertIn("🛡️ 故障转移", selector["outbounds"])
        self.assertEqual(selector["default"], "🌐 [VPS-A] VLESS-Reality")
        urltest = by_tag["♻️ 自动选择"]
        self.assertEqual(urltest["type"], "urltest")
        self.assertEqual(urltest["interval"], "300s")
        self.assertEqual(urltest["tolerance"], 50)
        self.assertEqual(len(urltest["outbounds"]), 6)

    def test_all_mihomo_groups_present(self):
        by_tag = {o["tag"]: o for o in self.cfg["outbounds"]}
        expected = {
            "🚀 节点选择": "selector",
            "♻️ 自动选择": "urltest",
            "🛡️ 故障转移": "selector",  # sing-box 无 fallback 类型，转手动选择
            "🤖 AI 专线": "selector",
            "⚡ AI 自动优选": "urltest",
            "📹 YouTube": "selector",
            "📲 Telegram": "selector",
            "🎬 流媒体服务": "selector",
            "🍎 苹果与微软": "selector",
            "🎯 全球直连": "selector",
            "🛑 广告拦截": "selector",
            "🐟 漏网之鱼": "selector",
        }
        for tag, typ in expected.items():
            self.assertIn(tag, by_tag, f"missing group: {tag}")
            self.assertEqual(by_tag[tag]["type"], typ, f"wrong type: {tag}")
        # DIRECT/REJECT 映射
        self.assertEqual(by_tag["🛑 广告拦截"]["outbounds"], ["block", "direct"])
        self.assertEqual(by_tag["🎯 全球直连"]["outbounds"],
                         ["direct", "🚀 节点选择"])

    def test_no_dangling_group_refs(self):
        tags = {o["tag"] for o in self.cfg["outbounds"]}
        for o in self.cfg["outbounds"]:
            if o["type"] in ("selector", "urltest"):
                for m in o["outbounds"]:
                    self.assertIn(m, tags, f"dangling ref {m} in {o['tag']}")

    def test_ai_domain_rule(self):
        rules = self.cfg["route"]["rules"]
        ai_rule = next((r for r in rules if r.get("outbound") == "🤖 AI 专线"), None)
        self.assertIsNotNone(ai_rule)
        self.assertIn("openai.com", ai_rule["domain_suffix"])
        self.assertIn("claude.ai", ai_rule["domain_suffix"])
        # 劫持与嗅探仍在 AI 规则之前
        self.assertEqual(rules[0], {"protocol": "dns", "action": "hijack-dns"})
        self.assertEqual(rules[1].get("action"), "sniff")

    def test_route_and_dns(self):
        rules = self.cfg["route"]["rules"]
        self.assertTrue(any(r.get("protocol") == "dns" for r in rules))
        self.assertTrue(any("geosite-cn" in str(r.get("rule_set", "")) for r in rules))
        self.assertEqual(self.cfg["route"]["final"], "🚀 节点选择")
        inbounds = {i["type"] for i in self.cfg["inbounds"]}
        self.assertIn("tun", inbounds)
        self.assertIn("mixed", inbounds)

    def test_dns_new_server_format(self):
        # sing-box 1.12+ 新 DNS 格式：必须带 type，不许用老 address 写法
        # （老格式 1.12 弃用、1.14 移除，实测 iOS 端直接报错拒绝导入）
        for s in self.cfg["dns"]["servers"]:
            self.assertIn("type", s)
            self.assertNotIn("address", s)

    def test_tun_no_deprecated_stack(self):
        # stack 选项 1.15 弃用、1.17 移除，缺省即新栈
        tun = next(i for i in self.cfg["inbounds"] if i["type"] == "tun")
        self.assertNotIn("stack", tun)

    def test_inbounds_no_legacy_fields(self):
        # 入站级 sniff/domain_strategy 等 1.11 弃用、1.13 移除；
        # inet4_address 1.10 起合并为 address
        legacy = {"sniff", "sniff_override_destination", "sniff_timeout",
                  "domain_strategy", "inet4_address", "inet6_address"}
        for i in self.cfg["inbounds"]:
            self.assertTrue(legacy.isdisjoint(i.keys()), f"legacy field in {i['type']}")

    def test_no_dns_outbound(self):
        # 1.13+ 已移除 dns 出站；DNS 查询改走 hijack-dns 路由动作
        self.assertFalse(any(o.get("type") == "dns" for o in self.cfg["outbounds"]))

    def test_dns_hijack_first_then_sniff(self):
        rules = self.cfg["route"]["rules"]
        self.assertEqual(rules[0], {"protocol": "dns", "action": "hijack-dns"})
        self.assertEqual(rules[1].get("action"), "sniff")

    def test_direct_dns_no_detour(self):
        # direct-dns 不写 detour：无 detour 即直连；写 detour 到空 direct
        # 出站在 1.14+ 启动时会被拒绝
        servers = {s["tag"]: s for s in self.cfg["dns"]["servers"]}
        self.assertNotIn("detour", servers["direct-dns"])
        self.assertEqual(servers["proxy-dns"]["detour"], "🚀 节点选择")

    def test_direct_outbound_not_empty(self):
        direct = next(o for o in self.cfg["outbounds"] if o["tag"] == "direct")
        self.assertEqual(direct["domain_resolver"], {"server": "direct-dns"})
        self.assertEqual(self.cfg["route"]["default_domain_resolver"],
                         {"server": "direct-dns"})

    def test_no_internal_fingerprint_leak(self):
        # 内部去重用的顶层 fingerprint 字段不得输出；
        # tls.utls.fingerprint 是 sing-box 正经字段，不在此限
        for o in self.cfg["outbounds"]:
            self.assertNotIn("fingerprint", o)

    def test_empty_store(self):
        store = {"settings": {}, "nodes": [], "subscriptions": []}
        cfg = json.loads(generate_singbox_config(store))
        by_tag = {o["tag"]: o for o in cfg["outbounds"]}
        self.assertEqual(by_tag["🚀 节点选择"]["default"], "direct")
        # 空节点时 urltest 组无意义被跳过，引用它的组不能悬空
        tags = set(by_tag)
        for o in cfg["outbounds"]:
            if o["type"] in ("selector", "urltest"):
                for m in o["outbounds"]:
                    self.assertIn(m, tags, f"dangling ref {m} in {o['tag']}")

    def test_wired_into_generator(self):
        out = generate_subscription_output(_make_store(), target="singbox")
        cfg = json.loads(out)
        self.assertIn("outbounds", cfg)


if __name__ == "__main__":
    unittest.main()
