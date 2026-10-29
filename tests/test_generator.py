import base64
import unittest

import yaml
from urllib.parse import unquote

from app.generator import (
    collect_all_proxies,
    build_proxy_groups,
    generate_subscription_output,
)

US_VLESS = (
    "vless://11111111-2222-3333-4444-555555555555@us.example.com:443"
    "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome"
    "&pbk=PUBLICKEY123&sid=abcd&type=tcp&flow=xtls-rprx-vision#%E7%BE%8E%E5%9B%BD%E6%B4%9B%E6%9D%89%E7%9F%B6"
)
HK_HY2 = "hysteria2://secretpass@hk.example.com:8443?sni=hk.example.com&insecure=1#%E9%A6%99%E6%B8%AF"


def _settings():
    return {
        "sub_token": "testtoken",
        "sub_filename": "SubHub-Mihomo",
        "test_url": "https://www.gstatic.com/generate_204",
        "test_interval": 300,
        "test_tolerance": 50,
        "auto_emoji": True,
        "prepend_vps_tag": True,
        "udp_default": True,
    }


def _store(nodes, subscriptions=None):
    return {"settings": _settings(), "nodes": nodes, "subscriptions": subscriptions or []}


class TestGenerator(unittest.TestCase):
    def test_collect_and_name_dedup(self):
        store = _store(
            [
                {"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5},
                # 同一条线路再导一次（换备注名）-> 指纹去重后只剩 1 个
                {"id": "a2", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS.replace("%E7%BE%8E%E5%9B%BD", "%E7%BE%8E%E5%9B%BD2"), "enabled": True, "priority": 5},
                {"id": "b1", "vps_tag": "VPS-B", "name": "", "uri": HK_HY2, "enabled": True, "priority": 10},
                {"id": "c1", "vps_tag": "VPS-C", "name": "", "uri": HK_HY2, "enabled": False, "priority": 1},
            ]
        )
        proxies, raw_uris = collect_all_proxies(store)
        # a1/a2 同指纹去重，c1 被禁用 -> 剩 2 个
        self.assertEqual(len(proxies), 2)
        names = [p["name"] for p in proxies]
        self.assertEqual(len(set(names)), 2)

    def test_region_groups_pruned(self):
        store = _store(
            [
                {"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5},
                {"id": "b1", "vps_tag": "VPS-B", "name": "", "uri": HK_HY2, "enabled": True, "priority": 10},
            ]
        )
        proxies, _ = collect_all_proxies(store)
        groups = build_proxy_groups(proxies, _settings())
        group_names = [g["name"] for g in groups]
        # 有美/港节点 -> 对应地区组存在；没有台湾节点 -> 台湾组被裁剪
        self.assertIn("🇺🇸 美国节点", group_names)
        self.assertIn("🇭🇰 香港节点", group_names)
        self.assertNotIn("🇹🇼 台湾节点", group_names)
        # 父级策略组里也没有对台湾组的引用
        for g in groups:
            for ref in g.get("proxies", []):
                self.assertNotIn("台湾", ref)

    def test_ai_group_excludes_hk(self):
        store = _store(
            [
                {"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5},
                {"id": "b1", "vps_tag": "VPS-B", "name": "", "uri": HK_HY2, "enabled": True, "priority": 10},
            ]
        )
        proxies, _ = collect_all_proxies(store)
        groups = build_proxy_groups(proxies, _settings())
        ai = next(g for g in groups if g["name"] == "⚡ AI 自动优选")
        # 香港节点被剔除，美国节点保留
        self.assertTrue(any("🇺🇸" in n for n in ai["proxies"]))
        self.assertFalse(any("🇭🇰" in n for n in ai["proxies"]))
        self.assertFalse(any("香港" in n for n in ai["proxies"]))

    def test_fallback_respects_priority(self):
        store = _store(
            [
                {"id": "b1", "vps_tag": "VPS-B", "name": "", "uri": HK_HY2, "enabled": True, "priority": 10},
                {"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5},
            ]
        )
        proxies, _ = collect_all_proxies(store)
        groups = build_proxy_groups(proxies, _settings())
        fb = next(g for g in groups if g["name"] == "🛡️ 故障转移")
        # 优先级 5 的美国节点排在优先级 10 的香港节点前面
        us_idx = next(i for i, n in enumerate(fb["proxies"]) if "🇺🇸" in n)
        hk_idx = next(i for i, n in enumerate(fb["proxies"]) if "🇭🇰" in n)
        self.assertLess(us_idx, hk_idx)

    def test_mihomo_output_is_valid_yaml(self):
        store = _store(
            [{"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5}]
        )
        out = generate_subscription_output(store, target="mihomo")
        cfg = yaml.safe_load(out)
        self.assertIn("proxies", cfg)
        self.assertIn("proxy-groups", cfg)
        self.assertIn("rules", cfg)
        self.assertIn("rule-providers", cfg)
        self.assertEqual(len(cfg["proxies"]), 1)
        # 模板里的 URL 必须是干净的纯 URL，不能带 markdown 残留
        for rp in cfg["rule-providers"].values():
            self.assertNotIn("](", rp["url"])
            self.assertTrue(rp["url"].startswith("https://"))

    def test_fingerprint_not_leaked_to_output(self):
        store = _store(
            [{"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5}]
        )
        cfg = yaml.safe_load(generate_subscription_output(store, target="mihomo"))
        self.assertFalse(any("fingerprint" in p for p in cfg["proxies"]))
        p2 = yaml.safe_load(generate_subscription_output(store, target="proxies"))
        self.assertFalse(any("fingerprint" in p for p in p2["proxies"]))

    def test_base64_roundtrip(self):
        store = _store(
            [{"id": "a1", "vps_tag": "VPS-A", "name": "", "uri": US_VLESS, "enabled": True, "priority": 5}]
        )
        out = generate_subscription_output(store, target="base64")
        decoded = base64.b64decode(out).decode("utf-8").strip()
        # 连接参数保持原样，仅 #fragment 同步为最终修饰名
        self.assertTrue(decoded.startswith(US_VLESS.split("#", 1)[0] + "#"))
        frag = unquote(decoded.split("#", 1)[1])
        self.assertEqual(frag, "🇺🇸 [VPS-A] 美国洛杉矶")


if __name__ == "__main__":
    unittest.main()
