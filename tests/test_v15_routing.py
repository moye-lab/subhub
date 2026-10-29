"""v1.5 自定义分流组与分流规则测试：双引擎同步、目标安全回退、
批量删除、CRUD 校验。"""
import json
import tempfile
import unittest

import yaml
from fastapi.testclient import TestClient

import app.config as config_mod

VLESS_A = (
    "vless://550e8400-e29b-41d4-a716-446655440000"
    "@127.0.0.1:1?encryption=none&security=none#nodeA"
)
VLESS_B = (
    "vless://660e8400-e29b-41d4-a716-446655440001"
    "@127.0.0.1:2?encryption=none&security=none#nodeB"
)


class TestV15Routing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = {}
        for attr in ("DATA_DIR", "STORE_FILE", "TEMPLATE_FILE"):
            self._saved[(config_mod, attr)] = getattr(config_mod, attr)
        import app.storage as storage_mod
        self._storage_mod = storage_mod
        for attr in ("STORE_FILE", "TEMPLATE_FILE"):
            self._saved[(storage_mod, attr)] = getattr(storage_mod, attr)
        config_mod.DATA_DIR = config_mod.Path(self.tmp.name)
        config_mod.STORE_FILE = config_mod.DATA_DIR / "store.json"
        config_mod.TEMPLATE_FILE = config_mod.DATA_DIR / "base_template.yaml"
        storage_mod.STORE_FILE = config_mod.STORE_FILE
        storage_mod.TEMPLATE_FILE = config_mod.TEMPLATE_FILE
        import app.main as main_mod
        self._main_mod = main_mod
        main_mod._login_attempts.clear()
        self.c = TestClient(main_mod.app)
        self.env_pw = config_mod.ADMIN_PASSWORD

    def tearDown(self):
        self._main_mod._login_attempts.clear()
        for (mod, attr), val in self._saved.items():
            setattr(mod, attr, val)
        self.tmp.cleanup()

    def _auth(self):
        return {"X-Admin-Token": self.env_pw}

    def _token(self):
        r = self.c.post("/api/login", json={"password": self.env_pw})
        self.assertEqual(r.status_code, 200)
        st = self.c.get(
            "/api/state", headers={"X-Admin-Token": r.json()["token"]}
        ).json()
        return st["settings"]["sub_token"]

    def _add_node(self, uri, vps_tag="VPS-A"):
        r = self.c.post(
            "/api/nodes",
            json={"vps_tag": vps_tag, "raw_input": uri,
                  "priority": 10, "enabled": True},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 200)
        st = self.c.get("/api/state", headers=self._auth()).json()
        return st["nodes"][-1]["id"]

    def _mihomo_cfg(self, token):
        r = self.c.get(f"/sub/{token}?target=mihomo")
        self.assertEqual(r.status_code, 200)
        return yaml.safe_load(r.text)

    def _singbox_cfg(self, token):
        r = self.c.get(f"/sub/{token}?target=singbox")
        self.assertEqual(r.status_code, 200)
        return json.loads(r.text)

    def test_custom_group_dual_engine(self):
        self._add_node(VLESS_A)
        r = self.c.post(
            "/api/groups",
            json={"name": "🎮 游戏专线", "type": "select", "vps_filter": "VPS-A"},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 200)
        token = self._token()
        # Mihomo 引擎
        cfg = self._mihomo_cfg(token)
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        self.assertIn("🎮 游戏专线", groups)
        g = groups["🎮 游戏专线"]
        self.assertEqual(g["type"], "select")
        self.assertTrue(any("[VPS-A]" in m for m in g["proxies"]))
        # 自定义组插在核心组之后、地区组之前：主选择组仍在首位
        self.assertEqual(cfg["proxy-groups"][0]["name"], "🚀 节点选择")
        # sing-box 引擎
        cfg = self._singbox_cfg(token)
        obs = {o["tag"]: o for o in cfg["outbounds"]}
        self.assertIn("🎮 游戏专线", obs)
        self.assertEqual(obs["🎮 游戏专线"]["type"], "selector")
        self.assertTrue(len(obs["🎮 游戏专线"]["outbounds"]) >= 1)

    def test_custom_rule_dual_engine(self):
        self._add_node(VLESS_A)
        self.c.post(
            "/api/groups",
            json={"name": "🎮 游戏专线", "vps_filter": "VPS-A"},
            headers=self._auth(),
        )
        r = self.c.post(
            "/api/rules",
            json={"rule_type": "DOMAIN-SUFFIX", "value": "example.org",
                  "target": "🎮 游戏专线"},
            headers=self._auth(),
        )
        self.assertEqual(r.json()["added"], 1)
        token = self._token()
        # Mihomo：自定义规则在 rules 最前面
        cfg = self._mihomo_cfg(token)
        self.assertTrue(
            cfg["rules"][0].startswith("DOMAIN-SUFFIX,example.org,🎮 游戏专线")
        )
        # sing-box：route.rules 优先位置
        cfg = self._singbox_cfg(token)
        found = [
            x for x in cfg["route"]["rules"]
            if x.get("domain_suffix") == ["example.org"]
        ]
        self.assertTrue(found)
        self.assertEqual(found[0]["outbound"], "🎮 游戏专线")
        # 自定义规则排在 hijack-dns/sniff 之后、AI 域名之前
        idx_custom = cfg["route"]["rules"].index(found[0])
        self.assertGreater(idx_custom, 1)

    def test_rule_target_fallback(self):
        self._add_node(VLESS_A)
        # 指向不存在的分流组 → 安全回退，不崩
        self.c.post(
            "/api/rules",
            json={"rule_type": "DOMAIN-SUFFIX", "value": "ghost.example",
                  "target": "不存在的组"},
            headers=self._auth(),
        )
        token = self._token()
        cfg = self._mihomo_cfg(token)
        self.assertTrue(
            cfg["rules"][0].startswith("DOMAIN-SUFFIX,ghost.example,🚀 节点选择")
        )
        cfg = self._singbox_cfg(token)
        found = [
            x for x in cfg["route"]["rules"]
            if x.get("domain_suffix") == ["ghost.example"]
        ]
        self.assertEqual(found[0]["outbound"], "🚀 节点选择")
        # IP-CIDR 带 no-resolve 且 DIRECT/REJECT 直通
        self.c.post(
            "/api/rules",
            json={"rule_type": "IP-CIDR", "value": "10.9.0.0/16",
                  "target": "DIRECT"},
            headers=self._auth(),
        )
        cfg = self._mihomo_cfg(token)
        self.assertIn("IP-CIDR,10.9.0.0/16,DIRECT,no-resolve", cfg["rules"])
        cfg = self._singbox_cfg(token)
        found = [
            x for x in cfg["route"]["rules"] if x.get("ip_cidr") == ["10.9.0.0/16"]
        ]
        self.assertEqual(found[0]["outbound"], "direct")

    def test_group_validation_and_empty_fallback(self):
        self.c.post("/api/groups", json={"name": "G1"}, headers=self._auth())
        # 重名拒绝
        r = self.c.post("/api/groups", json={"name": "G1"}, headers=self._auth())
        self.assertEqual(r.status_code, 400)
        # 非法正则拒绝
        r = self.c.post(
            "/api/groups", json={"name": "G2", "name_regex": "([a-z"},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 400)
        # 非法类型拒绝
        r = self.c.post(
            "/api/groups", json={"name": "G3", "type": "nope"},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 400)
        # 空匹配 → DIRECT 兜底，绝不输出空 proxies
        self.c.post(
            "/api/groups", json={"name": "G4", "vps_filter": "不存在的VPS"},
            headers=self._auth(),
        )
        token = self._token()
        cfg = self._mihomo_cfg(token)
        g = {x["name"]: x for x in cfg["proxy-groups"]}["G4"]
        self.assertEqual(g["proxies"], ["DIRECT"])
        # 删掉不存在的 → 404
        r = self.c.delete("/api/groups/nope", headers=self._auth())
        self.assertEqual(r.status_code, 404)

    def test_group_crud(self):
        r = self.c.post(
            "/api/groups",
            json={"name": "G5", "type": "url-test", "include_direct": True},
            headers=self._auth(),
        )
        gid = r.json()["group"]["id"]
        # 改名 + 启停
        r = self.c.put(f"/api/groups/{gid}",
                       json={"name": "G5x", "enabled": False},
                       headers=self._auth())
        self.assertEqual(r.json()["group"]["name"], "G5x")
        # 停用的组不出现在订阅里
        token = self._token()
        cfg = self._mihomo_cfg(token)
        self.assertNotIn("G5x", {g["name"] for g in cfg["proxy-groups"]})
        # 删除
        self.assertEqual(
            self.c.delete(f"/api/groups/{gid}", headers=self._auth()).status_code,
            200,
        )

    def test_rule_crud_and_batch_value(self):
        # 逗号+换行批量添加
        r = self.c.post(
            "/api/rules",
            json={"rule_type": "DOMAIN-SUFFIX", "value": "a.com\nb.com, c.com"},
            headers=self._auth(),
        )
        self.assertEqual(r.json()["added"], 3)
        rid = r.json()["rules"][0]["id"]
        r = self.c.put(f"/api/rules/{rid}",
                       json={"target": "🎯 全球直连", "enabled": False},
                       headers=self._auth())
        self.assertEqual(r.json()["rule"]["target"], "🎯 全球直连")
        self.assertFalse(r.json()["rule"]["enabled"])
        self.assertEqual(
            self.c.delete(f"/api/rules/{rid}", headers=self._auth()).status_code,
            200,
        )
        self.assertEqual(
            self.c.delete("/api/rules/nonexist", headers=self._auth()).status_code,
            404,
        )

    def test_batch_delete_nodes(self):
        id1 = self._add_node(VLESS_A)
        id2 = self._add_node(VLESS_B)
        r = self.c.post(
            "/api/nodes/batch-delete", json={"node_ids": [id1, id2]},
            headers=self._auth(),
        )
        self.assertEqual(r.json()["deleted"], 2)
        st = self.c.get("/api/state", headers=self._auth()).json()
        self.assertEqual(len(st["nodes"]), 0)

    def test_available_targets(self):
        self.c.post("/api/groups", json={"name": "🎮 游戏专线"},
                    headers=self._auth())
        st = self.c.get("/api/state", headers=self._auth()).json()
        self.assertIn("🎮 游戏专线", st["available_targets"])
        self.assertIn("DIRECT", st["available_targets"])
        self.assertIn("REJECT", st["available_targets"])
        self.assertIn("🚀 节点选择", st["available_targets"])
        self.assertEqual(len(st["custom_groups"]), 1)


if __name__ == "__main__":
    unittest.main()
