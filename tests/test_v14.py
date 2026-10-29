"""v1.4 新特性测试：UA 自适应订阅分发、备份导入导出、双引擎预览、
节点 TCP 测速、登录防爆破限流、存储损坏自恢复。"""
import json
import tempfile
import unittest

from fastapi.testclient import TestClient

import app.config as config_mod

VLESS_LOCAL = (
    "vless://550e8400-e29b-41d4-a716-446655440000"
    "@127.0.0.1:1?encryption=none&security=none#pingtest"
)


class TestV14(unittest.TestCase):
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

    def _add_local_node(self):
        r = self.c.post(
            "/api/nodes",
            json={"vps_tag": "VPS-A", "raw_input": VLESS_LOCAL,
                  "priority": 10, "enabled": True},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["added"], 1)
        st = self.c.get("/api/state", headers=self._auth()).json()
        return st["nodes"][0]["id"]

    # ---- 任务2：UA 自适应 ----
    def test_ua_auto_dispatch(self):
        token = self._token()
        cases = [
            ("sing-box/1.10.0", "application/json"),
            ("SFA/1.8.0", "application/json"),
            ("Shadowrocket/2050", "text/plain"),
            ("v2rayNG/1.8.0", "text/plain"),
            ("NekoBox/1.0", "text/plain"),
            ("Clash.Meta/1.18.0", "text/yaml"),
            ("Stash/2.0", "text/yaml"),
            ("Quantumult X/1.0", "text/plain"),
        ]
        for ua, ct in cases:
            r = self.c.get(f"/sub/{token}", headers={"User-Agent": ua})
            self.assertEqual(r.status_code, 200, ua)
            self.assertIn(ct, r.headers["content-type"], ua)
        # sing-box 输出是合法 JSON
        r = self.c.get(f"/sub/{token}", headers={"User-Agent": "sing-box/1.10.0"})
        json.loads(r.text)
        # base64 输出可解码
        import base64
        r = self.c.get(f"/sub/{token}", headers={"User-Agent": "Shadowrocket/2050"})
        base64.b64decode(r.text)
        # 无 UA（testclient 默认）→ 兜底 mihomo
        r = self.c.get(f"/sub/{token}")
        self.assertIn("text/yaml", r.headers["content-type"])
        # 显式别名
        r = self.c.get(f"/sub/{token}?target=sing-box")
        self.assertIn("application/json", r.headers["content-type"])
        r = self.c.get(f"/sub/{token}?target=clash")
        self.assertIn("text/yaml", r.headers["content-type"])
        # 坏 token 仍 403
        self.assertEqual(self.c.get("/sub/badtoken").status_code, 403)

    # ---- 任务4：备份导入导出 ----
    def test_backup_export_import(self):
        self._add_local_node()
        r = self.c.get("/api/backup/export", headers=self._auth())
        self.assertEqual(r.status_code, 200)
        backup = r.json()["backup"]
        self.assertEqual(len(backup["store"]["nodes"]), 1)
        self.assertTrue(backup["base_template"])
        self.assertIn("sub_token", backup["store"]["settings"])
        # 删掉节点再导入恢复
        nid = backup["store"]["nodes"][0]["id"]
        self.assertEqual(
            self.c.delete(f"/api/nodes/{nid}", headers=self._auth()).status_code, 200
        )
        r = self.c.post("/api/backup/import", json={"backup": backup},
                        headers=self._auth())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["restored_nodes"], 1)
        st = self.c.get("/api/state", headers=self._auth()).json()
        self.assertEqual(len(st["nodes"]), 1)
        # 非法备份被拒绝
        r = self.c.post("/api/backup/import", json={"backup": {"foo": 1}},
                        headers=self._auth())
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/backup/import",
                        json={"backup": {"store": {"settings": {}}}},
                        headers=self._auth())
        self.assertEqual(r.status_code, 400)

    # ---- 任务2：双引擎预览 ----
    def test_preview_dual(self):
        r = self.c.get("/api/preview", headers=self._auth())
        self.assertEqual(r.status_code, 200)
        self.assertIn("yaml", r.json())
        r = self.c.get("/api/preview?target=singbox", headers=self._auth())
        data = r.json()
        self.assertIn("json", data)
        parsed = json.loads(data["json"])
        self.assertIn("outbounds", parsed)

    # ---- 任务3：节点测速 ----
    def test_ping(self):
        # 空节点
        r = self.c.post("/api/nodes/ping", json={}, headers=self._auth())
        self.assertEqual(r.json(), {"ok": True, "results": {}})
        # 本地闭口 → offline
        nid = self._add_local_node()
        r = self.c.post("/api/nodes/ping", json={"node_ids": [nid]},
                        headers=self._auth())
        self.assertEqual(r.status_code, 200)
        res = r.json()["results"][nid]
        self.assertEqual(res["status"], "offline")
        self.assertEqual(res["latency"], -1)
        # 全量
        r = self.c.post("/api/nodes/ping", json={}, headers=self._auth())
        self.assertIn(nid, r.json()["results"])

    # ---- 任务4：登录限流 ----
    def test_login_rate_limit(self):
        for _ in range(5):
            r = self.c.post("/api/login", json={"password": "wrong-pw"})
            self.assertEqual(r.status_code, 401)
        r = self.c.post("/api/login", json={"password": "wrong-pw"})
        self.assertEqual(r.status_code, 429)
        self.assertIn("15 分钟", r.json()["detail"])

    # ---- 任务1：损坏自恢复 ----
    def test_corrupt_store_recovery(self):
        with open(config_mod.STORE_FILE, "w", encoding="utf-8") as f:
            f.write("{broken json,,,")
        # 服务不崩，登录仍可用（回退默认结构后环境密码生效）
        r = self.c.post("/api/login", json={"password": self.env_pw})
        self.assertEqual(r.status_code, 200)
        # 坏文件被改名留档
        self.assertTrue(
            config_mod.STORE_FILE.with_name("store.json.corrupt").exists()
        )
        # store 已重建为合法 JSON
        store = json.load(open(config_mod.STORE_FILE, encoding="utf-8"))
        self.assertIn("settings", store)


if __name__ == "__main__":
    unittest.main()
