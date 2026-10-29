"""终版测试：base64 名称同步、远程节点覆盖、健康检查、ping 免 body。"""
import base64
import json
import tempfile
import unittest
from urllib.parse import unquote

from fastapi.testclient import TestClient

import app.config as config_mod

VLESS_A = (
    "vless://550e8400-e29b-41d4-a716-446655440000"
    "@127.0.0.1:1?encryption=none&security=none#oldname"
)


class TestFinal(unittest.TestCase):
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

    def _base64_lines(self, token):
        r = self.c.get(f"/sub/{token}?target=base64")
        self.assertEqual(r.status_code, 200)
        raw = base64.b64decode(r.text).decode("utf-8")
        return [ln for ln in raw.splitlines() if ln.strip()]

    def test_health(self):
        # 免鉴权
        r = self.c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"status": "ok", "version": "1.0.0"})

    def test_base64_name_sync(self):
        """自建节点：fragment 必须换成最终修饰名（含 [VPS标签]）。"""
        r = self.c.post(
            "/api/nodes",
            json={"vps_tag": "VPS-A", "raw_input": VLESS_A,
                  "priority": 10, "enabled": True},
            headers=self._auth(),
        )
        self.assertEqual(r.status_code, 200)
        token = self._token()
        lines = self._base64_lines(token)
        self.assertEqual(len(lines), 1)
        uri = lines[0]
        self.assertTrue(uri.startswith("vless://"))
        # 原始参数保留
        self.assertIn("550e8400-e29b-41d4-a716-446655440000@127.0.0.1:1", uri)
        # fragment 是最终修饰名（含 [VPS-A] 前缀），不再是裸 oldname
        frag = unquote(uri.split("#", 1)[1])
        self.assertIn("[VPS-A]", frag)
        self.assertNotEqual(frag, "oldname")

    def test_base64_includes_remote(self):
        """远程订阅缓存节点（无原始 URI）必须反向拼装进 base64 输出。"""
        token = self._token()
        store_path = str(config_mod.STORE_FILE)
        with open(store_path, encoding="utf-8") as f:
            store = json.load(f)
        store["subscriptions"].append({
            "id": "subtest01",
            "name": "远程测试源",
            "url": "https://example.com/sub",
            "prefix": "",
            "exclude_regex": "",
            "enabled": True,
            "cached_proxies": [
                {"name": "远程-Hy2", "type": "hysteria2",
                 "server": "5.6.7.8", "port": 8443,
                 "password": "pw", "sni": "b.com",
                 "fingerprint": "fp-remote-1"},
            ],
            "last_updated": "2026-10-30",
        })
        with open(store_path, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False)
        lines = self._base64_lines(token)
        self.assertEqual(len(lines), 1)
        uri = lines[0]
        self.assertTrue(uri.startswith("hysteria2://pw@5.6.7.8:8443"))
        self.assertIn("sni=b.com", uri)
        frag = unquote(uri.split("#", 1)[1])
        self.assertEqual(frag, "远程-Hy2")

    def test_ping_without_body(self):
        """新前端 ping 不带 body，后端不得 422。"""
        r = self.c.post("/api/nodes/ping", headers=self._auth())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])


if __name__ == "__main__":
    unittest.main()
