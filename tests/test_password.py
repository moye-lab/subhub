"""管理密码修改功能的测试：哈希校验优先级 + 接口全流程。"""
import json
import os
import tempfile
import unittest

from fastapi.testclient import TestClient

import app.config as config_mod
from app.main import _hash_password, _check_password


class TestPasswordHelpers(unittest.TestCase):
    def test_hash_is_sha256_hex(self):
        h = _hash_password("abc123")
        self.assertEqual(len(h), 64)
        self.assertNotIn("abc123", h)

    def test_env_password_when_no_override(self):
        settings = {}
        self.assertTrue(_check_password(config_mod.ADMIN_PASSWORD, settings))
        self.assertFalse(_check_password("wrong", settings))

    def test_stored_hash_takes_precedence(self):
        settings = {"admin_password_hash": _hash_password("newpass")}
        self.assertTrue(_check_password("newpass", settings))
        # 环境密码此时失效
        self.assertFalse(_check_password(config_mod.ADMIN_PASSWORD, settings))
        self.assertFalse(_check_password("", settings))


class TestPasswordApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # 隔离数据目录，避免污染开发用的 data/
        self._saved = {}
        for mod in (config_mod,):
            for attr in ("DATA_DIR", "STORE_FILE", "TEMPLATE_FILE"):
                self._saved[(mod, attr)] = getattr(mod, attr)
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
        main_mod.STATIC_INDEX = main_mod.Path(__file__).resolve().parent.parent / "app" / "static" / "index.html"
        self.client = TestClient(main_mod.app)
        self.env_pw = config_mod.ADMIN_PASSWORD

    def tearDown(self):
        for (mod, attr), val in self._saved.items():
            setattr(mod, attr, val)
        self.tmp.cleanup()

    def test_full_flow(self):
        c = self.client
        # 默认密码登录
        r = c.post("/api/login", json={"password": self.env_pw})
        self.assertEqual(r.status_code, 200)

        # 当前密码错误
        r = c.post("/api/settings/password",
                   json={"current_password": "wrong", "new_password": "newpass123"},
                   headers={"X-Admin-Token": self.env_pw})
        self.assertEqual(r.status_code, 401)

        # 新密码太短
        r = c.post("/api/settings/password",
                   json={"current_password": self.env_pw, "new_password": "123"},
                   headers={"X-Admin-Token": self.env_pw})
        self.assertEqual(r.status_code, 400)

        # 正常修改
        r = c.post("/api/settings/password",
                   json={"current_password": self.env_pw, "new_password": "newpass123"},
                   headers={"X-Admin-Token": self.env_pw})
        self.assertEqual(r.status_code, 200)

        # 旧密码失效，新密码生效
        self.assertEqual(c.post("/api/login", json={"password": self.env_pw}).status_code, 401)
        self.assertEqual(c.post("/api/login", json={"password": "newpass123"}).status_code, 200)

        # state 不泄漏哈希
        r = c.get("/api/state", headers={"X-Admin-Token": "newpass123"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("admin_password_hash", r.json()["settings"])

        # 文件里是哈希不是原文
        store = json.load(open(config_mod.STORE_FILE, encoding="utf-8"))
        h = store["settings"].get("admin_password_hash", "")
        self.assertEqual(len(h), 64)
        self.assertNotIn("newpass123", json.dumps(store))

    def test_forget_recovery_by_deleting_hash(self):
        """忘记密码恢复路径：删掉 hash 即回退到环境密码。"""
        c = self.client
        c.post("/api/settings/password",
               json={"current_password": self.env_pw, "new_password": "newpass123"},
               headers={"X-Admin-Token": self.env_pw})
        store = json.load(open(config_mod.STORE_FILE, encoding="utf-8"))
        del store["settings"]["admin_password_hash"]
        json.dump(store, open(config_mod.STORE_FILE, "w", encoding="utf-8"))
        # 环境密码重新生效
        self.assertEqual(c.post("/api/login", json={"password": self.env_pw}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
