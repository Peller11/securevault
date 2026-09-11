import base64
import os
import re
import shutil
import tempfile
import unittest

from app import create_app
from app.config import TestConfig


CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class SecureVaultTestCase(unittest.TestCase):
    """Base class that spins up a fresh app, temp SQLite DB, and temp
    storage directory for every test method, so tests never share state
    or touch the real instance/storage directories."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="securevault_test_")
        overrides = {
            "DATABASE_PATH": os.path.join(self.tmp_dir, "test.db"),
            "STORAGE_DIR": os.path.join(self.tmp_dir, "storage"),
            "SECRET_KEY": os.urandom(32).hex(),
            "ENCRYPTION_KEY_B64": base64.b64encode(os.urandom(32)).decode(),
        }
        self.app = create_app(TestConfig, config_overrides=overrides)
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # --- helpers -----------------------------------------------------------

    def get_csrf(self, path: str) -> str:
        resp = self.client.get(path)
        match = CSRF_RE.search(resp.get_data(as_text=True))
        assert match, f"No CSRF token found on {path}"
        return match.group(1)

    def register(self, username="alice", email=None, password="correcthorsebattery"):
        email = email or f"{username}@example.com"
        token = self.get_csrf("/register")
        return self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    def login(self, username="alice", password="correcthorsebattery"):
        token = self.get_csrf("/login")
        return self.client.post(
            "/login",
            data={"csrf_token": token, "username": username, "password": password},
            follow_redirects=True,
        )

    def logout(self):
        token = self.get_csrf("/")
        return self.client.post("/logout", data={"csrf_token": token}, follow_redirects=True)

    def upload_file(self, filename="note.txt", content=b"hello world", token=None):
        from io import BytesIO
        if token is None:
            token = self.get_csrf("/")
        return self.client.post(
            "/files/upload",
            data={"csrf_token": token, "file": (BytesIO(content), filename)},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
