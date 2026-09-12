import re
import unittest

import pyotp

from app.db import get_db
from app.models import user as user_model
from tests.base import SecureVaultTestCase


class TestMFA(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")

    def enable_mfa(self):
        response = self.client.get("/mfa/setup")
        html = response.get_data(as_text=True)
        secret = re.search(r"Manual setup key:</p>|Manual setup key:", html)
        self.assertIsNotNone(secret)
        secret = re.search(r'class="mono">([A-Z2-7]+)</code>', html).group(1)
        token = self.get_csrf("/mfa/setup")
        response = self.client.post(
            "/mfa/setup",
            data={"csrf_token": token, "code": pyotp.TOTP(secret).now()},
        )
        self.assertEqual(response.status_code, 200)
        codes = re.findall(r"<code>([A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8})</code>", response.get_data(as_text=True))
        self.assertEqual(len(codes), 10)
        return secret, codes

    def test_setup_requires_valid_totp_and_generates_recovery_codes(self):
        response = self.client.get("/mfa/setup")
        secret = re.search(r'class="mono">([A-Z2-7]+)</code>', response.get_data(as_text=True)).group(1)
        token = self.get_csrf("/mfa/setup")
        response = self.client.post("/mfa/setup", data={"csrf_token": token, "code": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("current 6-digit code", response.get_data(as_text=True))
        token = self.get_csrf("/mfa/setup")
        response = self.client.post(
            "/mfa/setup", data={"csrf_token": token, "code": pyotp.TOTP(secret).now()}
        )
        self.assertIn("Multi-Factor Authentication enabled", response.get_data(as_text=True))
        with self.app.app_context():
            row = user_model.get_user_by_username(get_db(), "alice")
            self.assertEqual(row["mfa_enabled"], 1)

    def test_login_requires_mfa_and_cannot_bypass(self):
        secret, _ = self.enable_mfa()
        self.logout()
        response = self.login(username="alice", password="correcthorsebattery")
        self.assertIn("Verify your identity", response.get_data(as_text=True))
        response = self.client.get("/", follow_redirects=True)
        self.assertIn("Verify your identity", response.get_data(as_text=True))
        token = self.get_csrf("/mfa/verify")
        response = self.client.post(
            "/mfa/verify", data={"csrf_token": token, "code": pyotp.TOTP(secret).now()}, follow_redirects=True
        )
        self.assertIn("Upload a file", response.get_data(as_text=True))

    def test_invalid_totp_and_mfa_rate_limit(self):
        self.enable_mfa()
        self.logout()
        self.login(username="alice", password="correcthorsebattery")
        for _ in range(self.app.config["MFA_RATE_LIMIT_ATTEMPTS"]):
            token = self.get_csrf("/mfa/verify")
            response = self.client.post("/mfa/verify", data={"csrf_token": token, "code": "000000"})
            self.assertEqual(response.status_code, 401)
        token = self.get_csrf("/mfa/verify")
        response = self.client.post("/mfa/verify", data={"csrf_token": token, "code": "000000"})
        self.assertEqual(response.status_code, 429)

    def test_recovery_code_is_one_time(self):
        secret, codes = self.enable_mfa()
        self.logout()
        self.login(username="alice", password="correcthorsebattery")
        token = self.get_csrf("/mfa/verify")
        response = self.client.post("/mfa/verify", data={"csrf_token": token, "code": codes[0]})
        self.assertEqual(response.status_code, 302)
        self.logout()
        self.login(username="alice", password="correcthorsebattery")
        token = self.get_csrf("/mfa/verify")
        response = self.client.post("/mfa/verify", data={"csrf_token": token, "code": codes[0]})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(codes[0], response.get_data(as_text=True))

    def test_disable_requires_password_and_factor_and_is_audited(self):
        secret, _ = self.enable_mfa()
        token = self.get_csrf("/security")
        response = self.client.post(
            "/mfa/disable", data={"csrf_token": token, "password": "wrongpassword", "code": pyotp.TOTP(secret).now()}
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(user_model.get_user_by_username(get_db(), "alice")["mfa_enabled"], 1)
        token = self.get_csrf("/security")
        response = self.client.post(
            "/mfa/disable", data={"csrf_token": token, "password": "correcthorsebattery", "code": pyotp.TOTP(secret).now()}
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            db = get_db()
            self.assertEqual(user_model.get_user_by_username(db, "alice")["mfa_enabled"], 0)
            actions = [row["action"] for row in db.execute("SELECT action FROM audit_logs").fetchall()]
            self.assertIn("mfa_disabled", actions)

    def test_mfa_forms_require_csrf(self):
        self.enable_mfa()
        response = self.client.post("/mfa/disable", data={"password": "correcthorsebattery", "code": "000000"})
        self.assertEqual(response.status_code, 400)

    def test_regular_user_cannot_change_another_users_mfa(self):
        self.enable_mfa()
        self.logout()
        self.register(username="bob", email="bob@example.com")
        self.login(username="bob", password="correcthorsebattery")
        response = self.client.post("/mfa/disable", data={"password": "correcthorsebattery", "code": "000000", "csrf_token": self.get_csrf("/security")})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            row = user_model.get_user_by_username(get_db(), "alice")
            self.assertEqual(row["mfa_enabled"], 1)


if __name__ == "__main__":
    unittest.main()