import unittest

from tests.base import SecureVaultTestCase


class TestRegistration(SecureVaultTestCase):
    def test_register_success(self):
        resp = self.register()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Please log in", resp.get_data(as_text=True))

    def test_register_duplicate_username_rejected(self):
        self.register(username="bob")
        resp = self.register(username="bob", email="different@example.com")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("already taken", resp.get_data(as_text=True))

    def test_register_duplicate_email_rejected(self):
        self.register(username="carol", email="dup@example.com")
        resp = self.register(username="carol2", email="dup@example.com")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("already registered", resp.get_data(as_text=True))

    def test_register_weak_password_rejected(self):
        token = self.get_csrf("/register")
        resp = self.client.post(
            "/register",
            data={
                "csrf_token": token, "username": "dave", "email": "dave@example.com",
                "password": "short", "confirm_password": "short",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("at least 10 characters", resp.get_data(as_text=True))

    def test_register_mismatched_passwords_rejected(self):
        token = self.get_csrf("/register")
        resp = self.client.post(
            "/register",
            data={
                "csrf_token": token, "username": "erin", "email": "erin@example.com",
                "password": "correcthorsebattery", "confirm_password": "somethingelse123",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("do not match", resp.get_data(as_text=True))

    def test_register_invalid_username_rejected(self):
        token = self.get_csrf("/register")
        resp = self.client.post(
            "/register",
            data={
                "csrf_token": token, "username": "a b!", "email": "f@example.com",
                "password": "correcthorsebattery", "confirm_password": "correcthorsebattery",
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_password_is_never_stored_in_plaintext(self):
        self.register(username="frank", password="correcthorsebattery")
        with self.app.app_context():
            from app.db import get_db
            from app.models import user as user_model
            db = get_db()
            row = user_model.get_user_by_username(db, "frank")
            self.assertNotEqual(row["password_hash"], "correcthorsebattery")
            self.assertNotIn("correcthorsebattery", row["password_hash"])
            self.assertTrue(row["password_hash"].startswith("$argon2id$"))


class TestLogin(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")

    def test_login_success(self):
        resp = self.login(username="alice", password="correcthorsebattery")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Upload a file", resp.get_data(as_text=True))

    def test_login_wrong_password(self):
        resp = self.login(username="alice", password="wrongpassword")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid username or password", resp.get_data(as_text=True))

    def test_login_nonexistent_user_same_error(self):
        resp = self.login(username="ghost", password="whatever12345")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid username or password", resp.get_data(as_text=True))

    def test_dashboard_requires_login(self):
        resp = self.client.get("/", follow_redirects=True)
        self.assertIn("Log in", resp.get_data(as_text=True))

    def test_logout_clears_session(self):
        self.login(username="alice", password="correcthorsebattery")
        self.logout()
        resp = self.client.get("/", follow_redirects=True)
        self.assertIn("Log in", resp.get_data(as_text=True))


class TestAccountLockoutAndRateLimiting(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")

    def test_account_locks_after_max_failed_logins(self):
        # TestConfig.MAX_FAILED_LOGINS = 3
        for _ in range(3):
            resp = self.login(username="alice", password="wrongpassword")
            self.assertIn(resp.status_code, (401,))

        resp = self.login(username="alice", password="correcthorsebattery")
        self.assertEqual(resp.status_code, 423)
        self.assertIn("temporarily locked", resp.get_data(as_text=True))

    def test_successful_login_resets_failed_counter(self):
        self.login(username="alice", password="wrongpassword")
        self.login(username="alice", password="wrongpassword")
        resp = self.login(username="alice", password="correcthorsebattery")
        self.assertEqual(resp.status_code, 200)
        self.logout()  # a successful login authenticates the session; log
                        # back out so /login is reachable again for the
                        # next round of (failed) attempts below.

        # Should now take a fresh 3 failures to lock again.
        for _ in range(3):
            self.login(username="alice", password="wrongpassword")
        resp = self.login(username="alice", password="correcthorsebattery")
        self.assertEqual(resp.status_code, 423)

    def test_ip_rate_limit_triggers_429(self):
        # TestConfig.IP_RATE_LIMIT_ATTEMPTS = 12 within 1 minute
        for i in range(12):
            self.login(username=f"nouser{i}", password="whatever12345")
        resp = self.login(username="another_missing_user", password="whatever12345")
        self.assertEqual(resp.status_code, 429)


if __name__ == "__main__":
    unittest.main()
