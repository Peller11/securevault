import unittest

from tests.base import SecureVaultTestCase


class TestCSRFProtection(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")

    def test_upload_without_csrf_token_rejected(self):
        from io import BytesIO
        resp = self.client.post(
            "/files/upload",
            data={"file": (BytesIO(b"data"), "note.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)

    def test_upload_with_bad_csrf_token_rejected(self):
        from io import BytesIO
        resp = self.client.post(
            "/files/upload",
            data={"csrf_token": "totally-not-a-real-token", "file": (BytesIO(b"data"), "note.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)

    def test_logout_without_csrf_token_rejected(self):
        resp = self.client.post("/logout", data={})
        self.assertEqual(resp.status_code, 400)

    def test_login_form_requires_csrf_too(self):
        self.logout_without_csrf_bypass()

    def logout_without_csrf_bypass(self):
        # Register a fresh account, then attempt login POST with no CSRF.
        resp = self.client.post("/login", data={"username": "alice", "password": "correcthorsebattery"})
        self.assertEqual(resp.status_code, 400)


class TestSQLInjection(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")

    def test_login_username_sql_injection_attempt(self):
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "admin'--",
            "' UNION SELECT * FROM users --",
        ]
        for payload in payloads:
            resp = self.login(username=payload, password="whatever12345")
            self.assertEqual(resp.status_code, 401, f"Payload should fail auth safely: {payload}")

        # Ensure the users table still exists and alice is still there.
        with self.app.app_context():
            from app.db import get_db
            db = get_db()
            row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
            self.assertGreaterEqual(row["c"], 1)

    def test_registration_username_injection_stored_safely(self):
        # A malicious-looking username should be stored verbatim as data,
        # not executed as SQL, and should fail our username format check.
        resp = self.register(username="bob'; DROP TABLE users; --", email="inj@example.com")
        self.assertEqual(resp.status_code, 400)
        with self.app.app_context():
            from app.db import get_db
            db = get_db()
            row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
            self.assertGreaterEqual(row["c"], 1)  # alice from setUp still present


class TestSecurityHeaders(SecureVaultTestCase):
    def test_security_headers_present(self):
        resp = self.client.get("/login")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")

    def test_session_cookie_flags(self):
        resp = self.login_new_user_and_get_set_cookie()
        set_cookie_headers = resp.headers.get_all("Set-Cookie")
        session_cookie = next(h for h in set_cookie_headers if h.startswith("session="))
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Lax", session_cookie)

    def login_new_user_and_get_set_cookie(self):
        self.register(username="cookie_user", password="correcthorsebattery")
        token = self.get_csrf("/login")
        return self.client.post(
            "/login",
            data={"csrf_token": token, "username": "cookie_user", "password": "correcthorsebattery"},
        )


class TestXSSProtection(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")

    def test_uploaded_filename_is_escaped_in_dashboard(self):
        xss_filename = "<script>alert(1)</script>.txt"
        self.upload_file(filename=xss_filename, content=b"data")
        resp = self.client.get("/")
        html = resp.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        # Jinja2 autoescaping should turn it into harmless entities.
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
