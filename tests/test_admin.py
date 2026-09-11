import unittest

from tests.base import SecureVaultTestCase


class TestAdminAccessControl(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        # First registered user becomes admin automatically (see auth.register).
        self.register(username="root_admin", password="correcthorsebattery")
        self.register(username="regular_user", password="correcthorsebattery")

    def test_regular_user_cannot_access_admin_dashboard(self):
        self.login(username="regular_user", password="correcthorsebattery")
        resp = self.client.get("/admin/")
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_access_admin_dashboard(self):
        self.login(username="root_admin", password="correcthorsebattery")
        resp = self.client.get("/admin/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Registered users", html)
        self.assertIn("Audit log", html)

    def test_anonymous_cannot_access_admin_dashboard(self):
        resp = self.client.get("/admin/", follow_redirects=True)
        self.assertIn("Log in", resp.get_data(as_text=True))

    def test_second_registered_user_is_not_admin(self):
        with self.app.app_context():
            from app.db import get_db
            from app.models import user as user_model
            db = get_db()
            row = user_model.get_user_by_username(db, "regular_user")
            self.assertEqual(row["role"], "user")

    def test_admin_cannot_download_other_users_file_via_any_route(self):
        # Confirms there is no privileged bypass: the *same* ownership
        # check applies to admins as to anyone else on the files blueprint.
        self.login(username="regular_user", password="correcthorsebattery")
        self.upload_file(filename="private.txt", content=b"user-only-data")
        resp = self.client.get("/")
        import re
        file_id = re.search(r"/files/download/(\d+)", resp.get_data(as_text=True)).group(1)
        self.logout()

        self.login(username="root_admin", password="correcthorsebattery")
        resp = self.client.get(f"/files/download/{file_id}")
        self.assertEqual(resp.status_code, 403)


class TestAdminDashboardContent(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="root_admin", password="correcthorsebattery")

    def test_dashboard_reflects_failed_login_attempts(self):
        self.login(username="root_admin", password="wrongpassword")
        self.login(username="root_admin", password="correcthorsebattery")
        resp = self.client.get("/admin/")
        html = resp.get_data(as_text=True)
        self.assertIn("root_admin", html)
        self.assertIn("failed", html)


if __name__ == "__main__":
    unittest.main()
