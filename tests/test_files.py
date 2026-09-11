import re
import unittest
from io import BytesIO

from tests.base import SecureVaultTestCase


class TestFileUpload(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")

    def test_upload_and_list(self):
        resp = self.upload_file(filename="note.txt", content=b"hello world")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("note.txt", resp.get_data(as_text=True))

    def test_upload_rejects_disallowed_extension(self):
        resp = self.upload_file(filename="virus.exe", content=b"MZ\x90\x00fake-exe-content")
        self.assertIn("not permitted", resp.get_data(as_text=True))
        self.assertNotIn("virus.exe", resp.get_data(as_text=True).split("Recent activity")[0] if "Recent activity" in resp.get_data(as_text=True) else resp.get_data(as_text=True))

    def test_upload_rejects_content_extension_mismatch(self):
        # A .png extension but the content is plain text -- not a real PNG.
        resp = self.upload_file(filename="fake.png", content=b"just some plain text, not a png")
        self.assertIn("does not match", resp.get_data(as_text=True))

    def test_upload_rejects_empty_file(self):
        resp = self.upload_file(filename="empty.txt", content=b"")
        self.assertIn("empty", resp.get_data(as_text=True).lower())

    def test_upload_enforces_max_size(self):
        big_content = b"a" * (self.app.config["MAX_CONTENT_LENGTH"] + 1)
        resp = self.client.post(
            "/files/upload",
            data={"csrf_token": self.get_csrf("/"), "file": (BytesIO(big_content), "big.txt")},
            content_type="multipart/form-data",
        )
        # Werkzeug/Flask reject oversized bodies at the framework level (413).
        self.assertEqual(resp.status_code, 413)

    def test_stored_file_is_encrypted_on_disk(self):
        self.upload_file(filename="secret.txt", content=b"top-secret-plaintext-content")
        storage_dir = self.app.config["STORAGE_DIR"]
        import os
        found_plain = False
        for fname in os.listdir(storage_dir):
            with open(os.path.join(storage_dir, fname), "rb") as f:
                data = f.read()
                if b"top-secret-plaintext-content" in data:
                    found_plain = True
        self.assertFalse(found_plain, "Plaintext content must never appear on disk")

    def test_download_roundtrip_matches_original_content(self):
        self.upload_file(filename="round.txt", content=b"round trip content 12345")
        resp = self.client.get("/")
        file_id = re.search(r"/files/download/(\d+)", resp.get_data(as_text=True)).group(1)
        resp = self.client.get(f"/files/download/{file_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_data(), b"round trip content 12345")

    def test_delete_removes_file(self):
        self.upload_file(filename="deleteme.txt", content=b"bye")
        resp = self.client.get("/")
        file_id = re.search(r"/files/download/(\d+)", resp.get_data(as_text=True)).group(1)
        token = self.get_csrf("/")
        resp = self.client.post(f"/files/delete/{file_id}", data={"csrf_token": token}, follow_redirects=True)
        self.assertNotIn("deleteme.txt", resp.get_data(as_text=True))
        # Downloading afterwards should 404.
        resp = self.client.get(f"/files/download/{file_id}")
        self.assertEqual(resp.status_code, 404)


class TestFileAuthorization(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")
        self.upload_file(filename="alice_secret.txt", content=b"alice-only-data")
        resp = self.client.get("/")
        self.alice_file_id = re.search(r"/files/download/(\d+)", resp.get_data(as_text=True)).group(1)
        self.logout()

        self.register(username="bob", password="correcthorsebattery")
        self.login(username="bob", password="correcthorsebattery")

    def test_user_cannot_download_others_file(self):
        resp = self.client.get(f"/files/download/{self.alice_file_id}")
        self.assertEqual(resp.status_code, 403)

    def test_user_cannot_delete_others_file(self):
        token = self.get_csrf("/")
        resp = self.client.post(f"/files/delete/{self.alice_file_id}", data={"csrf_token": token})
        self.assertEqual(resp.status_code, 403)

    def test_unauthorized_attempt_is_audit_logged(self):
        self.client.get(f"/files/download/{self.alice_file_id}")
        with self.app.app_context():
            from app.db import get_db
            db = get_db()
            row = db.execute(
                "SELECT * FROM audit_logs WHERE action = 'unauthorized_access_attempt' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["resource_id"], self.alice_file_id)

    def test_download_requires_login(self):
        self.logout()
        resp = self.client.get(f"/files/download/{self.alice_file_id}", follow_redirects=True)
        self.assertIn("Log in", resp.get_data(as_text=True))

    def test_nonexistent_file_is_404(self):
        resp = self.client.get("/files/download/999999")
        self.assertEqual(resp.status_code, 404)


class TestPathTraversal(SecureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.register(username="alice", password="correcthorsebattery")
        self.login(username="alice", password="correcthorsebattery")

    def test_resolve_storage_path_rejects_traversal(self):
        from app.services.file_service import resolve_storage_path, FileValidationError
        storage_dir = self.app.config["STORAGE_DIR"]
        with self.assertRaises(FileValidationError):
            resolve_storage_path(storage_dir, "../../etc/passwd")

    def test_resolve_storage_path_rejects_nested_path(self):
        from app.services.file_service import resolve_storage_path, FileValidationError
        storage_dir = self.app.config["STORAGE_DIR"]
        with self.assertRaises(FileValidationError):
            resolve_storage_path(storage_dir, "subdir/evil")

    def test_uploaded_filename_never_used_as_path(self):
        # Upload a file whose name looks like a traversal attempt. It
        # should be accepted as a harmless display label (or rejected for
        # extension reasons) but never affect where bytes land on disk.
        resp = self.upload_file(filename="../../../etc/passwd.txt", content=b"data")
        self.assertIn(resp.status_code, (200,))
        import os
        storage_dir = self.app.config["STORAGE_DIR"]
        for fname in os.listdir(storage_dir):
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", fname), f"Unexpected stored filename: {fname}")


if __name__ == "__main__":
    unittest.main()
