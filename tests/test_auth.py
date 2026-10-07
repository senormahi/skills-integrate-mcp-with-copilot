import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

import src.auth as auth
from src.app import activities, signup_for_activity, unregister_from_activity


class TeacherAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.credentials_path = Path(self.temp_dir.name) / "teachers.json"
        self.credentials_patch = patch.object(
            auth, "TEACHERS_FILE", self.credentials_path
        )
        self.credentials_patch.start()
        self.password_hash = auth.hash_password("correct horse battery staple")
        auth.save_teacher_credentials({"teacher1": self.password_hash})
        self.token = auth.create_session_token("teacher1", self.password_hash)

    def tearDown(self):
        self.credentials_patch.stop()
        self.temp_dir.cleanup()

    def request(self, token=None):
        headers = []
        if token:
            headers.append((b"cookie", f"teacher_session={token}".encode()))
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/",
                "query_string": b"",
                "headers": headers,
                "server": ("test", 80),
                "client": ("test", 123),
                "scheme": "http",
            }
        )

    def test_password_hash_and_session_signature(self):
        self.assertTrue(
            auth.verify_password("correct horse battery staple", self.password_hash)
        )
        self.assertFalse(auth.verify_password("incorrect", self.password_hash))
        self.assertEqual(auth.get_session_teacher(self.token), "teacher1")
        self.assertIsNone(auth.get_session_teacher(self.token + "tampered"))

    def test_signup_and_unregister_require_teacher(self):
        email = "auth-test@mergington.edu"
        with self.assertRaises(HTTPException) as error:
            signup_for_activity("Chess Club", email, self.request())
        self.assertEqual(error.exception.status_code, 401)

        signup_for_activity("Chess Club", email, self.request(self.token))
        self.assertIn(email, activities["Chess Club"]["participants"])
        unregister_from_activity("Chess Club", email, self.request(self.token))
        self.assertNotIn(email, activities["Chess Club"]["participants"])


if __name__ == "__main__":
    unittest.main()