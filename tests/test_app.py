import base64
import os
import unittest
from unittest.mock import patch

from analyzer import MAX_LOG_LINES, SAMPLE_LOG
from app import create_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def test_index_is_available(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Web Log Security Analyzer", response.data)

    def test_frontend_assets_are_available(self):
        stylesheet = self.client.get("/static/styles.css")
        script = self.client.get("/static/app.js")
        try:
            self.assertEqual(stylesheet.status_code, 200)
            self.assertIn(b"--cyan", stylesheet.data)
            self.assertEqual(script.status_code, 200)
            self.assertIn(b"analyseLogs", script.data)
        finally:
            stylesheet.close()
            script.close()

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_version_uses_build_environment(self):
        with patch.dict(os.environ, {"APP_VERSION": "test-commit"}):
            response = self.client.get("/api/version")

        self.assertEqual(response.get_json(), {"version": "test-commit"})

    def test_sample_endpoint(self):
        response = self.client.get("/api/sample")

        self.assertEqual(response.status_code, 200)
        self.assertIn("UNION", response.get_json()["log_text"])

    def test_analyse_valid_log(self):
        response = self.client.post("/api/analyse", json={"log_text": SAMPLE_LOG})

        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.get_json()["alerts"]), 0)

    def test_analyse_accepts_base64_log_transport(self):
        encoded = base64.b64encode(SAMPLE_LOG.encode("utf-8")).decode("ascii")
        response = self.client.post("/api/analyse", json={"log_base64": encoded})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["summary"]["parsed_lines"], 13)
        alert_types = {alert["type"] for alert in response.get_json()["alerts"]}
        self.assertIn("sql_injection_pattern", alert_types)
        self.assertIn("unusual_http_method", alert_types)

    def test_analyse_rejects_invalid_base64(self):
        response = self.client.post(
            "/api/analyse", json={"log_base64": "not valid base64!"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("not valid Base64", response.get_json()["error"])

    def test_analyse_requires_json_object(self):
        response = self.client.post(
            "/api/analyse", data="plain text", content_type="text/plain"
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("JSON object", response.get_json()["error"])

    def test_analyse_rejects_invalid_log(self):
        response = self.client.post(
            "/api/analyse", json={"log_text": "not a supported log"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("No supported", response.get_json()["error"])

    def test_analyse_enforces_line_limit(self):
        response = self.client.post(
            "/api/analyse",
            json={"log_text": "invalid\n" * (MAX_LOG_LINES + 1)},
        )

        self.assertEqual(response.status_code, 413)
        self.assertIn("line analysis limit", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
