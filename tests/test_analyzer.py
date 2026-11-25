import unittest

from analyzer import AnalysisError, SAMPLE_LOG, analyse_log, parse_log_line


NORMAL_LINE = (
    '198.51.100.10 - - [25/Nov/2026:10:00:01 +0000] '
    '"GET /dashboard HTTP/1.1" 200 4210 "-" "Mozilla/5.0"'
)


class ParserTests(unittest.TestCase):
    def test_parses_combined_log_line(self):
        entry = parse_log_line(NORMAL_LINE)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "198.51.100.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/dashboard")
        self.assertEqual(entry.status, 200)

    def test_rejects_unsupported_line(self):
        self.assertIsNone(parse_log_line("this is not an access log"))


class AnalysisTests(unittest.TestCase):
    def test_summarises_normal_traffic(self):
        result = analyse_log(NORMAL_LINE)

        self.assertEqual(result["summary"]["parsed_lines"], 1)
        self.assertEqual(result["summary"]["unique_ips"], 1)
        self.assertEqual(result["summary"]["status_groups"]["2xx"], 1)
        self.assertEqual(result["risk"]["level"], "none")

    def test_detects_sample_security_events(self):
        result = analyse_log(SAMPLE_LOG)
        alert_types = {alert["type"] for alert in result["alerts"]}

        self.assertIn("repeated_authentication_failures", alert_types)
        self.assertIn("possible_path_enumeration", alert_types)
        self.assertIn("path_traversal_attempt", alert_types)
        self.assertIn("sql_injection_pattern", alert_types)
        self.assertIn("scanner_user_agent", alert_types)
        self.assertIn("unusual_http_method", alert_types)
        self.assertEqual(result["risk"]["level"], "critical")

    def test_detects_unusual_http_method(self):
        line = (
            '192.0.2.44 - - [25/Nov/2026:10:05:01 +0000] '
            '"DELETE /api/users/42 HTTP/1.1" 405 198 "-" "curl/8.5"'
        )

        result = analyse_log(line)
        alerts = result["alerts"]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "unusual_http_method")
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertIn("DELETE /api/users/42", alerts[0]["evidence"])

    def test_reports_mixed_invalid_lines(self):
        result = analyse_log(f"bad line\n{NORMAL_LINE}")

        self.assertEqual(result["summary"]["total_lines"], 2)
        self.assertEqual(result["summary"]["rejected_lines"], 1)
        self.assertEqual(result["summary"]["rejected_line_numbers"], [1])

    def test_rejects_empty_input(self):
        with self.assertRaisesRegex(AnalysisError, "non-empty"):
            analyse_log("")

    def test_rejects_input_without_supported_lines(self):
        with self.assertRaisesRegex(AnalysisError, "No supported"):
            analyse_log("not a log line")


if __name__ == "__main__":
    unittest.main()
