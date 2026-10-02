import base64
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import scan_job_logs as scanner


class ScanJobLogsTest(unittest.TestCase):
    def test_plaintext_and_ansi_color(self):
        matches = scanner.scan_text(
            "\x1b[31mresult: secret-value\x1b[0m\n", {"password": "secret-value"},
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].representation, "plaintext")
        self.assertEqual(matches[0].location, "line:1")

    def test_slurp_base64_in_job_events(self):
        value = "QA_CANARY_PASSWORD_demo!"
        text = json.dumps({
            "results": [{
                "event_data": {
                    "res": {"content": base64.b64encode(value.encode()).decode()},
                },
            }],
        })
        matches = scanner.scan_text(text, {"password": value})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].representation, "base64")
        self.assertIn('["event_data"]["res"]["content"]', matches[0].location)

    def test_json_escaped_value_in_stdout(self):
        value = 'a "quoted" value\non two lines'
        encoded = json.dumps(value)[1:-1]
        matches = scanner.scan_text("result: " + encoded, {"notes": value})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].representation, "json_escaped")

    def test_nested_json_values(self):
        text = json.dumps({"event_data": {"res": {"value": "sentinel"}}})
        matches = scanner.scan_text(text, {"custom_field": "sentinel"})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].label, "custom_field")

    def test_no_matches(self):
        self.assertEqual(scanner.scan_text("normal task output", {"password": "secret"}), [])

    def test_run_canaries_have_expected_password_suffix(self):
        values = scanner.run_canaries("demo")
        self.assertEqual(values["password"], "QA_CANARY_PASSWORD_demo!")
        self.assertEqual(values["cache_key"], "QA_CANARY_CACHE_KEY_demo")

    def test_report_does_not_echo_credential_values(self):
        value = "sensitive-credential-test-value"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / (value + ".txt")
            log.write_text(json.dumps({value: value}), encoding="utf-8")
            credentials = root / "credentials.json"
            credentials.write_text(json.dumps({"privateKey": value}), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                result = scanner.main([
                    str(log), "--secrets-file", str(credentials), "--fail-on-match",
                ])
            self.assertEqual(result, 1)
            self.assertNotIn(value, output.getvalue())
            self.assertIn("[REDACTED]", output.getvalue())
            self.assertIn("privateKey", output.getvalue())

    def test_json_report_and_clean_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "stdout.txt"
            log.write_text("ok: [localhost]", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                result = scanner.main([str(log), "--run-id", "demo", "--json"])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["match_count"], 0)


if __name__ == "__main__":
    unittest.main()
