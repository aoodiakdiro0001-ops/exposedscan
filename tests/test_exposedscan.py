#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for ExposedScan (no network — pure logic only)."""
import unittest

from exposedscan import (
    SENSITIVE_PATHS,
    classify,
    render_json,
    render_markdown,
    FindResult,
)


class TestClassify(unittest.TestCase):
    def test_absent_404(self):
        label, _, _ = classify(404, "", "/.env")
        self.assertEqual(label, "ABSENT")

    def test_protected_403(self):
        label, _, note = classify(403, "", "/.git/config")
        self.assertEqual(label, "PROTECTED")
        self.assertIn("access", note)

    def test_exposed_no_heuristic(self):
        label, sev, _ = classify(200, "<html>phpinfo</html>", "/backup.zip")
        self.assertEqual(label, "EXPOSED")
        self.assertEqual(sev, "high")

    def test_confirmed_env_heuristic(self):
        label, sev, _ = classify(200, "APP_KEY=secret123\nDB_PASS=x", "/.env")
        self.assertEqual(label, "CONFIRMED")
        self.assertEqual(sev, "critical")

    def test_suspicious_when_heuristic_fails(self):
        label, _, note = classify(200, "<html>marketing page</html>", "/.env")
        self.assertEqual(label, "SUSPICIOUS")
        self.assertIn("did not match", note)

    def test_confirmed_git_config(self):
        label, _, _ = classify(200, "[core]\n\trepositoryformatversion = 0",
                               "/.git/config")
        self.assertEqual(label, "CONFIRMED")

    def test_redirect(self):
        label, _, _ = classify(301, "", "/wp-config.php")
        self.assertEqual(label, "REDIRECT")

    def test_error_when_unreachable(self):
        label, _, note = classify(None, "", "/.env")
        self.assertEqual(label, "ERROR")
        self.assertIn("connection", note)


class TestSeverity(unittest.TestCase):
    def test_critical_paths_exist(self):
        self.assertEqual(SENSITIVE_PATHS["/.env"][0], "critical")
        self.assertEqual(SENSITIVE_PATHS["/.git/config"][0], "critical")

    def test_every_path_has_severity(self):
        for path, (sev, _) in SENSITIVE_PATHS.items():
            self.assertIn(sev, ("critical", "high", "medium", "info"),
                          f"{path} bad severity")


class TestReporting(unittest.TestCase):
    def _results(self):
        return [
            FindResult(url="https://a.com/.env", path="/.env", status=200,
                       severity="critical", label="CONFIRMED", note="matched"),
            FindResult(url="https://a.com/x", path="/nope", status=404,
                       severity="medium", label="ABSENT"),
            FindResult(url="https://a.com/y", path="/p", status=403,
                       severity="high", label="PROTECTED"),
        ]

    def test_markdown_ranks_findings(self):
        md = render_markdown("https://a.com", self._results())
        self.assertIn("Findings", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("rotate every credential", md)
        self.assertIn("© 2026 Baran Avisat", md)

    def test_markdown_clean_state(self):
        results = [FindResult(url="u", path="/p", status=404,
                              severity="medium", label="ABSENT")]
        md = render_markdown("https://a.com", results)
        self.assertIn("No exposed sensitive files detected", md)

    def test_json(self):
        import json
        data = json.loads(render_json("https://a.com", self._results()))
        self.assertEqual(data["tool"], "ExposedScan")
        self.assertEqual(len(data["results"]), 3)
        self.assertIn("fix", data["results"][0])


if __name__ == "__main__":
    unittest.main()
