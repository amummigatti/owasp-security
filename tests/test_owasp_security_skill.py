#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Tests for the scanner and report renderer of owasp-security-skill.

The scan report is the interface between the two skills, so these also render a
report and parse it back with the Jira skill's reader: if either side changes the
format without the other, that test fails instead of the Jira sync quietly missing
findings.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
OWASP_SCRIPTS = ROOT / "skills" / "owasp-security-skill" / "scripts"
JIRA_SCRIPTS = ROOT / "skills" / "jira-updates-skill" / "scripts"
sys.path.insert(0, str(OWASP_SCRIPTS))
sys.path.insert(0, str(JIRA_SCRIPTS))

import parse_report  # noqa: E402
import render_report  # noqa: E402
import scan_repos  # noqa: E402


def scan_args(**overrides):
    values = dict(max_file_bytes=1_500_000, max_per_rule_per_file=3, max_per_rule_per_repo=40)
    values.update(overrides)
    return Namespace(**values)


def scan_directory(path: Path, **overrides) -> dict:
    catalogue = json.loads(scan_repos.find_default_rules() and Path(scan_repos.find_default_rules()).read_text(encoding="utf-8"))
    rules = scan_repos.compile_rules(catalogue["rules"])
    repo = {"name": path.name, "path": str(path), "source": "test", "git": {}, "inventory": {}}
    return scan_repos.scan_repo(repo, rules, catalogue.get("presence_rules", []), catalogue.get("pair_rules", []),
                                scan_repos.build_classifier({}), scan_args(**overrides))


class Workdir(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="owasp-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)


class TruncationIsNeverSilent(Workdir):
    def make_repo(self, files: int) -> Path:
        repo = self.tmp / "big"
        repo.mkdir()
        for index in range(files):
            (repo / ("f%d.py" % index)).write_text('cur.execute("SELECT * FROM t WHERE id = " + request.args["x"])\n')
        return repo

    def test_cap_reached_is_recorded_with_how_much_was_left_out(self):
        result = scan_directory(self.make_repo(60))
        sql = [f for f in result["findings"] if f["rule_id"] == "sql-string-built-in-python"]
        self.assertEqual(len(sql), 40)
        self.assertFalse(result["scan"]["complete"])
        entry = [t for t in result["scan"]["truncated"] if t["rule_id"] == "sql-string-built-in-python"][0]
        self.assertEqual((entry["kept"], entry["suppressed_files"]), (40, 20))
        self.assertTrue(any("20 further file(s)" in note for note in result["scan"]["completeness_notes"]))
        self.assertEqual(result["stats"]["truncated_rules"], 1)

    def test_under_the_cap_is_complete(self):
        result = scan_directory(self.make_repo(10))
        self.assertTrue(result["scan"]["complete"])
        self.assertEqual(result["scan"]["truncated"], [])
        self.assertEqual(result["scan"]["completeness_notes"], [])

    def test_raising_the_cap_makes_the_scan_complete(self):
        result = scan_directory(self.make_repo(60), max_per_rule_per_repo=100)
        self.assertTrue(result["scan"]["complete"])
        self.assertEqual(len([f for f in result["findings"] if f["rule_id"] == "sql-string-built-in-python"]), 60)

    def test_oversized_files_are_reported_as_not_scanned(self):
        repo = self.make_repo(1)
        (repo / "huge.py").write_text("x = 1\n" * 100)
        result = scan_directory(repo, max_file_bytes=50)
        self.assertFalse(result["scan"]["complete"])
        self.assertTrue(any("larger than 50 bytes" in note for note in result["scan"]["completeness_notes"]))

    def test_lockfiles_are_visible_to_presence_rules(self):
        # Regression: lockfiles are skipped as generated, which once made
        # "manifest without a lockfile" fire on repositories that had one.
        repo = self.tmp / "app"
        repo.mkdir()
        (repo / "package.json").write_text('{"name": "app"}')
        (repo / "package-lock.json").write_text("{}")
        rules = [f["rule_id"] for f in scan_directory(repo)["findings"]]
        self.assertNotIn("npm-manifest-without-lockfile", rules)
        (repo / "package-lock.json").unlink()
        rules = [f["rule_id"] for f in scan_directory(repo)["findings"]]
        self.assertIn("npm-manifest-without-lockfile", rules)


def finding(fid, title, file, severity="medium", verdict="confirmed", **extra):
    base = {
        "id": fid, "rule_id": "manual-review", "title": title, "severity": severity, "confidence": "high",
        "owasp_id": "A05:2025", "owasp_name": "Injection", "cwe": ["CWE-89"], "file": file, "line": 10,
        "occurrences": 1, "other_lines": [], "snippets": ["cur.execute(sql + user)"],
        "explain": "Input becomes part of the statement.", "analysis": "Reached from a public route.",
        "remediation": "Use bind parameters.", "detector": "manual-review", "verdict": verdict,
    }
    base.update(extra)
    return base


def findings_document(findings, scan=None):
    return {
        "schema": "owasp-scan-findings/1", "generated_at": "2026-01-01T00:00:00+00:00",
        "tool": {"scanner": "scan_repos.py", "rules_version": 1},
        "taxonomy": {"source": "https://top10.owasp.org/2025/", "fetched_at": "2026-01-01T00:00:00+00:00"},
        "repos": [{
            "name": "demo", "source": "https://example.invalid/demo",
            "git": {"short_commit": "abc1234", "branch": "main", "committed_at": "2026-01-01"},
            "inventory": {"languages": {"Python": 3}},
            "scan": scan or {"files_scanned": 3, "complete": True, "completeness_notes": []},
            "findings": findings,
        }],
    }


class RenderTests(Workdir):
    def render(self, document, *extra):
        source = self.tmp / "findings.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        argv = ["render_report.py", "--findings", str(source), "--out-dir", str(self.tmp / "out"), *extra]
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            code = render_report.main()
        return code, json.loads(stdout.getvalue())

    def report_text(self, result) -> str:
        return Path(result["report"]).read_text(encoding="utf-8")

    def test_duplicate_repo_title_and_file_is_refused_and_nothing_is_written(self):
        document = findings_document([finding("demo-001", "Same title", "a.py"),
                                      finding("demo-002", "Same title", "a.py")])
        code, result = self.render(document)
        self.assertEqual(code, 2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["collisions"][0]["finding_ids"], ["demo-001", "demo-002"])
        self.assertFalse((self.tmp / "out").exists() and list((self.tmp / "out").glob("*.md")))

    def test_distinct_titles_or_files_are_fine(self):
        document = findings_document([finding("demo-001", "Same title", "a.py"),
                                      finding("demo-002", "Same title", "b.py"),
                                      finding("demo-003", "A different title", "a.py")])
        code, result = self.render(document)
        self.assertEqual(code, 0, result)

    def test_a_rejected_candidate_does_not_collide_with_a_real_finding(self):
        document = findings_document([finding("demo-001", "Same title", "a.py"),
                                      finding("demo-002", "Same title", "a.py", verdict="false_positive")])
        code, _ = self.render(document)
        self.assertEqual(code, 0)

    def test_secret_in_evidence_is_redacted_and_counted(self):
        document = findings_document([finding(
            "demo-001", "Hardcoded key", "a.py",
            snippets=['AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'],
            analysis="The value AKIAIOSFODNN7EXAMPLE was found in the file.")])
        code, result = self.render(document)
        self.assertEqual(code, 0)
        text = self.report_text(result)
        self.assertNotIn("wJalrXUtnFEMI", text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertIn("<redacted:", text)
        self.assertEqual(result["redactions"], 2)
        self.assertIn("2 value(s) matching secret patterns were redacted", text)

    def test_secret_in_a_rejected_candidate_is_cleaned_but_not_counted(self):
        document = findings_document([finding(
            "demo-001", "Placeholder", "a.py", verdict="false_positive", analysis="A documentation placeholder.",
            snippets=['api_key = "your_api_key_here"'])])
        _, result = self.render(document)
        self.assertEqual(result["redactions"], 0, "its evidence never appears in the report")

    def test_incomplete_scan_is_flagged_everywhere_a_reader_looks(self):
        scan = {"files_scanned": 3, "complete": False,
                "completeness_notes": ["rule sql-string-built-in-python: 20 further file(s) matched"]}
        code, result = self.render(findings_document([finding("demo-001", "Real one", "a.py")], scan))
        self.assertEqual(code, 0)
        self.assertFalse(result["scan_complete"])
        self.assertEqual(result["incomplete_repositories"], ["demo"])
        text = self.report_text(result)
        self.assertIn("**Incomplete scan.**", text)
        self.assertIn("**Incomplete** - 1 gap(s)", text)
        self.assertIn("This repository was not fully scanned", text)
        self.assertIn("20 further file(s) matched", text)

    def test_complete_scan_says_so_and_has_no_warning(self):
        code, result = self.render(findings_document([finding("demo-001", "Real one", "a.py")]))
        text = self.report_text(result)
        self.assertTrue(result["scan_complete"])
        self.assertIn("| Scan coverage | Complete |", text)
        self.assertNotIn("not fully scanned", text)


class ReportIsAContractBetweenTheSkills(RenderTests):
    """Render a report, then read it with the Jira skill's parser."""

    def test_round_trip_preserves_what_the_tracker_needs(self):
        document = findings_document([
            finding("demo-001", "SQL statement assembled from a string", "src/db.py", severity="high"),
            finding("demo-002", "Debug mode enabled", "src/settings.py", severity="low", verdict="needs_verification",
                    cwe=["CWE-489"], owasp_id="A02:2025", owasp_name="Security Misconfiguration",
                    snippets=["DEBUG = True"], remediation="Drive the flag from the environment."),
            finding("demo-003", "Rejected thing", "src/x.py", verdict="false_positive"),
        ])
        _, result = self.render(document)
        parsed = parse_report.parse(self.report_text(result), result["report"])

        # The report groups findings by OWASP category, so order is not the input order.
        by_id = {i["finding_id"]: i for i in parsed["issues"]}
        self.assertEqual(sorted(by_id), ["demo-001", "demo-002"])
        self.assertEqual(parsed["rejected_count"], 1)
        first, second = by_id["demo-001"], by_id["demo-002"]
        self.assertEqual((first["title"], first["severity"], first["verdict"]),
                         ("SQL statement assembled from a string", "high", "confirmed"))
        self.assertEqual((first["file"], first["line"], first["cwe"], first["owasp_id"]),
                         ("src/db.py", 10, ["CWE-89"], "A05:2025"))
        self.assertEqual(first["fix"], "Use bind parameters.")
        self.assertIn("cur.execute", first["evidence"][0])
        self.assertEqual(second["verdict"], "needs_verification")
        self.assertEqual(second["owasp_name"], "Security Misconfiguration")
        self.assertEqual(second["repo_commit"], "abc1234")
        self.assertEqual(parsed["report"]["rule_set_source"], "https://top10.owasp.org/2025/")

    def test_fingerprints_survive_the_round_trip_unchanged_by_redaction(self):
        document = findings_document([finding("demo-001", "Hardcoded key", "a.py",
                                              snippets=['password = "hunter2hunter2"'])])
        _, result = self.render(document)
        issue = parse_report.parse(self.report_text(result), result["report"])["issues"][0]
        self.assertEqual(issue["fingerprint"], parse_report.fingerprint("demo", "Hardcoded key", "a.py"))

    def test_unreviewed_findings_survive_as_unreviewed(self):
        _, result = self.render(findings_document([finding("demo-001", "Raw hit", "a.py", verdict="unreviewed")]))
        issue = parse_report.parse(self.report_text(result), result["report"])["issues"][0]
        self.assertEqual(issue["verdict"], "unreviewed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
