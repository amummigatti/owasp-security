#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Tests for jira-updates-skill against an in-memory Jira.

The behaviour worth protecting here is idempotency: running the sync twice must
not open a second ticket for the same finding, and the second run must leave the
older status comment struck through so only the latest reads as current. That is
hard to check by hand against a real instance (you would have to file and then
clean up real tickets), and easy to check against a fake that records what the
skill sent.

Run:  python -m unittest discover -s tests -v
      python tests/test_jira_updates_skill.py
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "jira-updates-skill" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import jira_client as jc  # noqa: E402
import parse_report  # noqa: E402
import sync_jira_issues as sync  # noqa: E402
import verify_jira_issues  # noqa: E402

API = "/rest/api/3"

REPORT = """# OWASP Security Scan Report

| Field | Value |
| --- | --- |
| Generated (UTC) | 2026-09-24T04:04:51+00:00 |
| Repositories in scope | 1 |
| OWASP rule set | read from https://top10.owasp.org/2025/ at 2026-09-24T03:57:56+00:00 |

## Executive summary

| Repository | Commit | Files | Critical | High | Medium | Low | Reported | Rejected |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| demo-app | `abc1234` | 10 | 1 | 0 | 1 | 0 | 2 | 1 |

### Findings by OWASP category

| Category | Critical | High | Medium | Low | Total |
| --- | --- | --- | --- | --- | --- |
| A05:2025 Injection | 1 | 0 | 0 | 0 | 1 |

## Repository: demo-app

| Field | Value |
| --- | --- |
| Source | https://example.invalid/demo-app |
| Commit scanned | `abc1234` on `main` (2026-09-20T10:00:00+00:00) |
| Files scanned | 10 |

### A05:2025 - Injection (1)

#### demo-app-001 - SQL statement assembled from a string

- **Severity:** CRITICAL  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `src/db.py:42` (also line 51)
- **CWE:** CWE-89
- **Detected by:** pattern

**Evidence**

```text
cur.execute("SELECT * FROM t WHERE id = " + request.args["id"])
```

**Why it matters**

Untrusted input becomes part of the statement the database parses.

**Review notes**

Reached from an unauthenticated route.

**Recommended fix**

Use bind parameters.

### A02:2025 - Security Misconfiguration (1)

#### demo-app-002 - Debug mode enabled

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Needs verification (requires a running instance)
- **Location:** `src/settings.py:7`
- **CWE:** CWE-489
- **Detected by:** pattern

**Why it matters**

Debug handlers expose stack traces.

**Recommended fix**

Drive the flag from the environment.

### Rejected during review (1)

Candidates the pattern scan raised that reading the code ruled out.

| Candidate | Location | Reason |
| --- | --- | --- |
| Broken hash algorithm (MD5 / SHA-1) | `src/cache.py:3` | Used for cache keys, not security. |

## Method

1. Something about the method.

## Scope and limitations

- A static review of one commit.
"""


def adf_violations(node, found=None):
    """Rules of Atlassian's document schema that real Jira enforces with a 400.

    Learned the hard way: the first real re-run failed on every issue because a
    struck-through comment still carried the code mark, and the fake accepted it.
    """
    found = [] if found is None else found
    if isinstance(node, list):
        for item in node:
            adf_violations(item, found)
    elif isinstance(node, dict):
        marks = [mark.get("type") for mark in node.get("marks", [])]
        if node.get("type") == "text":
            if "code" in marks and len(marks) > 1:
                found.append("code mark combined with " + ", ".join(m for m in marks if m != "code"))
            if not node.get("text"):
                found.append("empty text node")
        elif marks:
            found.append("marks on a non-text node: " + str(node.get("type")))
        if node.get("type") == "codeBlock":
            for child in node.get("content", []):
                if child.get("marks"):
                    found.append("marks inside a codeBlock")
        adf_violations(node.get("content", []), found)
    return found


class FakeJira:
    """Minimal stand-in for the Jira Cloud REST API, recording what it is sent."""

    def __init__(self, with_priority=True):
        self.with_priority = with_priority
        self.issues = {}
        self.counter = 1
        self.comment_counter = 0
        self.created_payloads = []
        self.requests = []

    def handle(self, method, path, body=None, params=None, allow_status=()):
        self.requests.append((method, path))

        if path == API + "/myself":
            return 200, {"displayName": "Test User", "accountId": "acct-1"}
        if path.startswith(API + "/project/"):
            return 200, {"key": "AI", "name": "AI", "id": "10000"}
        if path == API + "/issue/createmeta/AI/issuetypes":
            return 200, {"issueTypes": [{"id": "10004", "name": "Bug"}, {"id": "10001", "name": "Task"}]}
        if path == API + "/issue/createmeta/AI/issuetypes/10004":
            fields = [
                {"fieldId": "summary", "name": "Summary", "required": True},
                {"fieldId": "description", "name": "Description", "required": False},
                {"fieldId": "labels", "name": "Labels", "required": False},
                {"fieldId": "parent", "name": "Parent", "required": False},
                {"fieldId": "priority", "name": "Priority", "required": False,
                 "allowedValues": [{"id": "1", "name": "Highest"}, {"id": "2", "name": "High"},
                                   {"id": "3", "name": "Medium"}, {"id": "4", "name": "Low"},
                                   {"id": "5", "name": "Lowest"}]},
            ]
            if not self.with_priority:
                fields = [f for f in fields if f["fieldId"] != "priority"]
            return 200, {"fields": fields}
        if path == API + "/search/jql":
            wanted = set(re.findall(r'"([^"]+)"', (body or {}).get("jql", "")))
            found = []
            for key, issue in self.issues.items():
                if set(issue["fields"].get("labels", [])) & wanted:
                    found.append({"key": key, "fields": {
                        "summary": issue["fields"].get("summary"),
                        "labels": issue["fields"].get("labels", []),
                        "priority": issue["fields"].get("priority"),
                        "status": {"name": "To Do"},
                        "parent": issue["fields"].get("parent"),
                    }})
            return 200, {"issues": found}
        if path == API + "/issue" and method == "POST":
            self.counter += 1
            key = "AI-" + str(self.counter)
            problems = adf_violations(body["fields"].get("description", {}))
            if problems:
                raise jc.JiraError(400, ["INVALID_INPUT: " + "; ".join(problems)], path)
            self.created_payloads.append(body["fields"])
            self.issues[key] = {"fields": dict(body["fields"]), "comments": []}
            return 201, {"key": key, "id": str(1000 + self.counter)}

        comment_match = re.match(re.escape(API) + r"/issue/([\w-]+)/comment(?:/(\d+))?$", path)
        if comment_match:
            key, comment_id = comment_match.group(1), comment_match.group(2)
            issue = self.issues[key]
            if method == "GET":
                return 200, {"comments": issue["comments"]}
            problems = adf_violations(body["body"]) if method in ("POST", "PUT") else []
            if problems:
                raise jc.JiraError(400, ["INVALID_INPUT: " + "; ".join(problems)], path)
            if method == "POST":
                self.comment_counter += 1
                comment = {"id": str(self.comment_counter), "body": body["body"],
                           "author": {"accountId": "acct-1"}}
                issue["comments"].append(comment)
                return 201, comment
            if method == "PUT":
                for comment in issue["comments"]:
                    if comment["id"] == comment_id:
                        comment["body"] = body["body"]
                        return 200, comment
                raise AssertionError("comment not found: " + comment_id)

        issue_match = re.match(re.escape(API) + r"/issue/([\w-]+)$", path)
        if issue_match and method == "PUT":
            self.issues[issue_match.group(1)]["fields"].update(body["fields"])
            return 204, {}

        raise AssertionError("unhandled request: " + method + " " + path)


CONFIG = {
    "base_url": "https://example.atlassian.net",
    "email": "user@example.invalid",
    "token": "fake-token-value-1234567890",
    "project": "AI",
    "issue_type": "Bug",
    "epic": "AI-1",
    "auth_type": "basic",
    "label_prefix": "owasp",
    "extra_labels": [],
    "env_file": "",
    "env_file_found": False,
}


def run_sync(fake, parsed, dry_run=False):
    client = jc.JiraClient(CONFIG, dry_run=dry_run)
    client._request = fake.handle  # noqa: SLF001 - substituting the transport is the point
    client.myself()
    checks = sync.preflight(client, CONFIG)
    assert not checks["problems"], checks["problems"]
    return checks, sync.sync(client, CONFIG, parsed, checks, "owasp-security-agent")


class ParseReportTests(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_report.parse(REPORT, "reports/demo.md")

    def test_finds_only_reported_findings(self):
        self.assertEqual(len(self.parsed["issues"]), 2)
        self.assertEqual(self.parsed["rejected_count"], 1)
        titles = [issue["title"] for issue in self.parsed["issues"]]
        self.assertNotIn("Broken hash algorithm (MD5 / SHA-1)", titles)

    def test_extracts_fields(self):
        issue = self.parsed["issues"][0]
        self.assertEqual(issue["finding_id"], "demo-app-001")
        self.assertEqual(issue["severity"], "critical")
        self.assertEqual(issue["verdict"], "confirmed")
        self.assertEqual(issue["owasp_id"], "A05:2025")
        self.assertEqual(issue["owasp_name"], "Injection")
        self.assertEqual(issue["file"], "src/db.py")
        self.assertEqual(issue["line"], 42)
        self.assertEqual(issue["cwe"], ["CWE-89"])
        self.assertIn("database parses", issue["why"])
        self.assertIn("bind parameters", issue["fix"])
        self.assertIn('cur.execute("SELECT', issue["evidence"][0])
        self.assertEqual(issue["repo_commit"], "abc1234")
        self.assertEqual(issue["repo_branch"], "main")

    def test_needs_verification_verdict(self):
        issue = self.parsed["issues"][1]
        self.assertEqual(issue["verdict"], "needs_verification")

    def test_fingerprint_ignores_line_and_finding_id(self):
        moved = REPORT.replace("`src/db.py:42`", "`src/db.py:99`").replace("demo-app-001", "demo-app-077")
        again = parse_report.parse(moved, "reports/demo.md")
        self.assertEqual(self.parsed["issues"][0]["fingerprint"], again["issues"][0]["fingerprint"])

    def test_fingerprint_differs_per_file_and_repo(self):
        other = parse_report.fingerprint("demo-app", "Same title", "a.py")
        self.assertNotEqual(other, parse_report.fingerprint("demo-app", "Same title", "b.py"))
        self.assertNotEqual(other, parse_report.fingerprint("other-app", "Same title", "a.py"))


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeJira()
        self.parsed = parse_report.parse(REPORT, "reports/demo.md")

    def test_first_run_creates_issues_with_expected_fields(self):
        _, outcome = run_sync(self.fake, self.parsed)
        self.assertTrue(all(record["ok"] for record in outcome["results"]))
        self.assertEqual([r["action"] for r in outcome["results"]], ["created", "created"])
        self.assertEqual(len(self.fake.issues), 2)

        critical = self.fake.created_payloads[0]
        self.assertNotIn("priority", critical, "priority is deliberately never set; severity is a label")
        self.assertEqual(critical["parent"], {"key": "AI-1"})
        self.assertEqual(critical["issuetype"], {"id": "10004"})
        self.assertEqual(critical["project"], {"key": "AI"})
        self.assertEqual(critical["summary"], "[demo-app] [src/db] - SQL statement assembled from a string")
        self.assertEqual(self.fake.created_payloads[1]["summary"], "[demo-app] [src/settings] - Debug mode enabled")
        self.assertLessEqual(len(critical["summary"]), 250)

        labels = critical["labels"]
        self.assertIn("owasp", labels)
        self.assertIn("security", labels)
        self.assertIn("owasp-a05-2025", labels)
        self.assertIn("severity-critical", labels)
        self.assertIn("cwe-89", labels)
        self.assertIn("repo-demo-app", labels)
        self.assertTrue(any(item.startswith("owasp-fp-") for item in labels))
        for item in labels:
            self.assertNotIn(" ", item)

        medium = self.fake.created_payloads[1]
        self.assertNotIn("priority", medium)
        self.assertIn("severity-medium", medium["labels"])
        self.assertIn("owasp-needs-verification", medium["labels"])

    def test_description_has_current_issue_and_expected_fix(self):
        run_sync(self.fake, self.parsed)
        body = jc.plain_text(self.fake.created_payloads[0]["description"])
        for expected in ["Current issue", "Expected fix", "Evidence", "Classification", "Provenance",
                         "bind parameters", "CWE-89", "demo-app-001", "abc1234"]:
            self.assertIn(expected, body)

    def test_first_run_adds_agent_comment_with_date(self):
        run_sync(self.fake, self.parsed)
        comments = self.fake.issues["AI-2"]["comments"]
        self.assertEqual(len(comments), 1)
        text = jc.plain_text(comments[0]["body"])
        self.assertIn("Logged by owasp-security-agent on ", text)
        self.assertIn(sync.MARKER, text)
        self.assertFalse(sync.is_struck(comments[0]["body"]))

    def test_second_run_files_no_duplicates_and_strikes_previous_comment(self):
        run_sync(self.fake, self.parsed)
        created_after_first = len(self.fake.issues)

        _, outcome = run_sync(self.fake, self.parsed)
        self.assertEqual(len(self.fake.issues), created_after_first, "second run must not create issues")
        self.assertTrue(all(record["ok"] for record in outcome["results"]))
        self.assertNotIn("created", [record["action"] for record in outcome["results"]])

        comments = self.fake.issues["AI-2"]["comments"]
        self.assertEqual(len(comments), 2)
        self.assertTrue(sync.is_struck(comments[0]["body"]), "previous comment should be struck through")
        self.assertFalse(sync.is_struck(comments[1]["body"]), "latest comment should read as current")
        latest = jc.plain_text(comments[1]["body"])
        self.assertIn("Still present as of ", latest)
        self.assertEqual(outcome["results"][0]["comments_struck"], 1)

    def test_third_run_keeps_exactly_one_current_comment(self):
        run_sync(self.fake, self.parsed)
        run_sync(self.fake, self.parsed)
        run_sync(self.fake, self.parsed)
        comments = self.fake.issues["AI-2"]["comments"]
        self.assertEqual(len(comments), 3)
        unstruck = [comment for comment in comments if not sync.is_struck(comment["body"])]
        self.assertEqual(len(unstruck), 1)

    def test_severity_change_swaps_the_severity_label_and_is_noted(self):
        run_sync(self.fake, self.parsed)
        raised = REPORT.replace("- **Severity:** MEDIUM", "- **Severity:** HIGH")
        _, outcome = run_sync(self.fake, parse_report.parse(raised, "reports/demo.md"))
        record = [r for r in outcome["results"] if r["finding_id"] == "demo-app-002"][0]
        self.assertIn("severity medium -> high", record["changes"])
        labels = self.fake.issues["AI-3"]["fields"]["labels"]
        self.assertIn("severity-high", labels)
        self.assertNotIn("severity-medium", labels, "the old severity label must be replaced, not kept")
        self.assertEqual(len([item for item in labels if item.startswith("severity-")]), 1)
        self.assertNotIn("priority", self.fake.issues["AI-3"]["fields"])
        latest = jc.plain_text(self.fake.issues["AI-3"]["comments"][-1]["body"])
        self.assertIn("severity medium -> high", latest)

    def test_unchanged_severity_leaves_labels_alone(self):
        run_sync(self.fake, self.parsed)
        before = list(self.fake.issues["AI-2"]["fields"]["labels"])
        _, outcome = run_sync(self.fake, self.parsed)
        self.assertEqual(self.fake.issues["AI-2"]["fields"]["labels"], before)
        self.assertEqual(outcome["results"][0]["changes"], [])

    def test_dry_run_writes_nothing(self):
        run_sync(self.fake, self.parsed, dry_run=True)
        self.assertEqual(len(self.fake.issues), 0)
        self.assertNotIn("POST", [method for method, path in self.fake.requests if path == API + "/issue"])

    def test_human_comments_are_never_struck(self):
        run_sync(self.fake, self.parsed)
        human = {"id": "900", "body": jc.document(jc.paragraph("I am looking at this, please leave it alone.")),
                 "author": {"accountId": "acct-2"}}
        self.fake.issues["AI-2"]["comments"].append(human)
        run_sync(self.fake, self.parsed)
        kept = [c for c in self.fake.issues["AI-2"]["comments"] if c["id"] == "900"][0]
        self.assertFalse(sync.is_struck(kept["body"]))
        self.assertIn("leave it alone", jc.plain_text(kept["body"]))


class PriorityIsIgnoredTests(unittest.TestCase):
    """The Priority field is never read or written; severity is carried by a label."""

    def setUp(self):
        self.parsed = parse_report.parse(REPORT, "reports/demo.md")

    def _sync_against(self, fake):
        client = jc.JiraClient(CONFIG)
        client._request = fake.handle  # noqa: SLF001
        checks = sync.preflight(client, CONFIG)
        outcome = sync.sync(client, CONFIG, self.parsed, checks, "owasp-security-agent")
        return checks, outcome

    def test_screen_without_a_priority_field_is_not_a_problem(self):
        fake = FakeJira(with_priority=False)
        checks, outcome = self._sync_against(fake)
        self.assertEqual(checks["problems"], [])
        self.assertTrue(all(record["ok"] for record in outcome["results"]))
        for payload in fake.created_payloads:
            self.assertNotIn("priority", payload)

    def test_screen_with_a_priority_field_is_still_not_written_to(self):
        fake = FakeJira(with_priority=True)
        checks, outcome = self._sync_against(fake)
        self.assertEqual(checks["problems"], [])
        for payload in fake.created_payloads:
            self.assertNotIn("priority", payload)

    def test_no_priority_label_is_invented(self):
        fake = FakeJira(with_priority=False)
        self._sync_against(fake)
        for payload in fake.created_payloads:
            self.assertFalse([item for item in payload["labels"] if item.startswith("priority-")])
            self.assertTrue([item for item in payload["labels"] if item.startswith("severity-")])

    def test_severity_is_stated_in_the_description(self):
        fake = FakeJira(with_priority=False)
        self._sync_against(fake)
        body = jc.plain_text(fake.created_payloads[0]["description"])
        self.assertIn("Severity: critical", body)


class SummaryFormatTests(unittest.TestCase):
    """Summaries must read as: [repo name] [component] - Summary sentence."""

    def component(self, path, repo="open-webui"):
        return sync.derive_component(path, repo)

    def test_component_is_top_directory_plus_module(self):
        self.assertEqual(self.component("backend/open_webui/routers/auths.py"), "backend/auths")
        self.assertEqual(self.component("backend/open_webui/env.py"), "backend/env")
        self.assertEqual(self.component("src/lib/components/chat/Chat.svelte"), "src/Chat")

    def test_generic_file_names_use_the_enclosing_directory(self):
        self.assertEqual(self.component("src/routes/auth/+page.svelte"), "src/auth")
        self.assertEqual(self.component("backend/open_webui/main.py"), "backend")
        self.assertEqual(self.component("web/widgets/index.ts", repo="shop"), "web/widgets")

    def test_root_level_files_are_named_by_the_file(self):
        self.assertEqual(self.component("Dockerfile"), "Dockerfile")
        self.assertEqual(self.component("docker-compose.otel.yaml"), "docker-compose.otel")

    def test_dot_directories_and_windows_paths(self):
        self.assertEqual(self.component(".github/workflows/regression.yaml"), ".github/regression")
        self.assertEqual(self.component("backend\\open_webui\\env.py"), "backend/env")

    def test_empty_path_falls_back_to_general(self):
        self.assertEqual(self.component(""), "general")

    def test_summary_shape(self):
        issue = {"repo": "open-webui", "file": "backend/open_webui/env.py",
                 "title": "Auth cookie Secure flag defaults to off"}
        self.assertEqual(sync.build_summary(issue),
                         "[open-webui] [backend/env] - Auth cookie Secure flag defaults to off")

    def test_brackets_in_names_cannot_break_the_format(self):
        issue = {"repo": "we[ir]d", "file": "a[1]/b.py", "title": "Something"}
        summary = sync.build_summary(issue)
        self.assertTrue(summary.startswith("[weird] [a1/b] - "), summary)

    def test_long_titles_are_truncated_to_jiras_limit(self):
        issue = {"repo": "r", "file": "a/b.py", "title": "x" * 400}
        summary = sync.build_summary(issue)
        self.assertLessEqual(len(summary), 250)
        self.assertTrue(summary.startswith("[r] [a/b] - "))

    def test_every_finding_in_the_real_report_gets_a_wellformed_summary(self):
        report = Path(__file__).resolve().parent.parent / "reports" / "owasp-security-report-20260924-040451Z.md"
        if not report.is_file():
            self.skipTest("sample report not present")
        parsed = parse_report.parse(report.read_text(encoding="utf-8"), str(report))
        self.assertGreater(len(parsed["issues"]), 0)
        for issue in parsed["issues"]:
            self.assertRegex(sync.build_summary(issue), r"^\[[^\[\]]+\] \[[^\[\]]+\] - \S")


class VerificationTests(unittest.TestCase):
    """The verification phase must catch a tracker that disagrees with the report."""

    def setUp(self):
        self.fake = FakeJira()
        self.parsed = parse_report.parse(REPORT, "reports/demo.md")

    def _verify(self):
        client = jc.JiraClient(CONFIG)
        client._request = self.fake.handle  # noqa: SLF001
        return verify_jira_issues.verify(client, CONFIG, self.parsed["issues"], self.parsed["report"])

    def test_passes_after_a_successful_sync(self):
        run_sync(self.fake, self.parsed)
        result = self._verify()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["findings_expected"], 2)
        self.assertEqual(result["issues_found"], 2)
        self.assertEqual(result["missing"], 0)

    def test_reports_a_finding_that_was_never_filed(self):
        run_sync(self.fake, self.parsed)
        # Simulate a sync that failed partway: drop one issue from the tracker.
        del self.fake.issues["AI-3"]
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"], 1)
        self.assertEqual(result["missing_findings"][0]["finding_id"], "demo-app-002")
        self.assertIn("re-run sync_jira_issues.py", result["next_step"])

    def test_detects_a_wrong_severity_label(self):
        run_sync(self.fake, self.parsed)
        labels = self.fake.issues["AI-2"]["fields"]["labels"]
        self.fake.issues["AI-2"]["fields"]["labels"] = [
            "severity-low" if item == "severity-critical" else item for item in labels]
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"], 0)
        self.assertEqual(result["inconsistent"], 1)
        self.assertIn("severity label severity-critical is missing", result["inconsistencies"][0]["problems"][0])

    def test_detects_conflicting_severity_labels(self):
        run_sync(self.fake, self.parsed)
        self.fake.issues["AI-2"]["fields"]["labels"].append("severity-low")
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("conflicting severity labels" in problem
                            for problem in result["inconsistencies"][0]["problems"]))

    def test_priority_is_not_checked(self):
        run_sync(self.fake, self.parsed)
        self.fake.issues["AI-2"]["fields"]["priority"] = {"name": "Lowest"}
        self.assertTrue(self._verify()["ok"])

    def test_detects_issue_moved_out_of_the_epic(self):
        run_sync(self.fake, self.parsed)
        self.fake.issues["AI-2"]["fields"]["parent"] = {"key": "AI-99"}
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("expected epic AI-1" in problem
                            for problem in result["inconsistencies"][0]["problems"]))

    def test_detects_a_missing_agent_comment(self):
        run_sync(self.fake, self.parsed)
        self.fake.issues["AI-2"]["comments"] = []
        result = self._verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("no status comment" in problem
                            for problem in result["inconsistencies"][0]["problems"]))


class SafetyTests(unittest.TestCase):
    def test_token_is_redacted_from_messages(self):
        jc.remember_secret("fake-token-value-1234567890")
        message = jc.redact("request failed with token fake-token-value-1234567890 in it")
        self.assertNotIn("fake-token-value-1234567890", message)
        self.assertIn("<redacted>", message)

    def test_auth_header_is_redacted(self):
        self.assertNotIn("abcdefghijklmnop", jc.redact("Authorization: Basic abcdefghijklmnop"))

    def test_error_body_is_redacted(self):
        jc.remember_secret("fake-token-value-1234567890")
        messages = jc.JiraClient._error_messages(  # noqa: SLF001
            json.dumps({"errorMessages": ["bad token fake-token-value-1234567890"]}))
        self.assertNotIn("fake-token-value-1234567890", " ".join(messages))

    def test_base_url_normalisation_strips_ui_paths(self):
        self.assertEqual(jc.normalize_base_url("https://site.atlassian.net/jira/software/projects/AI"),
                         "https://site.atlassian.net")
        self.assertEqual(jc.normalize_base_url("site.atlassian.net"), "https://site.atlassian.net")

    def test_issue_key_normalisation_accepts_urls(self):
        self.assertEqual(jc.normalize_issue_key("https://site.atlassian.net/browse/AI-1"), "AI-1")
        self.assertEqual(jc.normalize_issue_key("ai-1"), "AI-1")

    def test_missing_config_reports_email_for_basic_auth(self):
        config = dict(CONFIG, email="")
        self.assertIn("JIRA_EMAIL", jc.missing_config(config))

    def test_strike_leaves_code_blocks_alone(self):
        doc = jc.document(jc.paragraph("text"), jc.code_block("secret_code()"))
        struck = jc.strike_document(doc)
        self.assertIn("strike", json.dumps(struck["content"][0]))
        self.assertNotIn("strike", json.dumps(struck["content"][1]))

    def test_struck_comment_is_valid_for_jira(self):
        # The comment the skill posts ends with a code-styled run marker.
        issue = {"finding_id": "x-1", "title": "t", "file": "a.py", "line": 1, "severity": "low",
                 "fingerprint": "abc", "status": "Confirmed by review", "repo_commit": "c"}
        comment = sync.build_comment(issue, {"file_name": "r.md", "generated_utc": "u"}, "agent", True, [])
        self.assertEqual(adf_violations(comment), [])
        struck = jc.strike_document(comment)
        self.assertEqual(adf_violations(struck), [], "striking must not produce a schema violation")
        self.assertTrue(sync.is_struck(struck))
        self.assertIn(sync.MARKER, jc.plain_text(struck), "a struck comment must still be recognisable as ours")

    def test_fake_rejects_what_real_jira_rejects(self):
        bad = jc.document(jc.paragraph(jc.text("marker", marks=["code", "strike"])))
        self.assertTrue(adf_violations(bad))

    def test_no_priority_machinery_remains(self):
        self.assertFalse(hasattr(jc, "resolve_priority"))
        self.assertFalse(hasattr(jc, "PRIORITY_CANDIDATES"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
