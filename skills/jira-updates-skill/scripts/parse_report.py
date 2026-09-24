#!/usr/bin/env python3
"""Turn an OWASP scan report into a list of issues ready to file in a tracker.

The report is the contract between the two skills, so this parser reads the
Markdown that render_report.py produces rather than any intermediate JSON. That
keeps the document a human approved and the tickets that get filed from it the
same artifact - nobody has to wonder whether the tracker reflects the report
someone signed off on.

Two things it is careful about:

- **Rejected candidates are never returned.** They live in a per-repository
  appendix precisely because reading the code ruled them out, and filing them
  would train people to ignore the tracker.
- **Each issue gets a fingerprint** derived from the repository, the title and
  the file, and deliberately not from the line number or the report's own
  finding id. Both of those shift when unrelated code changes, and an
  idempotency key that shifts files a duplicate ticket on the next run.

Usage:
  python parse_report.py --report reports/owasp-security-report-<stamp>.md
  python parse_report.py --report <path> --out issues.json --min-severity medium
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Headings inside a repository section that hold findings look like
# "### A02:2025 - Security Misconfiguration (2)". The appendix and the
# cross-repository summary tables must not be mistaken for them.
CATEGORY_RE = re.compile(r"^###\s+(?P<id>[A-Za-z0-9:._-]+?)(?:\s+-\s+(?P<name>.*?))?\s*\((?P<count>\d+)\)\s*$")
FINDING_RE = re.compile(r"^####\s+(?P<id>[\w.-]+)\s+-\s+(?P<title>.+?)\s*$")
REPO_RE = re.compile(r"^##\s+Repository:\s*(?P<name>.+?)\s*$")
SECTION_RE = re.compile(r"^##\s+(?P<name>.+?)\s*$")
REJECTED_RE = re.compile(r"^###\s+Rejected during review", re.I)
FIELD_RE = re.compile(r"^-\s+\*\*(?P<key>[^:*]+):\*\*\s*(?P<value>.*)$")
BOLD_BLOCK_RE = re.compile(r"^\*\*(?P<name>[^*]+)\*\*\s*$")
TABLE_ROW_RE = re.compile(r"^\|\s*(?P<key>[^|]+?)\s*\|\s*(?P<value>.*?)\s*\|\s*$")

# Prose blocks under a finding, mapped to the field they populate.
BLOCK_FIELDS = {
    "evidence": "evidence",
    "why it matters": "why",
    "review notes": "review_notes",
    "recommended fix": "fix",
}

STATUS_VERDICTS = [
    ("confirmed", "confirmed"),
    ("needs verification", "needs_verification"),
    ("not yet reviewed", "unreviewed"),
    ("rejected", "rejected"),
    ("not applicable", "rejected"),
    ("accepted risk", "accepted_risk"),
]


def fingerprint(repo: str, title: str, file: str) -> str:
    """Stable identity for a finding across runs.

    Line numbers and the report's sequential finding ids both move when
    unrelated code changes, so neither belongs in the key. Repository, title and
    file together survive edits to the surrounding code, which is what makes a
    re-run update the existing ticket instead of opening a second one.
    """
    basis = "|".join([repo.strip().lower(), title.strip().lower(), file.strip().lower()])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


def normalize_verdict(status: str) -> str:
    lowered = (status or "").lower()
    for needle, verdict in STATUS_VERDICTS:
        if needle in lowered:
            return verdict
    return "unknown"


def split_location(location: str) -> tuple:
    """Pull `path:line` out of a location cell that may list extra lines."""
    match = re.search(r"`([^`]+)`", location or "")
    raw = match.group(1) if match else (location or "").strip()
    parts = raw.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return raw, None


def parse(text: str, report_path: str) -> dict:
    report = {
        "path": report_path,
        "file_name": Path(report_path).name,
        "generated_utc": "",
        "rule_set_source": "",
        "rule_set_fetched_at": "",
    }
    issues = []
    rejected = 0

    repo = None          # current repository name, None until the first repository section
    repo_meta = {}       # per-repository source and commit, keyed by name
    category = None      # (owasp_id, owasp_name)
    current = None       # finding under construction
    block = None         # which prose block we are inside
    in_rejected = False  # inside a repository's rejected appendix
    in_code = False

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        for key in ("why", "review_notes", "fix"):
            current[key] = " ".join(current[key]).strip()
        current["evidence"] = [line for line in current["evidence"] if line.strip()]
        meta = repo_meta.get(current["repo"], {})
        current["repo_source"] = meta.get("source", "")
        current["repo_commit"] = meta.get("commit", "")
        current["repo_branch"] = meta.get("branch", "")
        current["fingerprint"] = fingerprint(current["repo"], current["title"], current["file"])
        issues.append(current)
        current = None

    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            if block == "evidence":
                continue
        if in_code and block == "evidence" and current is not None:
            current["evidence"].append(line)
            continue

        repo_match = REPO_RE.match(line)
        if repo_match:
            flush()
            repo = repo_match.group("name").strip()
            repo_meta.setdefault(repo, {})
            category = None
            in_rejected = False
            block = None
            continue

        if line.startswith("## "):
            # Any other level-2 heading ends the repository scope (Method, Scope
            # and limitations, the category reference appendix).
            section = SECTION_RE.match(line)
            if section and not section.group("name").startswith("Repository:"):
                flush()
                repo = None
                category = None
                in_rejected = False
                block = None
                continue

        if REJECTED_RE.match(line):
            flush()
            in_rejected = True
            category = None
            block = None
            continue

        if line.startswith("### "):
            flush()
            block = None
            category_match = CATEGORY_RE.match(line)
            if category_match and repo and not REJECTED_RE.match(line):
                in_rejected = False
                category = (
                    category_match.group("id"),
                    (category_match.group("name") or "").strip(),
                )
            else:
                category = None
            continue

        if in_rejected:
            # Rows of the appendix table, minus its header and separator.
            row = TABLE_ROW_RE.match(line)
            if row and row.group("key") not in ("Candidate", "---") and "---" not in row.group("key"):
                rejected += 1
            continue

        finding_match = FINDING_RE.match(line)
        if finding_match and repo and category:
            flush()
            current = {
                "finding_id": finding_match.group("id"),
                "title": finding_match.group("title").strip(),
                "repo": repo,
                "owasp_id": category[0],
                "owasp_name": category[1],
                "severity": "medium",
                "confidence": "",
                "status": "",
                "verdict": "",
                "location": "",
                "file": "",
                "line": None,
                "cwe": [],
                "detector": "",
                "evidence": [],
                "why": [],
                "review_notes": [],
                "fix": [],
            }
            block = None
            continue

        field = FIELD_RE.match(line)
        if field and current is not None:
            key = field.group("key").strip().lower()
            value = field.group("value").strip()
            if key == "severity":
                # "MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review"
                severity = re.match(r"([A-Za-z]+)", value)
                if severity:
                    current["severity"] = severity.group(1).lower()
                confidence = re.search(r"\*\*Confidence:\*\*\s*([A-Za-z]+)", value)
                if confidence:
                    current["confidence"] = confidence.group(1).lower()
                status = re.search(r"\*\*Status:\*\*\s*(.+)$", value)
                if status:
                    current["status"] = status.group(1).strip()
                    current["verdict"] = normalize_verdict(current["status"])
            elif key == "location":
                current["location"] = value
                current["file"], current["line"] = split_location(value)
            elif key == "cwe":
                current["cwe"] = [item.strip() for item in value.split(",") if item.strip()]
            elif key == "detected by":
                current["detector"] = value
            continue

        bold = BOLD_BLOCK_RE.match(line)
        if bold and current is not None:
            block = BLOCK_FIELDS.get(bold.group("name").strip().lower())
            continue

        if current is not None and block in ("why", "review_notes", "fix") and line.strip():
            current[block].append(line.strip())
            continue

        # Report-level and repository-level metadata tables.
        row = TABLE_ROW_RE.match(line)
        if row:
            key = row.group("key").strip().lower()
            value = row.group("value").strip()
            if key == "generated (utc)" and not report["generated_utc"]:
                report["generated_utc"] = value
            elif key == "owasp rule set" and not report["rule_set_source"]:
                source = re.search(r"read from\s+(\S+)\s+at\s+(.+)$", value)
                if source:
                    report["rule_set_source"] = source.group(1)
                    report["rule_set_fetched_at"] = source.group(2).strip()
            elif repo and key == "source":
                repo_meta.setdefault(repo, {})["source"] = value
            elif repo and key == "commit scanned":
                commit = re.search(r"`([^`]+)`(?:\s+on\s+`([^`]+)`)?", value)
                if commit:
                    repo_meta.setdefault(repo, {})["commit"] = commit.group(1)
                    repo_meta.setdefault(repo, {})["branch"] = commit.group(2) or ""

    flush()
    return {"report": report, "issues": issues, "rejected_count": rejected}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--report", required=True, help="the OWASP scan report Markdown file")
    parser.add_argument("--out", help="write the parsed issues JSON here (default: stdout summary only)")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER,
                        help="drop findings less severe than this")
    parser.add_argument("--include-verdict", action="append", default=[], metavar="VERDICT",
                        help="only these verdicts (confirmed, needs_verification, unreviewed); "
                             "repeatable, default: all that the report lists as findings")
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.is_file():
        print(json.dumps({"ok": False, "error": "report not found: " + str(report_path)}, indent=2))
        return 1

    parsed = parse(report_path.read_text(encoding="utf-8"), str(report_path))
    issues = parsed["issues"]

    if args.min_severity:
        ceiling = SEVERITY_ORDER.index(args.min_severity)
        issues = [i for i in issues
                  if (SEVERITY_ORDER.index(i["severity"]) if i["severity"] in SEVERITY_ORDER else 9) <= ceiling]
    if args.include_verdict:
        wanted = {value.lower() for value in args.include_verdict}
        issues = [i for i in issues if i["verdict"] in wanted]

    parsed["issues"] = issues
    duplicates = {}
    for issue in issues:
        duplicates.setdefault(issue["fingerprint"], []).append(issue["finding_id"])
    collisions = {key: value for key, value in duplicates.items() if len(value) > 1}

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    by_severity = {}
    by_repo = {}
    for issue in issues:
        by_severity[issue["severity"]] = by_severity.get(issue["severity"], 0) + 1
        by_repo[issue["repo"]] = by_repo.get(issue["repo"], 0) + 1

    print(json.dumps({
        "ok": True,
        "report": parsed["report"]["file_name"],
        "generated_utc": parsed["report"]["generated_utc"],
        "issues": len(issues),
        "rejected_in_report_not_filed": parsed["rejected_count"],
        "by_severity": by_severity,
        "by_repo": by_repo,
        "fingerprint_collisions": collisions,
        "issues_json": args.out or None,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
