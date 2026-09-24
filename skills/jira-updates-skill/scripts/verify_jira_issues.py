#!/usr/bin/env python3
"""Check that every finding in a report really is in Jira.

This exists because the sync run reports its own success, and that is the weakest
possible evidence. A partial failure, a field rejected on one issue, a network
drop halfway through, or a label edited by hand all leave the tracker
disagreeing with the report while the sync output still reads mostly fine. So
this reads the report again, asks Jira what it actually holds, and compares.

It checks, per finding: an issue carries the fingerprint label, it sits under the
configured epic, its priority matches the severity, and it has a status comment
from the agent. Findings with no issue are reported as missing, which is the
signal to re-run the sync.

Exit status is 0 only when nothing is missing, so a pipeline can gate on it.

Usage:
  python verify_jira_issues.py --report reports/owasp-security-report-<stamp>.md
  python verify_jira_issues.py --report <path> --out verification.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import jira_client as jc  # noqa: E402
import parse_report  # noqa: E402
import sync_jira_issues as sync  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--report", required=True, help="the OWASP scan report that was filed")
    parser.add_argument("--env", default="", help="path to the .env file")
    parser.add_argument("--min-severity", choices=parse_report.SEVERITY_ORDER,
                        help="use the same filter the sync run used")
    parser.add_argument("--include-verdict", action="append", default=[],
                        help="use the same filter the sync run used")
    parser.add_argument("--skip-comment-check", action="store_true",
                        help="do not fetch comments (one fewer API call per issue)")
    parser.add_argument("--out", default="", help="write the verification JSON here")
    args = parser.parse_args()

    config = jc.load_config(args.env)
    missing_config = jc.missing_config(config)
    if missing_config:
        print(json.dumps({"ok": False, "error": "Jira configuration incomplete",
                          "missing": missing_config}, indent=2))
        return 2

    report_path = Path(args.report)
    if not report_path.is_file():
        print(json.dumps({"ok": False, "error": "report not found: " + str(report_path)}, indent=2))
        return 2

    parsed = parse_report.parse(report_path.read_text(encoding="utf-8"), str(report_path))
    issues = parsed["issues"]
    if args.min_severity:
        ceiling = parse_report.SEVERITY_ORDER.index(args.min_severity)
        issues = [i for i in issues
                  if (parse_report.SEVERITY_ORDER.index(i["severity"])
                      if i["severity"] in parse_report.SEVERITY_ORDER else 9) <= ceiling]
    if args.include_verdict:
        wanted = {value.lower() for value in args.include_verdict}
        issues = [i for i in issues if i["verdict"] in wanted]

    client = jc.JiraClient(config)
    try:
        client.myself()
        result = verify(client, config, issues, parsed["report"],
                        check_comments=not args.skip_comment_check)
    except jc.JiraError as error:
        print(json.dumps({"ok": False, "error": jc.redact(str(error)), "status_code": error.status}, indent=2))
        return 2

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def verify(client, config: dict, issues: list, report: dict, check_comments: bool = True) -> dict:
    """Compare the report's findings against what Jira actually holds."""
    meta = client.create_meta()
    fields = {field.get("fieldId"): field for field in meta["fields"]}
    priorities = [value.get("name") for value in fields.get("priority", {}).get("allowedValues", [])]
    existing = sync.find_existing(client, config, issues) if issues else {}

    checks = []
    missing = []
    for issue in issues:
        key_label = sync.fingerprint_label(issue, config)
        match = existing.get(key_label)
        record = {
            "finding_id": issue["finding_id"],
            "fingerprint": issue["fingerprint"],
            "title": issue["title"],
            "severity": issue["severity"],
            "fingerprint_label": key_label,
        }
        if match is None:
            record["present"] = False
            record["problems"] = ["no Jira issue carries the label " + key_label]
            missing.append(record)
            checks.append(record)
            continue

        problems = []
        issue_fields = match.get("fields", {})
        record["present"] = True
        record["key"] = match["key"]
        record["status"] = (issue_fields.get("status") or {}).get("name")

        expected_priority = jc.resolve_priority(issue["severity"], priorities,
                                                config.get("priority_override", {}))
        actual_priority = (issue_fields.get("priority") or {}).get("name")
        record["priority"] = actual_priority
        if expected_priority and actual_priority and expected_priority != actual_priority:
            problems.append("priority is " + actual_priority + ", expected "
                            + expected_priority + " for severity " + issue["severity"])

        if config.get("epic"):
            parent = (issue_fields.get("parent") or {}).get("key")
            record["parent"] = parent
            if parent and parent != config["epic"]:
                problems.append("parent is " + parent + ", expected epic " + config["epic"])
            elif not parent:
                # A company-managed project may hold the link in a custom field
                # instead, which this listing does not return; report rather than
                # guess, so nobody reads a blank as a failure.
                problems.append("no parent returned; if this project uses the Epic Link custom field, "
                                "confirm the epic link in the Jira UI")

        if check_comments:
            try:
                comments = client.comments(match["key"])
                agent_comments = [comment for comment in comments if sync.is_agent_comment(comment)]
                record["agent_comments"] = len(agent_comments)
                if not agent_comments:
                    problems.append("no status comment from the agent found on this issue")
                else:
                    unstruck = [comment for comment in agent_comments
                                if not sync.is_struck(comment.get("body", {}))]
                    record["current_comments"] = len(unstruck)
                    if len(unstruck) > 1:
                        problems.append(str(len(unstruck)) + " agent comments are not struck through; "
                                        "only the latest should read as current")
            except jc.JiraError as error:
                problems.append("could not read comments: " + jc.redact(str(error)))

        record["problems"] = problems
        checks.append(record)

    inconsistent = [record for record in checks if record.get("present") and record["problems"]]
    result = {
        "ok": not missing and not inconsistent,
        "report": report["file_name"],
        "findings_expected": len(issues),
        "issues_found": len([record for record in checks if record.get("present")]),
        "missing": len(missing),
        "inconsistent": len(inconsistent),
        "api_calls": client.calls,
        "missing_findings": [{"finding_id": r["finding_id"], "title": r["title"],
                              "fingerprint": r["fingerprint"]} for r in missing],
        "inconsistencies": [{"key": r["key"], "finding_id": r["finding_id"], "problems": r["problems"]}
                            for r in inconsistent],
        "checks": checks,
    }
    if missing:
        result["next_step"] = ("re-run sync_jira_issues.py with the same report and filters; it will file only "
                              "the missing findings. If they still do not appear, the per-finding error in the "
                              "sync output says why.")
    return result


if __name__ == "__main__":
    sys.exit(main())
