#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""File the findings from an OWASP scan report as Jira issues, idempotently.

Run it twice on the same report and the second run files nothing: it finds the
issue it created the first time, leaves it where it is, strikes through the
status comment it left last time and adds a fresh one carrying the new run date.
That property is what makes it safe to wire into a pipeline, because a security
report that opens duplicate tickets every night gets muted within a week.

Identity comes from a fingerprint label on the issue (repository + title + file),
not from the report's finding ids, which renumber, and not from a local state
file, which would not survive a fresh clone or a different machine. Jira itself
is the state.

Before writing anything it checks what the project demands: that the issue type
exists, that labels can be set (without them there is no idempotency), which
and whether any required field is one this skill
cannot fill. It would rather stop with a precise explanation than file half a
report.

Usage:
  python sync_jira_issues.py --report reports/owasp-security-report-<stamp>.md --dry-run
  python sync_jira_issues.py --report <path>
  python sync_jira_issues.py --report <path> --min-severity high
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import jira_client as jc  # noqa: E402
import parse_report  # noqa: E402

SEVERITY_ORDER = parse_report.SEVERITY_ORDER
MARKER = "owasp-sync"
FIELDS_WE_OWN = ("labels",)


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def label(value: str) -> str:
    """Jira labels cannot contain spaces; keep them lowercase and plain."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-").lower()
    return cleaned[:60]


def build_labels(issue: dict, config: dict) -> list:
    prefix = label(config.get("label_prefix") or "owasp")
    labels = [
        prefix,
        "security",
        label(prefix + "-" + issue["owasp_id"]),
        severity_label(issue),
        label("repo-" + issue["repo"]),
        fingerprint_label(issue, config),
    ]
    labels += [label(cwe) for cwe in issue.get("cwe", [])]
    if issue.get("verdict") == "needs_verification":
        labels.append(label(prefix + "-needs-verification"))
    labels += [label(extra) for extra in config.get("extra_labels", [])]
    seen = []
    for item in labels:
        if item and item not in seen:
            seen.append(item)
    return seen


SEVERITY_LABELS = {"severity-" + name for name in jc.SEVERITIES}


def severity_label(issue: dict) -> str:
    return label("severity-" + issue["severity"])


def fingerprint_label(issue: dict, config: dict) -> str:
    prefix = label(config.get("label_prefix") or "owasp")
    return prefix + "-fp-" + issue["fingerprint"]


# Files whose name says nothing about what they are (index.ts, main.py,
# +page.svelte); for these the enclosing directory names the component instead.
GENERIC_STEMS = {"index", "main", "__init__", "app", "mod", "init", "+page", "+layout"}
GENERIC_DIRS = {"src", "lib", "app", "source", "pkg", "internal"}


def derive_component(file_path: str, repo: str) -> str:
    """Name the part of the codebase a finding lives in, from its file path.

    The report records where a finding is but not which component it belongs to,
    and a summary of "[repo] [component]" is only useful if the component reads as
    a place a team recognises. The rule is the top-level directory plus the module
    name: backend/open_webui/routers/auths.py -> "backend/auths". It stays
    deterministic on purpose, so the same finding gets the same component on every
    run and the summary never churns between runs.

    A file at the repository root has no directory to lean on, so it is named by
    the file itself (Dockerfile, docker-compose.otel).
    """
    parts = [part for part in re.split(r"[\\/]+", file_path or "") if part and part != "."]
    if not parts:
        return "general"
    name = parts[-1]
    stem = Path(name).stem or name
    if len(parts) == 1:
        return stem

    top = parts[0]
    repo_key = re.sub(r"[^a-z0-9]", "", (repo or "").lower())
    if stem.lower() in GENERIC_STEMS:
        for directory in reversed(parts[1:-1]):
            if re.sub(r"[^a-z0-9]", "", directory.lower()) == repo_key or directory.lower() in GENERIC_DIRS:
                continue
            stem = directory
            break
        else:
            return top
    return top + "/" + stem


def build_summary(issue: dict) -> str:
    """Summary in the form: [repo name] [component] - Summary sentence.

    Repository and component come first so a backlog list can be scanned and
    sorted by where the problem is; the OWASP category and severity live in labels,
    where they can be filtered on without cluttering the line.
    """
    def clean(value: str) -> str:
        return re.sub(r"[\[\]]", "", str(value)).strip()

    prefix = "[" + clean(issue["repo"]) + "] [" + clean(derive_component(issue.get("file", ""), issue["repo"])) + "] - "
    return prefix + issue["title"][:max(0, 250 - len(prefix))].strip()


def build_description(issue: dict, report: dict, agent: str, config: dict) -> dict:
    where = [
        "Repository: " + issue["repo"] + ((" (" + issue["repo_source"] + ")") if issue.get("repo_source") else ""),
        "Commit scanned: " + (issue.get("repo_commit") or "unknown")
        + ((" on " + issue["repo_branch"]) if issue.get("repo_branch") else ""),
        "Location: " + issue["file"] + ((":" + str(issue["line"])) if issue.get("line") else ""),
    ]
    classification = [
        "OWASP category: " + issue["owasp_id"] + (" " + issue["owasp_name"] if issue["owasp_name"] else ""),
        "CWE: " + (", ".join(issue.get("cwe", [])) or "not mapped"),
        "Severity: " + issue["severity"] + "  |  Confidence: " + (issue.get("confidence") or "unstated"),
        "Review status: " + (issue.get("status") or "unstated"),
        "Detected by: " + (issue.get("detector") or "unstated"),
    ]
    provenance = [
        "Report: " + report["file_name"],
        "Report generated (UTC): " + (report.get("generated_utc") or "unknown"),
        "OWASP rule set: " + (report.get("rule_set_source") or "unknown")
        + (" read at " + report["rule_set_fetched_at"] if report.get("rule_set_fetched_at") else ""),
        "Finding id in report: " + issue["finding_id"],
        "Fingerprint: " + issue["fingerprint"],
    ]

    blocks = [
        jc.heading("Current issue"),
        jc.paragraph(issue.get("why") or issue["title"]),
    ]
    if issue.get("review_notes"):
        blocks.append(jc.paragraph(issue["review_notes"]))
    blocks += [jc.heading("Where"), jc.bullet_list(where)]
    if issue.get("evidence"):
        blocks += [jc.heading("Evidence"), jc.code_block("\n".join(issue["evidence"])[:2000])]
    blocks += [
        jc.heading("Expected fix"),
        jc.paragraph(issue.get("fix") or "Not stated in the report; needs a decision by the owning team."),
        jc.heading("Classification"),
        jc.bullet_list(classification),
        jc.heading("Provenance"),
        jc.bullet_list(provenance),
        jc.paragraph(jc.text("Tracked by " + agent + ". The "),
                     jc.text(fingerprint_label(issue, config), marks=["code"]),
                     jc.text(" label is how re-runs recognise this issue; removing it will cause a "
                             "duplicate to be filed on the next run.")),
    ]
    return jc.document(*blocks)


def build_comment(issue: dict, report: dict, agent: str, first_time: bool, changes: list) -> dict:
    when = utc_today()
    if first_time:
        opening = jc.paragraph(
            jc.text("Logged by " + agent + " on " + when + " (UTC)", marks=["strong"]),
            jc.text(" from the OWASP scan report below."),
        )
    else:
        opening = jc.paragraph(
            jc.text("Still present as of " + when + " (UTC)", marks=["strong"]),
            jc.text(", re-confirmed by " + agent + ". The previous status comment above has been "
                    "struck through so the latest run is the one that reads as current."),
        )
    details = [
        "Report: " + report["file_name"] + " (generated " + (report.get("generated_utc") or "unknown") + ")",
        "Finding: " + issue["finding_id"] + " - " + issue["title"],
        "Location: " + issue["file"] + ((":" + str(issue["line"])) if issue.get("line") else "")
        + " at commit " + (issue.get("repo_commit") or "unknown"),
        "Severity: " + issue["severity"] + "  |  Review status: " + (issue.get("status") or "unstated"),
    ]
    if changes:
        details.append("Updated on this run: " + "; ".join(changes))
    return jc.document(
        opening,
        jc.bullet_list(details),
        jc.paragraph(jc.text("[" + MARKER + " fingerprint=" + issue["fingerprint"]
                             + " run=" + utc_stamp() + "]", marks=["code"])),
    )


def is_agent_comment(comment: dict) -> bool:
    body = jc.plain_text(comment.get("body", {}))
    return MARKER in body


def is_struck(node) -> bool:
    """True when every text run in the document already carries the strike mark."""
    texts = []

    def walk(item):
        if isinstance(item, list):
            for entry in item:
                walk(entry)
            return
        if not isinstance(item, dict):
            return
        if item.get("type") == "codeBlock":
            return
        if item.get("type") == "text":
            texts.append(any(mark.get("type") == "strike" for mark in item.get("marks", [])))
            return
        walk(item.get("content", []))

    walk(node)
    return bool(texts) and all(texts)


def jql_project(project: str) -> str:
    return project if project.isdigit() else '"' + project + '"'


def find_existing(client: jc.JiraClient, config: dict, issues: list) -> dict:
    """Map fingerprint label -> existing issue, in as few searches as possible."""
    found = {}
    labels = [fingerprint_label(issue, config) for issue in issues]
    chunk_size = 40
    for start in range(0, len(labels), chunk_size):
        chunk = labels[start:start + chunk_size]
        quoted = ", ".join('"' + item + '"' for item in chunk)
        jql = "project = " + jql_project(config["project"]) + " AND labels in (" + quoted + ") ORDER BY created ASC"
        for result in client.search(jql, fields=("summary", "labels", "status", "parent")):
            for name in result.get("fields", {}).get("labels", []):
                if name in chunk and name not in found:
                    found[name] = result
    return found


def preflight(client: jc.JiraClient, config: dict) -> dict:
    """Confirm the project can accept what we are about to send."""
    meta = client.create_meta()
    problems = []
    if not meta["issue_type"]:
        problems.append(
            "issue type " + repr(config["issue_type"]) + " does not exist in project "
            + config["project"] + "; available: " + ", ".join(str(name) for name in meta["available_types"])
        )
    fields = {field.get("fieldId"): field for field in meta["fields"]}
    if "labels" not in fields:
        problems.append(
            "the create screen for this issue type has no Labels field. This skill identifies the issues "
            "it filed by a fingerprint label, so without it a re-run would file duplicates. Add Labels to "
            "the screen, or set JIRA_ISSUE_TYPE to a type that has it."
        )

    epic_strategy, epic_field = None, None
    if config.get("epic"):
        if "parent" in fields:
            epic_strategy, epic_field = "parent", "parent"
        else:
            for field_id, field in fields.items():
                schema = field.get("schema", {}) or {}
                if str(field.get("name", "")).lower() == "epic link" or "gh-epic-link" in str(schema.get("custom", "")):
                    epic_strategy, epic_field = "epic_link", field_id
                    break
            if not epic_strategy:
                problems.append(
                    "JIRA_EPIC_ID is set but this issue type exposes neither a parent field nor an Epic Link "
                    "field, so the issues cannot be placed under the epic. Clear JIRA_EPIC_ID to file them "
                    "at the top level of the project."
                )

    # Priority is deliberately not managed: severity is carried by a label and the
    # description, so the Priority field is ignored whether or not the screen has it.
    known = {"summary", "description", "project", "issuetype", "priority", "labels", "parent", "reporter"}
    unfillable = []
    autofilled = {}
    for field_id, field in fields.items():
        if not field.get("required") or field_id in known or field_id == epic_field:
            continue
        allowed = field.get("allowedValues") or []
        if allowed:
            first = allowed[0]
            value = {"id": first["id"]} if isinstance(first, dict) and first.get("id") else first
            autofilled[field_id] = (field.get("name", field_id), value)
        else:
            unfillable.append(field.get("name", field_id) + " (" + field_id + ")")
    return {
        "meta": meta,
        "problems": problems,
        "epic_strategy": epic_strategy,
        "epic_field": epic_field,
        "autofilled_required": autofilled,
        "unfillable_required": unfillable,
    }


def sync(client: jc.JiraClient, config: dict, parsed: dict, checks: dict, agent: str) -> dict:
    report = parsed["report"]
    issues = parsed["issues"]
    existing = find_existing(client, config, issues) if issues else {}
    results = []

    for issue in issues:
        key_label = fingerprint_label(issue, config)
        match = existing.get(key_label)
        labels = build_labels(issue, config)
        record = {
            "finding_id": issue["finding_id"],
            "fingerprint": issue["fingerprint"],
            "title": issue["title"],
            "severity": issue["severity"],
            "labels": labels,
        }
        try:
            if match is None:
                fields = {
                    "project": ({"id": config["project"]} if config["project"].isdigit()
                                else {"key": config["project"]}),
                    "issuetype": {"id": str(checks["meta"]["issue_type"]["id"])},
                    "summary": build_summary(issue),
                    "description": build_description(issue, report, agent, config),
                    "labels": labels,
                }
                if config.get("epic") and checks["epic_strategy"] == "parent":
                    fields["parent"] = {"key": config["epic"]}
                elif config.get("epic") and checks["epic_strategy"] == "epic_link":
                    fields[checks["epic_field"]] = config["epic"]
                for field_id, (_, value) in checks["autofilled_required"].items():
                    fields[field_id] = value

                created = client.create_issue(fields)
                record["action"] = "created"
                record["key"] = created.get("key")
                if not client.dry_run:
                    client.add_comment(record["key"], build_comment(issue, report, agent, True, []))
                record["comment"] = "added"
            else:
                key = match["key"]
                record["action"] = "updated"
                record["key"] = key
                record["status"] = (match.get("fields", {}).get("status") or {}).get("name")

                changes = []
                update_fields = {}
                current_labels = match.get("fields", {}).get("labels", []) or []
                # Severity lives only in a label, so when it changes the old severity
                # label must be swapped out, not left beside the new one - an issue
                # tagged both medium and high would answer "how bad is this" with both.
                current_severity = sorted(item for item in current_labels if item in SEVERITY_LABELS)
                wanted_severity = severity_label(issue)
                stale = [item for item in current_severity if item != wanted_severity]
                kept = [item for item in current_labels if item not in stale]
                added = [item for item in labels if item not in kept]
                merged = kept + added
                if stale:
                    changes.append("severity " + ", ".join(item[len("severity-"):] for item in stale)
                                   + " -> " + issue["severity"])
                others = [item for item in added if item != wanted_severity]
                if others:
                    changes.append("labels added: " + ", ".join(others))
                if merged != current_labels:
                    update_fields["labels"] = merged
                if update_fields:
                    client.update_issue(key, update_fields)
                record["changes"] = changes

                struck = 0
                if not client.dry_run:
                    for comment in client.comments(key):
                        if not is_agent_comment(comment) or is_struck(comment.get("body", {})):
                            continue
                        client.update_comment(key, comment["id"], jc.strike_document(comment["body"]))
                        struck += 1
                    client.add_comment(key, build_comment(issue, report, agent, False, changes))
                record["comments_struck"] = struck
                record["comment"] = "added"
                record["action"] = "updated" if changes or struck else "recommented"
            record["ok"] = True
        except jc.JiraError as error:
            record["ok"] = False
            record["action"] = "failed"
            record["error"] = jc.redact(str(error))
            record["status_code"] = error.status
        results.append(record)

    return {"results": results}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--report", required=True, help="the OWASP scan report Markdown file")
    parser.add_argument("--env", default="", help="path to the .env file holding the Jira settings")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would be filed or updated without writing to Jira")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, help="skip findings below this severity")
    parser.add_argument("--include-verdict", action="append", default=[],
                        help="only file these verdicts (confirmed, needs_verification, unreviewed)")
    parser.add_argument("--agent-name", default="", help="name recorded in comments (default: owasp-security-agent)")
    parser.add_argument("--out", default="", help="write the run result JSON here")
    parser.add_argument("--force", action="store_true",
                        help="proceed even when required fields cannot be filled (the create may fail)")
    args = parser.parse_args()

    config = jc.load_config(args.env)
    missing = jc.missing_config(config)
    if missing:
        print(json.dumps({
            "ok": False,
            "error": "Jira configuration incomplete",
            "missing": missing,
            "env_file": config["env_file"] or "no .env file found",
            "hint": "copy templates/jira.env.template to .env and fill it in. The API token comes from "
                    "id.atlassian.com/manage-profile/security/api-tokens and is never printed by this skill.",
        }, indent=2))
        return 2

    agent = args.agent_name or "owasp-security-agent"
    report_path = Path(args.report)
    if not report_path.is_file():
        print(json.dumps({"ok": False, "error": "report not found: " + str(report_path)}, indent=2))
        return 2

    parsed = parse_report.parse(report_path.read_text(encoding="utf-8"), str(report_path))
    if args.min_severity:
        ceiling = SEVERITY_ORDER.index(args.min_severity)
        parsed["issues"] = [i for i in parsed["issues"]
                            if (SEVERITY_ORDER.index(i["severity"]) if i["severity"] in SEVERITY_ORDER else 9)
                            <= ceiling]
    if args.include_verdict:
        wanted = {value.lower() for value in args.include_verdict}
        parsed["issues"] = [i for i in parsed["issues"] if i["verdict"] in wanted]

    if not parsed["issues"]:
        print(json.dumps({"ok": True, "filed": 0,
                          "note": "the report contains no findings matching the filters; nothing to file"},
                         indent=2))
        return 0

    client = jc.JiraClient(config, dry_run=args.dry_run)
    try:
        me = client.myself()
        checks = preflight(client, config)
    except jc.JiraError as error:
        print(json.dumps({
            "ok": False, "error": jc.redact(str(error)), "status_code": error.status,
            "hint": "401/403: the email and API token pair is not valid for this site. "
                    "404: check JIRA_BASE_URL and JIRA_PROJECT_ID.",
        }, indent=2))
        return 2

    blocking = list(checks["problems"])
    if checks["unfillable_required"] and not args.force:
        blocking.append("required fields this skill cannot fill: " + ", ".join(checks["unfillable_required"])
                        + ". Give them a default in the project, or re-run with --force to try anyway.")
    if blocking:
        print(json.dumps({"ok": False, "error": "project preflight failed", "problems": blocking}, indent=2))
        return 2

    outcome = sync(client, config, parsed, checks, agent)
    results = outcome["results"]
    failed = [record for record in results if not record["ok"]]
    counts = {}
    for record in results:
        counts[record["action"]] = counts.get(record["action"], 0) + 1

    summary = {
        "ok": not failed,
        "dry_run": args.dry_run,
        "authenticated_as": me.get("displayName") or "unknown",
        "project": config["project"],
        "epic": config["epic"] or None,
        "epic_strategy": checks["epic_strategy"],
        "report": parsed["report"]["file_name"],
        "issues_in_report": len(parsed["issues"]),
        "actions": counts,
        "api_calls": client.calls,
        "autofilled_required_fields": {name: field_id for field_id, (name, _) in
                                       checks["autofilled_required"].items()},
        "failures": [{"finding_id": r["finding_id"], "error": r.get("error")} for r in failed],
        "results": results,
    }
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        summary["result_file"] = args.out
    print(json.dumps(summary, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
