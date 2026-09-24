#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Render reviewed findings into the timestamped Markdown report.

The report is the deliverable, and it is written to a new timestamped file every
run rather than overwriting a single report.md. Two scans of the same repository
a month apart are different evidence, and keeping both is what lets anyone show
that a finding was present on one date and fixed by another.

Findings are grouped by repository, then by OWASP category, then ordered by
severity, because that is the order the reader acts in: whose repository is it,
which class of problem is it, what do I fix first.

Usage:
  python render_report.py --findings ws/findings.reviewed.json --out-dir reports
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from redact import redact_list, redact_text  # noqa: E402

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLUMNS = ["critical", "high", "medium", "low"]

# Verdicts set during review. Anything not rejected belongs in the body of the
# report; rejected candidates move to an appendix so the reader can see what was
# considered and why it was dropped, without them crowding the real findings.
REJECTED = {"false_positive", "rejected", "not_applicable", "wont_fix"}

VERDICT_LABEL = {
    "confirmed": "Confirmed by review",
    "needs_verification": "Needs verification (requires a running instance or domain knowledge)",
    "unreviewed": "Pattern candidate, not yet reviewed",
    "false_positive": "Rejected during review",
    "rejected": "Rejected during review",
    "not_applicable": "Not applicable",
    "wont_fix": "Accepted risk",
}


TEXT_FIELDS = ("title", "explain", "analysis", "remediation")


def redact_findings(data: dict) -> int:
    """Mask secret-looking values in every piece of text that ends up in the report.

    The scanner masks what its own rules collect, but the review step adds free text
    and evidence typed by hand, and a report is copied onward (into a tracker, into
    chat). Redaction here means what leaves this tool is clean whoever wrote it.
    """
    total = 0
    for repo in data.get("repos", []):
        for finding in repo.get("findings", []):
            # A rejected candidate only surfaces as a title and a reason in the appendix.
            # Its other text is still cleaned (the findings file may be shared), but only
            # what actually appears in the report is counted in the report's own note.
            shown = ("title", "analysis") if finding.get("verdict", "unreviewed") in REJECTED else TEXT_FIELDS
            for field in TEXT_FIELDS:
                if isinstance(finding.get(field), str):
                    finding[field], n = redact_text(finding[field])
                    total += n if field in shown else 0
            if isinstance(finding.get("snippets"), list):
                finding["snippets"], n = redact_list(finding["snippets"])
                total += n if "snippets" in shown or shown == TEXT_FIELDS else 0
    return total


def fingerprint_key(repo_name: str, finding: dict) -> tuple:
    """Same identity the Jira skill uses to recognise a finding across runs."""
    return (str(repo_name).strip().lower(), str(finding.get("title", "")).strip().lower(),
            str(finding.get("file", "")).strip().lower())


def find_collisions(data: dict) -> list:
    """Findings that would be indistinguishable in a tracker: same repo, title and file.

    Two such findings share one identity, so a tracker would either merge them or
    file duplicates and later lose track of one. The fix is cheap at review time
    (give them distinct titles) and expensive afterwards, so refuse to render.
    """
    collisions = []
    for repo in data.get("repos", []):
        seen: dict = {}
        for finding in repo.get("findings", []):
            if finding.get("verdict", "unreviewed") in REJECTED:
                continue
            seen.setdefault(fingerprint_key(repo.get("name", ""), finding), []).append(finding)
        for key, group in seen.items():
            if len(group) > 1:
                collisions.append({
                    "repo": repo.get("name", ""), "title": group[0].get("title", ""), "file": group[0].get("file", ""),
                    "finding_ids": [item.get("id", "?") for item in group],
                })
    return collisions


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else len(SEVERITY_ORDER)


def counts_by_severity(findings: list) -> dict:
    counts = {name: 0 for name in SEVERITY_COLUMNS}
    for finding in findings:
        severity = finding.get("severity", "medium")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def fence(lines: list) -> list:
    """Fence evidence so stray backticks in source cannot break the layout."""
    cleaned = [line.replace("```", "` ` `") for line in lines if line]
    if not cleaned:
        return []
    return ["```text"] + cleaned + ["```", ""]


def location_line(finding: dict) -> str:
    location = "`" + finding.get("file", "?") + ":" + str(finding.get("line", 1)) + "`"
    others = finding.get("other_lines") or []
    if others:
        location += " (also line " + ", ".join(str(number) for number in others) + ")"
    occurrences = finding.get("occurrences", 1)
    if occurrences > 1 + len(others):
        location += " - " + str(occurrences) + " occurrences in this file"
    return location


def render_finding(finding: dict, lines: list) -> None:
    severity = finding.get("severity", "medium").upper()
    lines.append("#### " + finding.get("id", "?") + " - " + finding.get("title", "(untitled)"))
    lines.append("")
    lines.append("- **Severity:** " + severity
                 + "  |  **Confidence:** " + str(finding.get("confidence", "medium"))
                 + "  |  **Status:** "
                 + VERDICT_LABEL.get(finding.get("verdict", "unreviewed"), finding.get("verdict", "")))
    lines.append("- **Location:** " + location_line(finding))
    if finding.get("cwe"):
        lines.append("- **CWE:** " + ", ".join(finding["cwe"]))
    lines.append("- **Detected by:** " + str(finding.get("detector", "pattern")))
    lines.append("")
    evidence = finding.get("snippets") or []
    if evidence:
        lines.append("**Evidence**")
        lines.append("")
        lines += fence(evidence)
    if finding.get("explain"):
        lines += ["**Why it matters**", "", finding["explain"], ""]
    if finding.get("analysis"):
        lines += ["**Review notes**", "", finding["analysis"], ""]
    if finding.get("remediation"):
        lines += ["**Recommended fix**", "", finding["remediation"], ""]


def render_repo(repo: dict, taxonomy_names: dict, lines: list) -> dict:
    findings = repo.get("findings", [])
    active = [f for f in findings if f.get("verdict", "unreviewed") not in REJECTED]
    rejected = [f for f in findings if f.get("verdict", "unreviewed") in REJECTED]
    git = repo.get("git", {})
    inventory = repo.get("inventory", {})
    scan = repo.get("scan", {})

    lines.append("## Repository: " + repo.get("name", "(unnamed)"))
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append("| Source | " + str(repo.get("source", "")) + " |")
    lines.append("| Commit scanned | `" + str(git.get("short_commit", "")) + "` on `"
                 + str(git.get("branch", "")) + "` (" + str(git.get("committed_at", "")) + ") |")
    lines.append("| Languages | " + (", ".join(list(inventory.get("languages", {}))[:8]) or "n/a") + " |")
    lines.append("| Files scanned | " + str(scan.get("files_scanned", "n/a")) + " |")
    notes = scan.get("completeness_notes") or []
    lines.append("| Scan coverage | " + ("Complete" if not notes else "**Incomplete** - " + str(len(notes))
                                          + " gap(s), listed below") + " |")
    lines.append("| Findings reported | " + str(len(active))
                 + " (plus " + str(len(rejected)) + " rejected during review) |")
    lines.append("")
    if notes:
        lines.append("> **This repository was not fully scanned.** The findings below are a subset, so "
                     "an absence of findings here is not evidence of absence.")
        lines.append(">")
        lines += ["> - " + note for note in notes]
        lines.append("")

    if not active:
        lines += ["No findings were reported for this repository. "
                  "See the scope note at the end of the report for what that does and does not mean.", ""]
    else:
        severity_counts = counts_by_severity(active)
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for name in SEVERITY_COLUMNS:
            lines.append("| " + name.capitalize() + " | " + str(severity_counts.get(name, 0)) + " |")
        lines.append("")

        grouped: dict = {}
        for finding in active:
            grouped.setdefault(finding.get("owasp_id", "UNMAPPED"), []).append(finding)

        for owasp_id in sorted(grouped, key=lambda key: (key == "UNMAPPED", key)):
            bucket = sorted(grouped[owasp_id], key=lambda f: (severity_rank(f.get("severity", "medium")),
                                                              f.get("file", ""), f.get("line", 0)))
            name = taxonomy_names.get(owasp_id) or bucket[0].get("owasp_name", "")
            heading = owasp_id + (" - " + name if name else "")
            lines.append("### " + heading + " (" + str(len(bucket)) + ")")
            lines.append("")
            for finding in bucket:
                render_finding(finding, lines)

    if rejected:
        lines.append("### Rejected during review (" + str(len(rejected)) + ")")
        lines.append("")
        lines.append("Candidates the pattern scan raised that reading the code ruled out.")
        lines.append("")
        lines.append("| Candidate | Location | Reason |")
        lines.append("| --- | --- | --- |")
        for finding in rejected:
            reason = (finding.get("analysis") or "reviewed and rejected").replace("|", "\\|")
            lines.append("| " + finding.get("title", "") + " | `" + finding.get("file", "")
                         + ":" + str(finding.get("line", "")) + "` | " + reason + " |")
        lines.append("")

    return {"active": active, "rejected": rejected}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--findings", required=True,
                        help="findings JSON from scan_repos.py, after review")
    parser.add_argument("--out-dir", default="reports", help="directory for the report (default: reports)")
    parser.add_argument("--title", default="OWASP Security Scan Report", help="report title")
    parser.add_argument("--prefix", default="owasp-security-report", help="report filename prefix")
    parser.add_argument("--taxonomy", help="owasp-taxonomy.json, for category names and source URLs")
    args = parser.parse_args()

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))

    collisions = find_collisions(data)
    if collisions:
        print(json.dumps({
            "ok": False,
            "error": "findings would be indistinguishable in a tracker: same repository, title and file",
            "collisions": collisions,
            "hint": "give each finding a title that says what is different about it (which system, which "
                    "setting), then render again. Nothing was written.",
        }, indent=2))
        return 2

    redactions = redact_findings(data)
    taxonomy = json.loads(Path(args.taxonomy).read_text(encoding="utf-8")) if args.taxonomy else {}
    categories = taxonomy.get("categories", [])
    taxonomy_names = {category["id"]: category["name"] for category in categories}
    taxonomy_urls = {category["id"]: category.get("url", "") for category in categories}

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d-%H%M%SZ")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / (args.prefix + "-" + stamp + ".md")

    repos = data.get("repos", [])
    scan_taxonomy = data.get("taxonomy", {})
    lines = [
        "# " + args.title,
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Generated (UTC) | " + now.isoformat(timespec="seconds") + " |",
        "| Generated (local) | " + datetime.now().astimezone().isoformat(timespec="seconds") + " |",
        "| Repositories in scope | " + str(len(repos)) + " |",
        "| OWASP rule set | read from " + str(scan_taxonomy.get("source") or "owasp.org")
        + " at " + str(scan_taxonomy.get("fetched_at") or "n/a") + " |",
        "| Scan run at | " + str(data.get("generated_at", "n/a")) + " |",
        "| Detection | " + str((data.get("tool") or {}).get("scanner", "scan_repos.py"))
        + " pattern pass, rules v" + str((data.get("tool") or {}).get("rules_version", "?"))
        + ", plus agent code review |",
        "",
    ]

    # Cross-repository summary first: the reader wants the worst repository, not
    # the first one alphabetically.
    all_active = []
    per_repo_rendered = []
    body: list = []
    for repo in repos:
        repo_lines: list = []
        outcome = render_repo(repo, taxonomy_names, repo_lines)
        all_active += outcome["active"]
        per_repo_rendered.append((repo, outcome, repo_lines))

    lines += ["## Executive summary", ""]
    lines += ["| Repository | Commit | Files | Critical | High | Medium | Low | Reported | Rejected |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    totals = {name: 0 for name in SEVERITY_COLUMNS}
    for repo, outcome, _ in per_repo_rendered:
        counts = counts_by_severity(outcome["active"])
        for name in SEVERITY_COLUMNS:
            totals[name] += counts.get(name, 0)
        lines.append("| " + repo.get("name", "") + " | `" + str(repo.get("git", {}).get("short_commit", ""))
                     + "` | " + str(repo.get("scan", {}).get("files_scanned", ""))
                     + " | " + " | ".join(str(counts.get(name, 0)) for name in SEVERITY_COLUMNS)
                     + " | " + str(len(outcome["active"])) + " | " + str(len(outcome["rejected"])) + " |")
    lines.append("| **All repositories** |  |  | "
                 + " | ".join("**" + str(totals[name]) + "**" for name in SEVERITY_COLUMNS)
                 + " | **" + str(len(all_active)) + "** |  |")
    lines.append("")

    category_totals: dict = {}
    for finding in all_active:
        key = finding.get("owasp_id", "UNMAPPED")
        bucket = category_totals.setdefault(key, {name: 0 for name in SEVERITY_COLUMNS})
        bucket[finding.get("severity", "medium")] = bucket.get(finding.get("severity", "medium"), 0) + 1

    if category_totals:
        lines += ["### Findings by OWASP category", "",
                  "| Category | Critical | High | Medium | Low | Total |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for key in sorted(category_totals, key=lambda k: (k == "UNMAPPED", k)):
            bucket = category_totals[key]
            name = taxonomy_names.get(key, "")
            total = sum(bucket.get(name_, 0) for name_ in SEVERITY_COLUMNS)
            lines.append("| " + key + (" " + name if name else "") + " | "
                         + " | ".join(str(bucket.get(name_, 0)) for name_ in SEVERITY_COLUMNS)
                         + " | " + str(total) + " |")
        lines.append("")

    incomplete = [repo.get("name", "?") for repo in repos if (repo.get("scan") or {}).get("completeness_notes")]
    if incomplete:
        lines += ["> **Incomplete scan.** " + str(len(incomplete)) + " of " + str(len(repos))
                  + " repositories were not fully scanned (" + ", ".join(incomplete) + "). The counts above "
                  "are a lower bound; each repository section lists what was not covered.", ""]

    unreviewed = [f for f in all_active if f.get("verdict", "unreviewed") == "unreviewed"]
    if unreviewed:
        lines += ["> **" + str(len(unreviewed)) + " finding(s) in this report are unreviewed pattern "
                  "candidates.** They mark code worth reading rather than confirmed vulnerabilities, "
                  "and each is labelled as such below.", ""]

    lines += body
    for _, _, repo_lines in per_repo_rendered:
        lines += repo_lines

    lines += [
        "## Method",
        "",
        "1. The current OWASP rule set was read from the OWASP website at the time shown above, "
        "so the categories used here are the ones OWASP publishes now rather than a copy held in "
        "this tool.",
        "2. Each repository was cloned at the commit recorded in its table and swept for candidate "
        "issues, which are classified by mapping their CWE to the live OWASP categories.",
        "3. Every candidate was then reviewed against the surrounding code: confirmed, rejected, or "
        "marked as needing verification. Issues that pattern matching cannot see - missing "
        "authorization checks, flawed trust boundaries, weak design decisions - were looked for by "
        "reading the code paths that handle authentication, authorization and untrusted input.",
        "",
        "## Scope and limitations",
        "",
        "- This is a static review of source code at one commit. It cannot observe runtime "
        "configuration, deployed infrastructure, secrets held outside the repository, or the "
        "behaviour of third-party services.",
        "- No dependency CVE lookup was performed against a vulnerability database; supply chain "
        "findings here are about how dependencies are declared and pinned.",
        "- Secrets found in source are masked in the evidence above. Treat any of them as disclosed "
        "and rotate them - masking the report does not undo the exposure in version control.",
        "- An empty result for a repository means these checks found nothing, not that the "
        "repository is secure.",
    ]
    if redactions:
        lines.append("- " + str(redactions) + " value(s) matching secret patterns were redacted from the "
                     "evidence and notes in this report.")
    lines.append("")

    referenced = sorted({f.get("owasp_id", "") for f in all_active if f.get("owasp_id", "UNMAPPED") != "UNMAPPED"})
    if referenced:
        lines += ["## OWASP categories referenced", ""]
        for key in referenced:
            url = taxonomy_urls.get(key, "")
            name = taxonomy_names.get(key, "")
            lines.append("- " + key + (" " + name if name else "") + (" - " + url if url else ""))
        lines.append("")

    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "report": str(out_path),
        "repositories": len(repos),
        "findings_reported": len(all_active),
        "unreviewed_included": len(unreviewed),
        "by_severity": {name: totals[name] for name in SEVERITY_COLUMNS},
        "redactions": redactions,
        "scan_complete": not incomplete,
        "incomplete_repositories": incomplete,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
