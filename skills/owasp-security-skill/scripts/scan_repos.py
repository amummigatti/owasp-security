#!/usr/bin/env python3
"""Sweep the prepared repositories for candidate OWASP findings.

This is the deterministic half of the skill. It reads every in-scope file once,
applies the patterns in patterns/owasp-scan-patterns.json, and classifies each hit by
looking its CWE up in the taxonomy fetched from owasp.org -- so the OWASP category
ids in the output come from the live rule set rather than from anything hardcoded
here.

Everything it emits is marked verdict="unreviewed" on purpose. Pattern matching
finds places worth reading; it cannot tell an exploitable sink from a sanitised
one, and it cannot see a missing authorization check at all. The reviewing agent
confirms or rejects each candidate and adds what only reading the code reveals.

Usage:
  python scan_repos.py --manifest ws/manifest.json --taxonomy ws/owasp-taxonomy.json \
      --out ws/findings.json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "site-packages",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", "coverage",
    ".gradle", ".idea", ".vscode", ".terraform", "bin", "obj", "Pods", ".cache",
}

# Generated or vendored single files that produce matches nobody can act on.
SKIP_FILE_PATTERNS = ["*.min.js", "*.min.css", "*.map", "*.bundle.js", "*-lock.json", "*.lock"]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf", ".zip", ".gz",
    ".tar", ".bz2", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar",
    ".war", ".pyc", ".pyd", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov",
    ".avi", ".bmp", ".tiff", ".psd", ".sqlite", ".db", ".bin", ".wasm",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


RULES_FILENAME = "owasp-scan-patterns.json"


def find_default_rules() -> str:
    """Locate patterns/<catalogue> by walking up from this script, then from the cwd.

    The catalogue lives in the repository's top-level patterns/ folder rather than
    inside the skill, so it can be reused and reviewed independently of any one
    skill. Pass --rules to point at a copy kept elsewhere.
    """
    starts = [Path(__file__).resolve().parent, Path.cwd().resolve()]
    for start in starts:
        for directory in [start] + list(start.parents):
            candidate = directory / "patterns" / RULES_FILENAME
            if candidate.is_file():
                return str(candidate)
    return ""


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def matches_any(patterns: list, name: str, relpath: str) -> bool:
    for pattern in patterns:
        if pattern == "*":
            return True
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(relpath, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(relpath, pattern[3:]):
            return True
    return False


def path_excluded(excludes: list, relpath: str) -> bool:
    lowered = relpath.lower()
    return any(fragment.lower() in lowered for fragment in excludes)


def compile_rules(rules: list) -> list:
    compiled = []
    for rule in rules:
        try:
            rule = dict(rule)
            rule["regex"] = re.compile(rule["pattern"])
            compiled.append(rule)
        except re.error as error:
            print("skipping rule " + rule.get("id", "?") + ": bad pattern (" + str(error) + ")",
                  file=sys.stderr)
    return compiled


def build_classifier(taxonomy: dict):
    """Return a function mapping a rule to (owasp_id, owasp_name) using live OWASP data."""
    cwe_index = (taxonomy or {}).get("cwe_index", {})
    categories = (taxonomy or {}).get("categories", [])
    by_id = {category["id"]: category["name"] for category in categories}

    def classify(rule: dict) -> tuple:
        for cwe in rule.get("cwe", []):
            ids = cwe_index.get(cwe)
            if ids:
                return ids[0], by_id.get(ids[0], "")
        hint = (rule.get("category_hint") or "").lower()
        if hint:
            for category in categories:
                name = category["name"].lower()
                if hint in name or name in hint:
                    return category["id"], category["name"]
        return "UNMAPPED", rule.get("category_hint") or "Unmapped"

    return classify


def mask_secret(text: str) -> str:
    """Keep evidence useful without copying live credentials into the report."""
    def replace(match: re.Match) -> str:
        value = match.group(0)
        return value[:3] + "<redacted:" + str(len(value)) + " chars>"

    return re.sub(r"[A-Za-z0-9+/=_\-\.]{12,}", replace, text)


def iter_files(root: Path, max_bytes: int) -> tuple:
    """Yield scannable files plus counters for what was skipped and why."""
    files = []
    skipped = {"large": 0, "binary": 0, "generated": 0, "unreadable": 0}
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if any(fnmatch.fnmatch(path.name, pattern) for pattern in SKIP_FILE_PATTERNS):
            skipped["generated"] += 1
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS:
            skipped["binary"] += 1
            continue
        try:
            if path.stat().st_size > max_bytes:
                skipped["large"] += 1
                continue
        except OSError:
            skipped["unreadable"] += 1
            continue
        files.append(path)
    return files, skipped


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if b"\x00" in data[:8192]:
        raise ValueError("binary content")
    return data.decode("utf-8", "replace")


def line_of(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def snippet_at(content: str, match: re.Match, sensitive: bool) -> str:
    start = content.rfind("\n", 0, match.start()) + 1
    end = content.find("\n", match.start())
    line = content[start:end if end != -1 else len(content)].strip()
    if len(line) > 240:
        line = line[:240] + " ..."
    return mask_secret(line) if sensitive else line


def scan_repo(repo: dict, rules: list, presence_rules: list, pair_rules: list,
              classify, args) -> dict:
    root = Path(repo["path"])
    files, skipped = iter_files(root, args.max_file_bytes)
    findings = []
    counter = 0
    per_rule_totals: dict = {}
    all_relpaths = []

    for path in files:
        relpath = path.relative_to(root).as_posix()
        all_relpaths.append(relpath)
        try:
            content = read_text(path)
        except (OSError, ValueError):
            skipped["unreadable"] += 1
            continue

        for rule in rules:
            if not matches_any(rule.get("include", ["*"]), path.name, relpath):
                continue
            if path_excluded(rule.get("exclude_paths", []), relpath):
                continue
            if per_rule_totals.get(rule["id"], 0) >= args.max_per_rule_per_repo:
                continue

            lines = []
            snippets = []
            for match in rule["regex"].finditer(content):
                lines.append(line_of(content, match.start()))
                if len(snippets) < args.max_per_rule_per_file:
                    snippets.append(snippet_at(content, match, rule.get("sensitive", False)))
                if len(lines) >= 500:  # a pathological file should not stall the scan
                    break
            if not lines:
                continue

            per_rule_totals[rule["id"]] = per_rule_totals.get(rule["id"], 0) + 1
            counter += 1
            owasp_id, owasp_name = classify(rule)
            findings.append({
                "id": repo["name"] + "-" + str(counter).zfill(3),
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule.get("severity", "medium"),
                "confidence": rule.get("confidence", "medium"),
                "owasp_id": owasp_id,
                "owasp_name": owasp_name,
                "cwe": rule.get("cwe", []),
                "file": relpath,
                "line": lines[0],
                "occurrences": len(lines),
                "other_lines": lines[1:6],
                "snippets": snippets,
                "explain": rule.get("explain", ""),
                "remediation": rule.get("remediation", ""),
                "detector": "pattern",
                "verdict": "unreviewed",
            })

    for rule in presence_rules:
        for relpath in all_relpaths:
            name = relpath.split("/")[-1]
            if not matches_any(rule.get("paths", []), name, relpath):
                continue
            if path_excluded(rule.get("exclude_paths", []), relpath):
                continue
            if per_rule_totals.get(rule["id"], 0) >= args.max_per_rule_per_repo:
                continue
            per_rule_totals[rule["id"]] = per_rule_totals.get(rule["id"], 0) + 1
            counter += 1
            owasp_id, owasp_name = classify(rule)
            findings.append({
                "id": repo["name"] + "-" + str(counter).zfill(3),
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule.get("severity", "medium"),
                "confidence": rule.get("confidence", "medium"),
                "owasp_id": owasp_id,
                "owasp_name": owasp_name,
                "cwe": rule.get("cwe", []),
                "file": relpath,
                "line": 1,
                "occurrences": 1,
                "other_lines": [],
                "snippets": ["tracked file: " + relpath],
                "explain": rule.get("explain", ""),
                "remediation": rule.get("remediation", ""),
                "detector": "presence",
                "verdict": "unreviewed",
            })

    for rule in pair_rules:
        triggers = [p for p in all_relpaths
                    if matches_any(rule.get("if_present", []), p.split("/")[-1], p)]
        if not triggers:
            continue
        satisfied = [p for p in all_relpaths
                     if matches_any(rule.get("requires_any", []), p.split("/")[-1], p)]
        if satisfied:
            continue
        counter += 1
        owasp_id, owasp_name = classify(rule)
        findings.append({
            "id": repo["name"] + "-" + str(counter).zfill(3),
            "rule_id": rule["id"],
            "title": rule["title"],
            "severity": rule.get("severity", "medium"),
            "confidence": rule.get("confidence", "medium"),
            "owasp_id": owasp_id,
            "owasp_name": owasp_name,
            "cwe": rule.get("cwe", []),
            "file": triggers[0],
            "line": 1,
            "occurrences": len(triggers),
            "other_lines": [],
            "snippets": ["present: " + ", ".join(triggers[:3]) +
                         "; none of: " + ", ".join(rule.get("requires_any", [])[:4])],
            "explain": rule.get("explain", ""),
            "remediation": rule.get("remediation", ""),
            "detector": "pair",
            "verdict": "unreviewed",
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"])
                                 if f["severity"] in SEVERITY_ORDER else 9,
                                 f["owasp_id"], f["file"], f["line"]))

    by_severity: dict = {}
    by_category: dict = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        key = finding["owasp_id"] + " " + finding["owasp_name"]
        by_category[key] = by_category.get(key, 0) + 1

    return {
        "name": repo["name"],
        "source": repo.get("source", ""),
        "path": repo["path"],
        "git": repo.get("git", {}),
        "inventory": repo.get("inventory", {}),
        "scan": {
            "files_scanned": len(files),
            "skipped": skipped,
            "rules_applied": len(rules) + len(presence_rules) + len(pair_rules),
        },
        "stats": {"total": len(findings), "by_severity": by_severity, "by_category": by_category},
        "findings": findings,
    }


def main() -> int:
    default_rules = find_default_rules()
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--manifest", required=True, help="manifest.json from prepare_repos.py")
    parser.add_argument("--taxonomy", help="owasp-taxonomy.json from fetch_owasp_taxonomy.py "
                                          "(without it, findings stay UNMAPPED)")
    parser.add_argument("--rules", default=default_rules or None,
                        help="pattern catalogue (default: patterns/" + RULES_FILENAME
                             + " found above this script or the current directory)")
    parser.add_argument("--out", required=True, help="where to write the findings JSON")
    parser.add_argument("--max-file-bytes", type=int, default=1_500_000,
                        help="skip files larger than this (default: 1500000)")
    parser.add_argument("--max-per-rule-per-file", type=int, default=3,
                        help="snippets kept per rule per file (default: 3)")
    parser.add_argument("--max-per-rule-per-repo", type=int, default=40,
                        help="findings kept per rule per repository (default: 40)")
    args = parser.parse_args()
    if not args.rules:
        parser.error("could not find patterns/" + RULES_FILENAME + "; pass --rules PATH")

    manifest = load_json(args.manifest)
    catalogue = load_json(args.rules)
    taxonomy = load_json(args.taxonomy) if args.taxonomy else {}
    classify = build_classifier(taxonomy)

    rules = compile_rules(catalogue.get("rules", []))
    presence_rules = catalogue.get("presence_rules", [])
    pair_rules = catalogue.get("pair_rules", [])

    started = time.time()
    results = [scan_repo(repo, rules, presence_rules, pair_rules, classify, args)
               for repo in manifest.get("repos", [])]

    report = {
        "schema": "owasp-scan-findings/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round(time.time() - started, 2),
        "tool": {"scanner": "scan_repos.py", "rules_file": str(Path(args.rules).name),
                 "rules_version": catalogue.get("version")},
        "taxonomy": {
            "fetched_at": taxonomy.get("fetched_at"),
            "source": (taxonomy.get("sources") or {}).get("top10_index"),
            "categories": [c["id"] + " " + c["name"] for c in taxonomy.get("categories", [])],
        },
        "repos": results,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "findings_json": str(out_path),
        "duration_seconds": report["duration_seconds"],
        "repos": [
            {
                "name": repo["name"],
                "files_scanned": repo["scan"]["files_scanned"],
                "candidates": repo["stats"]["total"],
                "by_severity": repo["stats"]["by_severity"],
                "by_category": repo["stats"]["by_category"],
            }
            for repo in results
        ],
        "next_step": "review every candidate, set verdict to confirmed/false_positive, "
                     "add findings patterns cannot see, then run render_report.py",
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
