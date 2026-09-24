#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Fetch the repositories under review and inventory what is in them.

Given the repository URLs the user supplied, this clones each one into a
throwaway workspace and writes a manifest.json that the scanner and the report
both read. The manifest pins the exact commit that was scanned, which is what
makes a report reproducible: "we found X" is only meaningful alongside "at commit
abc1234 of branch main".

Accepts full git URLs, the GitHub "owner/repo" shorthand, and paths to
repositories already on disk (those are inventoried in place, never modified).

Usage:
  python prepare_repos.py --workspace ./.owasp-workspace --repo https://github.com/owner/app
  python prepare_repos.py --workspace ./ws --repo owner/app --repo ../other-checkout --depth 50
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Directories that hold third-party or generated code. Scanning them buries the
# findings that the repository's own authors can actually fix.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv",
    "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "site-packages",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit", "coverage",
    ".gradle", ".idea", ".vscode", ".terraform", "bin", "obj", "Pods", ".cache",
}

DEPENDENCY_MANIFESTS = [
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock", "Cargo.toml",
    "Cargo.lock", "*.csproj", "packages.config", "Dockerfile", "docker-compose.yml",
]

LANGUAGE_BY_EXTENSION = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java",
    ".kt": "Kotlin", ".cs": "C#", ".php": "PHP", ".rb": "Ruby", ".go": "Go",
    ".rs": "Rust", ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++",
    ".swift": "Swift", ".scala": "Scala", ".sh": "Shell", ".ps1": "PowerShell",
    ".sql": "SQL", ".tf": "Terraform", ".yml": "YAML", ".yaml": "YAML",
    ".html": "HTML", ".vue": "Vue", ".svelte": "Svelte", ".ejs": "Template",
    ".erb": "Template", ".jinja": "Template", ".j2": "Template",
}


def redact(text: str) -> str:
    """Strip any credentials embedded in a URL before it reaches a log or report."""
    return re.sub(r"(://)[^/@\s]+:[^/@\s]+@", r"\1***:***@", text)


def run_git(args: list, cwd: Path = None, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def normalize_target(raw: str) -> dict:
    """Work out whether a target is a local checkout, a shorthand, or a git URL."""
    value = raw.strip().rstrip("/")
    local = Path(value).expanduser()
    if local.is_dir():
        return {"kind": "local", "location": str(local.resolve()), "display": str(local.resolve()),
                "name": local.resolve().name}
    if re.match(r"^[\w.\-]+/[\w.\-]+$", value):
        value = "https://github.com/" + value
    if not re.match(r"^(https?://|ssh://|git://|git@)", value):
        raise ValueError(
            "not a directory, a git URL, or an owner/repo shorthand: " + raw
        )
    name = re.sub(r"\.git$", "", value.split("/")[-1].split(":")[-1]) or "repository"
    return {"kind": "git", "location": value, "display": redact(value), "name": name}


def clone_or_reuse(target: dict, workspace: Path, depth: int, branch: str, refresh: bool) -> dict:
    """Return the on-disk path for a target, cloning it if needed."""
    if target["kind"] == "local":
        return {"path": Path(target["location"]), "action": "reused-local-checkout"}

    destination = workspace / target["name"]
    if destination.exists() and (destination / ".git").exists():
        if not refresh:
            return {"path": destination, "action": "reused-existing-clone"}
        fetch = run_git(["fetch", "--depth", str(depth), "origin"], cwd=destination)
        if fetch.returncode != 0:
            return {"path": destination, "action": "reused-existing-clone",
                    "warning": redact(fetch.stderr.strip()[:400])}
        run_git(["reset", "--hard", "FETCH_HEAD"], cwd=destination)
        return {"path": destination, "action": "refreshed-existing-clone"}

    command = ["clone", "--single-branch"]
    if depth > 0:
        command += ["--depth", str(depth)]
    if branch:
        command += ["--branch", branch]
    command += [target["location"], str(destination)]
    result = run_git(command)
    if result.returncode != 0:
        raise RuntimeError(redact(result.stderr.strip()[:600]) or "git clone failed")
    return {"path": destination, "action": "cloned"}


def git_metadata(path: Path) -> dict:
    def first_line(args: list) -> str:
        result = run_git(args, cwd=path)
        return result.stdout.strip() if result.returncode == 0 else ""

    return {
        "commit": first_line(["rev-parse", "HEAD"]),
        "short_commit": first_line(["rev-parse", "--short", "HEAD"]),
        "branch": first_line(["rev-parse", "--abbrev-ref", "HEAD"]),
        "committed_at": first_line(["log", "-1", "--format=%cI"]),
        "commit_subject": first_line(["log", "-1", "--format=%s"])[:160],
        "origin": redact(first_line(["remote", "get-url", "origin"])),
    }


def inventory(path: Path) -> dict:
    """Count what is actually there, so the report can say what was in scope."""
    extensions: dict = {}
    manifests = []
    files = 0
    total_bytes = 0
    exact_manifests = {name for name in DEPENDENCY_MANIFESTS if "*" not in name}
    glob_manifests = [name for name in DEPENDENCY_MANIFESTS if "*" in name]

    for item in path.rglob("*"):
        if any(part in SKIP_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        files += 1
        try:
            total_bytes += item.stat().st_size
        except OSError:
            pass
        extensions[item.suffix.lower()] = extensions.get(item.suffix.lower(), 0) + 1
        if item.name in exact_manifests or any(item.match(pattern) for pattern in glob_manifests):
            manifests.append(item.relative_to(path).as_posix())

    languages: dict = {}
    for extension, count in extensions.items():
        language = LANGUAGE_BY_EXTENSION.get(extension)
        if language:
            languages[language] = languages.get(language, 0) + count

    return {
        "files": files,
        "bytes": total_bytes,
        "languages": dict(sorted(languages.items(), key=lambda pair: -pair[1])),
        "top_extensions": dict(sorted(extensions.items(), key=lambda pair: -pair[1])[:12]),
        "dependency_manifests": sorted(set(manifests))[:40],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--workspace", required=True, help="directory to clone into and write manifest.json")
    parser.add_argument("--repo", action="append", default=[], metavar="URL_OR_PATH",
                        help="repository to review; repeatable")
    parser.add_argument("targets", nargs="*", help="repositories as positional arguments")
    parser.add_argument("--depth", type=int, default=1,
                        help="clone depth; 0 for full history (default: 1, since a scan only reads the tip)")
    parser.add_argument("--branch", default="", help="branch or tag to check out (default: remote default)")
    parser.add_argument("--refresh", action="store_true",
                        help="re-fetch and hard-reset clones that already exist in the workspace")
    args = parser.parse_args()

    raw_targets = args.repo + args.targets
    if not raw_targets:
        parser.error("no repositories given: pass --repo URL (repeatable) or positional paths/URLs")

    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    repos = []
    errors = []
    used_names: dict = {}
    for raw in raw_targets:
        try:
            target = normalize_target(raw)
        except ValueError as error:
            errors.append({"target": raw, "error": str(error)})
            continue

        # Two repositories can share a basename ("owner-a/api" and "owner-b/api").
        count = used_names.get(target["name"], 0)
        used_names[target["name"]] = count + 1
        if count:
            target["name"] = target["name"] + "-" + str(count + 1)

        try:
            placement = clone_or_reuse(target, workspace, args.depth, args.branch, args.refresh)
        except Exception as error:  # noqa: BLE001 - surfaced per repo so one bad URL does not abort the run
            errors.append({"target": target["display"], "error": str(error)})
            continue

        entry = {
            "name": target["name"],
            "source": target["display"],
            "kind": target["kind"],
            "path": str(placement["path"]),
            "action": placement["action"],
            "git": git_metadata(placement["path"]),
            "inventory": inventory(placement["path"]),
        }
        if placement.get("warning"):
            entry["warning"] = placement["warning"]
        repos.append(entry)

    manifest = {
        "schema": "owasp-scan-manifest/1",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workspace": str(workspace.resolve()),
        "repos": repos,
        "errors": errors,
    }
    manifest_path = workspace / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(json.dumps({
        "ok": bool(repos),
        "manifest": str(manifest_path),
        "repos": [
            {
                "name": repo["name"],
                "source": repo["source"],
                "commit": repo["git"]["short_commit"],
                "branch": repo["git"]["branch"],
                "files": repo["inventory"]["files"],
                "languages": list(repo["inventory"]["languages"])[:5],
                "action": repo["action"],
            }
            for repo in repos
        ],
        "errors": errors,
    }, indent=2))
    return 0 if repos else 1


if __name__ == "__main__":
    sys.exit(main())
