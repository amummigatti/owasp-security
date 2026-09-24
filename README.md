# OWASP Security Analysis

Reusable [Agent Skills](https://code.claude.com/docs/en/skills) for auditing source repositories
against the current OWASP guidance, and for reporting the results onward to Jira.

The skills here are plain Markdown + Python. They are not tied to any single editor or vendor —
any agent runtime that supports the `SKILL.md` convention (Claude Code, the Claude Agent SDK,
Claude.ai, or your own harness) can load them, and the Python scripts run standalone from a shell.

## Contents

| Path | What it is |
| --- | --- |
| [.claude/skills/owasp-security-skill/](.claude/skills/owasp-security-skill/) | Scans one or more repositories for OWASP security issues and writes a timestamped Markdown report |
| [reports/](reports/) | Generated reports, one timestamped file per run, kept as evidence |

Planned (added in later commits): a `jira-updates-skill` that files the report's findings as Jira
issues, and an `owasp-security-agent` that runs both skills in sequence.

## Requirements

- Python 3.9+ (standard library only — no `pip install` needed)
- `git` on `PATH` (used to clone the repositories under review)
- Network access to `owasp.org` so the skill can read the current OWASP rule set at run time,
  and to whatever host serves the repositories being scanned

## Install

Clone this repository and copy (or symlink) the skill directories into wherever your agent
runtime looks for skills:

```bash
git clone https://github.com/<your-org>/owasp-security-analysis.git

# Project-scoped: available to anyone working in this repo, no copying needed.
# Claude Code picks up .claude/skills/ automatically.

# User-scoped: available in every project on your machine.
cp -r owasp-security-analysis/.claude/skills/owasp-security-skill ~/.claude/skills/
```

## Usage

Ask your agent for a scan and name the repositories:

```
Run an OWASP security scan on https://github.com/OWASP/NodeGoat
```

The skill clones each repository, reads the current OWASP taxonomy from the OWASP website,
scans the code, triages what it finds, and writes
`reports/owasp-security-report-<UTC timestamp>.md` grouped by repository.

Each script is also usable on its own — see
[the skill's README-equivalent, SKILL.md](.claude/skills/owasp-security-skill/SKILL.md), and run any
script with `--help`.

## License

MIT — see [LICENSE](LICENSE).
