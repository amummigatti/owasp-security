# OWASP Security Analysis

Reusable skills and agents for auditing source repositories against the current
OWASP guidance, and for reporting the results onward to Jira.

A skill is a directory with a `SKILL.md` (name, description, instructions) and
Python helper scripts. Any agent runtime that can load skills in that format can
use them, and every script also runs standalone from a shell.

## Repository layout

| Path | Contents |
| --- | --- |
| [skills/](skills/) | Skills: one directory each, with `SKILL.md` and `scripts/` |
| [agents/](agents/) | Agents that orchestrate skills |
| [patterns/](patterns/) | Detection rules the skills load at run time |
| [templates/](templates/) | Starting-point shapes for files skills consume |
| [specs/](specs/) | Requirements for each skill and agent |
| [docs/](docs/) | Design notes and longer-form documentation |
| [tests/](tests/) | Automated tests and synthetic fixtures |
| [reports/](reports/) | Generated reports, one timestamped file per run, kept as evidence |

## Available skills

| Skill | Purpose |
| --- | --- |
| [owasp-security-skill](skills/owasp-security-skill/SKILL.md) | Scans one or more repositories for OWASP security issues and writes a timestamped Markdown report grouped by repository |

Planned in later commits: `jira-updates-skill`, which files the report's findings
as Jira issues, and `owasp-security-agent`, which runs both skills in sequence.

## Requirements

- Python 3.9+ (standard library only, no `pip install`)
- `git` on `PATH`, to clone the repositories under review
- Network access to `owasp.org`, so the skill reads the current OWASP rules at
  run time, and to the host serving the repositories being scanned

## Install

Clone the repository and point your agent runtime at the `skills/` directory:

```bash
git clone https://github.com/<your-org>/owasp-security-analysis.git
```

Keep `skills/` and `patterns/` together: the scripts locate the detection rules in
`patterns/` by searching upward from the script, then from the working directory.
If you install a skill somewhere else, pass `--rules <path to owasp-scan-patterns.json>`
to `scan_repos.py`.

## Usage

Ask your agent for a scan and name the repositories:

```
Run an OWASP security scan on https://github.com/OWASP/NodeGoat
```

The skill reads the current OWASP rules, clones each repository, scans and reviews
the code, and writes `reports/owasp-security-report-<UTC timestamp>.md` grouped by
repository.

The scripts can be run on their own; each supports `--help`:

```bash
python skills/owasp-security-skill/scripts/fetch_owasp_taxonomy.py --out-dir .owasp-workspace
python skills/owasp-security-skill/scripts/prepare_repos.py --workspace .owasp-workspace --repo <url>
python skills/owasp-security-skill/scripts/scan_repos.py --manifest .owasp-workspace/manifest.json \
    --taxonomy .owasp-workspace/owasp-taxonomy.json --out .owasp-workspace/findings.json
python skills/owasp-security-skill/scripts/render_report.py --findings .owasp-workspace/findings.json \
    --taxonomy .owasp-workspace/owasp-taxonomy.json --out-dir reports
```

The full workflow, including the review step between scanning and rendering, is in
[SKILL.md](skills/owasp-security-skill/SKILL.md).

## License

MIT, see [LICENSE](LICENSE).
