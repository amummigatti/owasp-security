# Patterns

Detection rules that skills load at run time. Keeping them here, outside any one
skill, lets them be reviewed, versioned and extended on their own.

| File | Used by |
| --- | --- |
| [owasp-scan-patterns.json](owasp-scan-patterns.json) | `skills/owasp-security-skill` (`scan_repos.py`) |

## Conventions

- Rules carry **CWE numbers, not OWASP category ids**. Category ids are resolved
  at run time from the taxonomy fetched from owasp.org, so a rule keeps
  classifying correctly when OWASP renumbers its categories.
- A pattern finds places worth reading; it does not prove a vulnerability. Every
  hit is reviewed before it reaches a report.
- Add a rule when a repository uses a framework or sink the existing rules miss.
  Give it an `explain` and a `remediation`, and choose `confidence` honestly.
