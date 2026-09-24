<!-- Author: Akshatha Mummigatti -->
# Spec: owasp-security-skill

## Purpose

Find OWASP security issues in one or more source repositories and report them in
a single structured document that a developer can act on and a reviewer can trust
later.

## Input

One value from the user: the URL of the repository, or of several. A git URL,
the `owner/repo` shorthand, or a path to a local checkout are accepted.

## Behaviour

1. Learn the current OWASP rule set from the OWASP website
   (https://top10.owasp.org/2025/ and the OWASP standards projects) at run time.
   The categories are not listed in this spec or in the skill; the website is the
   source of truth, so the skill follows OWASP when it publishes a new list.
2. Fetch each repository and record the exact commit scanned.
3. Scan each repository for issues that match the OWASP rules, then review every
   candidate against the surrounding code to confirm or reject it, and look for
   issues that pattern matching cannot see, such as missing authorization.
4. Produce the report.

## Output

A Markdown file, `reports/owasp-security-report-<UTC timestamp>.md`.

- Issues are **grouped by repository**, then by OWASP category, then by severity.
- Each issue records its location, severity, CWE, evidence, why it matters and a
  recommended fix.
- A new timestamped file is written on every run. Earlier reports are never
  overwritten, so each one stands as evidence of that scan.
- The report states its scope and limits, and the OWASP guidance and commit it
  was produced against.

## Constraints

- Python 3.9+ scripts using the standard library only.
- Nothing specific to a particular editor or vendor.
- Secrets found in source are masked in the report.
- Only repositories the user is entitled to scan.

## Out of scope

Dynamic testing, dependency CVE lookups, and filing tickets. The last is handled
by `jira-updates-skill`.
