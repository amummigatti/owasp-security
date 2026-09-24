<!-- Author: Akshatha Mummigatti -->
# Spec: jira-updates-skill

## Purpose

Turn the findings in an OWASP scan report into tracked work in Jira, and keep the
tracker in step with the report on later runs without creating duplicates.

## Inputs

1. The Markdown report produced by `owasp-security-skill`
   (`reports/owasp-security-report-<UTC timestamp>.md`).
2. A `.env` file at the repository root, git-ignored, holding:
   - `JIRA_BASE_URL` - the Jira site (a UI URL is accepted and reduced to the origin)
   - `JIRA_EMAIL` - the Atlassian account the issues are filed as
   - `JIRA_API_TOKEN` - API token for that account
   - `JIRA_PROJECT_ID` - project key or numeric id
   - `JIRA_ISSUE_TYPE` - the issue type to create, for example Bug
   - `JIRA_EPIC_ID` - optional epic to file the issues under

   Real environment variables take precedence, so CI can inject the token as a
   secret. `templates/jira.env.template` is the committed, value-free copy.

## Behaviour

1. Read the report and take only what it reports as reviewed findings. Candidates the
   report lists as rejected during review are never filed, and findings still marked
   as not yet reviewed are left out unless explicitly requested.
2. Check the project before writing: the issue type exists, the Labels field is
   available, and whether any required field cannot be filled. Stop with an explanation rather than filing part of a report.
3. Create one issue per finding with every mandatory field populated: a tagged
   summary of the form `[repo name] [component] - Summary sentence` (component
   derived from the finding's file path), a description stating the current issue
   and the expected fix, labels for category, severity, CWE and repository, and the
   epic as parent when configured. Severity is carried by a label and the
   description; the Jira Priority field is deliberately never read or set.
4. Add a comment recording that the agent logged the issue, with the run date and
   the source report.
5. On a later run, do not duplicate. Find the existing issue by its fingerprint
   label, update only the fields this skill owns, strike through its own previous
   status comment, and add a new comment carrying the latest run date.
6. Verify afterwards that every finding in the report is present in Jira, and
   report anything missing or inconsistent.

## Output

- Jira issues, one per finding, under the configured epic.
- A run result JSON listing, per finding, the action taken and the issue key.
- A verification JSON, exiting non-zero when the tracker does not match the report.

## Constraints

- Python 3.9+, standard library only.
- The API token is never printed, echoed, logged or committed, and is redacted
  from error output.
- Nothing specific to a particular editor or vendor.
- Nothing is written to Jira unless the caller passes `--apply`; the default run is a
  preview.
- Text sent to Jira is redacted for credential-shaped values before it leaves the tool.
- Findings that share a fingerprint stop the run before anything is written.
- The skill edits only what it created: never an issue's status, summary or
  description on re-run, and never another author's comments.

## Identity model

A finding's identity is a fingerprint of repository, title and file path, stored
as a Jira label. The line number and the report's finding id are excluded because
both shift when unrelated code changes, and an identity that shifts produces
duplicates. Jira holds the state, so no local state file is needed and the skill
works from a fresh clone or a different machine.

## Out of scope

Transitioning or closing issues, deciding whether a finding is real (that happens
during the scan's review step), and any tracker other than Jira.
