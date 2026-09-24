<!-- Author: Akshatha Mummigatti -->
# Spec: owasp-security-agent

## Purpose

Give a user one entry point for a security review: scan repositories against current
OWASP guidance, then, if the user agrees, track the findings in Jira.

## Input

The repository URL, or several, from the user. Jira settings come from the git-ignored
`.env`, not from the conversation.

## Behaviour

1. Run `owasp-security-skill` on the repositories, producing a timestamped report.
2. Ask the user whether to log the findings as bugs in Jira. The question states where
   the report is, how many findings it holds by severity, and the Jira site, project
   and epic the bugs would go to.
3. If the answer is yes, run `jira-updates-skill` on that report: file the bugs, then
   verify that every finding reached Jira.
4. If the answer is no, say that the report is ready to view at its location, and stop.

## Rules

- The scan always runs first, and Jira is never contacted before the user answers.
- Only an explicit yes starts the Jira step. An ambiguous reply is not consent.
- A no ends the run without any contact with Jira.
- A scan with no findings skips the question, since there is nothing to file.
- The API token is never printed, echoed, read back or requested in the conversation.
- The agent files only the report it just produced.
- The agent does not commit or push.

## Output

- `reports/owasp-security-report-<UTC timestamp>.md`, always.
- Jira issues, one per finding, under the configured epic, only after a yes.
- A closing message giving the report location and, if bugs were filed, how many were
  created or updated, the epic, some issue keys and the verification result.

## Out of scope

Deciding which findings are real (the scan's review step does that), transitioning or
closing Jira issues, and any tracker other than Jira.
