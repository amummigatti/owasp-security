---
name: jira-updates-skill
description: >-
  File the findings from an OWASP security scan report as Jira issues, one issue
  per finding, under an optional epic, and keep them up to date on later runs
  without creating duplicates. Use this skill whenever someone asks to log, file,
  raise or create Jira issues, bugs or tickets from a security report or scan
  output; to push OWASP findings into Jira; to sync a security report with a
  tracker; or to check that findings already reached Jira. Also use it after
  running owasp-security-skill when the person wants the results tracked rather
  than only written up, and when they ask to re-run or refresh tickets from an
  updated report.
compatibility: >-
  Needs Python 3.9+ (standard library only), network access to the Jira site, and
  a .env file holding the Jira settings (see templates/jira.env.template). Works
  with Jira Cloud (email + API token) and Jira Data Center (personal access
  token via JIRA_AUTH_TYPE=bearer).
---

# Filing OWASP findings in Jira

## What this skill is for

An OWASP scan report is evidence; a tracker is where work actually gets
scheduled. This skill moves each finding from the report into Jira as a properly
filled-in issue, and - just as importantly - keeps doing so on later runs without
turning the backlog into a pile of duplicates.

The report is the input, not a database. Whatever a human approved in that
Markdown file is exactly what gets filed, which means nobody has to wonder
whether the tickets reflect the document they signed off on.

## Handling the API token

The token in `JIRA_API_TOKEN` grants the same access to Jira that its owner has.
Treat it as a live credential:

- **Never print it, echo it, or read the `.env` file back to the user.** Do not
  `cat .env`, do not include it in a command you display, and do not put it in a
  commit, an issue or a message. The scripts redact it from their own error
  output; your own commands need the same care.
- **Never ask the user to paste the token into the conversation.** If the
  configuration is incomplete, tell them which keys are missing and ask them to
  fill those in `.env` themselves. Point them at
  `id.atlassian.com/manage-profile/security/api-tokens` to create one, and at
  `templates/jira.env.template` for the file's shape.
- **If a token is exposed anyway**, say so plainly and tell the user to revoke it
  at that same page and issue a replacement. A token that reached a terminal
  transcript or a log should be considered disclosed.
- `.env` is listed in `.gitignore`. If you ever see it staged, stop and unstage
  it rather than committing "just this once".

## Inputs

1. **The report**: an `owasp-security-report-<timestamp>.md` produced by
   `owasp-security-skill`, normally the most recent file in `reports/`.
2. **`.env` at the repository root**, copied from
   [templates/jira.env.template](../../templates/jira.env.template):
   `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_ID`,
   `JIRA_ISSUE_TYPE`, and optionally `JIRA_EPIC_ID` for the epic to file under.

All three scripts live in `scripts/` next to this file and take `--help`.

## Workflow

### Step 1 - Check the configuration and the project

```bash
python scripts/jira_client.py --check
```

This authenticates, then reports the project, the issue type, **which fields the
project marks required**, and which priorities its scheme offers. Read the
output before filing anything: a project that requires a field this skill does
not know about will reject every create, and it is much better to learn that from
one check than from thirty failed calls.

If it reports missing configuration, name the missing keys to the user and ask
them to fill `.env`. Do not guess values, and do not ask for the token in chat.

### Step 2 - Dry run

```bash
python scripts/sync_jira_issues.py --report reports/owasp-security-report-<stamp>.md --dry-run
```

Nothing is written. The output lists, per finding, whether it would be created or
updated, the priority chosen for its severity, and the labels. Check that the
count matches the report's findings total and that no rejected candidate has crept
in, then show the user what is about to be filed and get their agreement. Filing
into someone's tracker is visible to their whole team, so it is worth one
confirmation.

### Step 3 - File the issues

```bash
python scripts/sync_jira_issues.py --report reports/owasp-security-report-<stamp>.md \
    --out .owasp-workspace/jira-sync.json
```

For each finding not already in Jira it creates an issue with:

- **Summary** in the form `[repo name] [component] - Summary sentence`, for
  example `[open-webui] [backend/env] - Auth cookie Secure flag defaults to off`.
  The component is derived from the file path: the top-level directory plus the
  module name, or the enclosing directory when the file name says nothing
  (`index.ts`, `main.py`, `+page.svelte`), or the file itself at the repository
  root (`Dockerfile`). It is deterministic, so a finding keeps the same summary on
  every run. The OWASP category and severity are in the labels instead.
- **Priority** derived from the finding's severity, mapped onto a priority the
  project actually offers (critical→Highest, high→High, medium→Medium, low→Low,
  info→Lowest, with fallbacks for schemes that use Blocker/Major/Minor).
- **Description** with `Current issue` (why it matters, plus the reviewer's
  notes), `Where` (repository, commit, file and line), `Evidence`,
  `Expected fix`, `Classification` (OWASP category, CWEs, severity, confidence,
  review status) and `Provenance` (report file, generation time, the OWASP rule
  set and when it was read, and the finding id).
- **Labels**: `owasp`, `security`, the category (`owasp-a02-2025`), the severity,
  each CWE, the repository, and a fingerprint label such as
  `owasp-fp-77804e3ec231`.
- **Parent**: the epic from `JIRA_EPIC_ID`, when set.
- **A comment** recording that the agent logged it, with the run date and the
  report it came from.

For findings already in Jira it updates only what it owns (priority and labels,
when they changed), strikes through its previous status comment, and adds a fresh
one. It never edits the summary, the description or anyone else's comments, and
it never changes an issue's status - if a team closed something, that is their
decision to revisit, and the new comment tells them the finding is still present.

Useful flags: `--min-severity high` to file only the serious findings,
`--include-verdict confirmed` to leave the needs-verification ones out of the
tracker, and `--agent-name` if the comments should be attributed differently.

### Step 4 - Verify

```bash
python scripts/verify_jira_issues.py --report reports/owasp-security-report-<stamp>.md \
    --out .owasp-workspace/jira-verification.json
```

The sync reports its own success, which is the weakest possible evidence. This
reads the report again, asks Jira what it actually holds, and compares: every
finding has an issue, each sits under the configured epic, priorities match
severities, and each has a current agent comment. It exits non-zero if anything
is missing.

**If findings are missing**, re-run step 3 with the same report and filters. The
sync is idempotent, so it files only what is absent. If they are still missing
after a retry, read the per-finding `error` in the sync output and tell the user
plainly what Jira refused and why - a required field, a permission, a rate limit
- rather than reporting success. Use the same filters in both steps, or
verification will look for findings the sync was never asked to file.

### Step 5 - Report back

Tell the user: how many issues were created, how many already existed and were
updated, the epic they sit under, and the verification result. Link a couple of
the created issues by key. If anything failed, lead with that.

## How idempotency works

Each finding gets a fingerprint from its repository, its title and its file path,
stored as a label on the issue. A re-run searches Jira for that label, and
whatever it finds is the existing issue.

The fingerprint deliberately excludes the line number and the report's finding
id, because both shift when unrelated code changes, and an identity that shifts
files a duplicate. It does include the file path, so the same weakness in two
files is two issues - which is what you want, since they are fixed separately.

Two consequences worth knowing:

- **If someone removes the fingerprint label, the next run files a duplicate.**
  The description says so, to discourage label tidying.
- **If a finding's title changes** (because the pattern rule was reworded, or a
  reviewer rewrote it), the next run treats it as new and files a second issue.
  When you deliberately reword a finding, either accept the duplicate and close
  the old one, or move the old fingerprint label onto the new wording by hand.

## When the project rejects an issue

The preflight catches the usual causes before anything is written:

- **Issue type missing**: the output lists the types that do exist; set
  `JIRA_ISSUE_TYPE` to one of them.
- **No Labels field on the create screen**: idempotency depends on it, so the run
  stops. Add Labels to the screen, or choose an issue type that has it.
- **A required field this skill cannot fill**: fields with a fixed set of options
  are filled with their first allowed value and reported; anything else stops the
  run so you can give it a project-level default. `--force` tries anyway.
- **`JIRA_EPIC_ID` set but no parent or Epic Link field**: clear the variable to
  file at the top level, or use an issue type that can sit under an epic.

Authentication failures are worth reading precisely: 401 or 403 almost always
means the email and token pair is wrong for that site, while 404 usually means
`JIRA_BASE_URL` or `JIRA_PROJECT_ID` is. Do not retry a 401 in a loop; it will
not start working.

## Tests

The behaviour that matters here is hard to check by hand against a real Jira,
because doing so means filing and then cleaning up real tickets. It is covered
against an in-memory Jira instead:

```bash
python -m unittest discover -s tests -v
```

This asserts that a second run creates nothing, that the previous comment ends up
struck through while exactly one reads as current, that a human's comment is never
struck, that a severity change updates the priority and is noted, that `--dry-run`
writes nothing, and that the token never appears in an error message. Run it after
changing any of these scripts.
