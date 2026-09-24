---
name: owasp-security-skill
description: >-
  Scan one or more source repositories for OWASP security issues and produce a
  timestamped Markdown report grouped by repository. Use this skill whenever
  someone asks for an OWASP scan, a security audit, a vulnerability review or a
  security assessment of a repository, names the OWASP Top 10 or an OWASP
  standard, or asks whether a repo has issues like injection, broken access
  control, hardcoded secrets, weak crypto, insecure deserialization or supply
  chain problems -- even if they never say the word "OWASP". Also use it when
  someone gives you one or more repository URLs and asks what is wrong with them
  security-wise, or asks for security findings they can file as tickets.
compatibility: >-
  Needs Python 3.9+ (standard library only), git on PATH, and network access to
  owasp.org plus the repository host. A web fetch tool is useful but not required.
---

# OWASP security scan

## What this skill is for

Someone hands you repository URLs and wants to know where the code stands
against the OWASP guidance that is current **today**. The deliverable is one
Markdown report, timestamped, grouped by repository, that a developer can work
through and a reviewer can trust months later because it records exactly what
was scanned and what it was graded against.

Two things make this different from running a grep over the code:

1. **The rules come from OWASP at run time.** The OWASP Top 10 is re-published
   every few years, categories get renamed and renumbered, and standards
   projects change. This skill reads the live pages instead of carrying a copy,
   so it never reports against a list that has moved on. Nothing in this skill
   file enumerates the categories on purpose -- the fetched taxonomy is the
   source of truth.
2. **Pattern matching is the first pass, not the answer.** The scanner finds
   candidate locations quickly; you then read the code around each one. The
   single most-reported OWASP failure -- missing access control -- is largely
   invisible to regular expressions, so a report that only echoes grep hits both
   misses the worst problems and cries wolf about sanitised code.

## The one input you need

The repository URL, or several. Accepted forms: a full git URL
(`https://github.com/owner/app`, `git@host:team/app.git`), the GitHub shorthand
`owner/app`, or a path to a checkout already on disk.

If the user has not given you one, ask for it and stop -- there is nothing
useful to scan without it. If they gave you several, scan them all in one run:
the report is designed to hold multiple repositories, grouped, so a team can see
its whole surface in one document.

Before cloning anything, make sure the user is entitled to scan what they named.
Scanning your own or your employer's code is routine; scanning a third party's
private code is not yours to authorise. Public repositories are fine to read.

## Workflow

Run these five steps in order. Every step writes a file, so a later step can be
re-run without repeating the earlier ones, and the intermediate artifacts double
as evidence of how the report was produced.

Pick a workspace directory for the intermediate files -- `.owasp-workspace/` in
the current project is the convention, and it is already git-ignored in this
repository. The final report goes to `reports/`.

All four scripts live in `scripts/` next to this file and take `--help`.

### Step 1 - Learn the current OWASP rules

```bash
python scripts/fetch_owasp_taxonomy.py --out-dir .owasp-workspace
```

This reads `https://top10.owasp.org/2025/` and every category page beneath it,
and writes `owasp-taxonomy.json` (used by the next two steps) plus a timestamped
Markdown snapshot. Read the snapshot, or the JSON, before you start reviewing:
the category descriptions and the "how to prevent" guidance are what you are
grading against, and they are worth having in mind rather than working from
memory of an older Top 10.

Two things the script cannot do for you:

- **The standards projects.** `https://owasp.org/projects?view=all&category=Standards`
  renders in the browser, so a plain HTTP fetch returns an empty shell. Use your
  own web fetch or search tool to read that index and skim the standards that
  apply to the code in front of you -- the verification standard is the usual
  one for web and API code, with mobile, IoT or AI standards where relevant.
  Then record what you actually consulted so it lands in the evidence:

  ```bash
  # standards.json follows templates/standards.template.json at the repository root
  python scripts/fetch_owasp_taxonomy.py --out-dir .owasp-workspace --merge standards.json
  ```

  Keep the `checks` list to the handful of requirements you will genuinely apply
  to this codebase. A long copied list is noise; three requirements you actually
  check are evidence.
- **Anything else on owasp.org worth reading for this codebase** -- a cheat
  sheet for the framework in use, for instance. Pass static pages with
  `--url <page>` and they are captured into the taxonomy file too.

If the fetch fails outright (no network, site down), say so plainly in your
report's method section and fall back to reading the pages with your web tool.
Do not silently substitute a remembered category list: a report that claims to
grade against current OWASP guidance while doing something else is worse than
one that admits it ran offline.

### Step 2 - Fetch the repositories

```bash
python scripts/prepare_repos.py --workspace .owasp-workspace \
    --repo https://github.com/owner/app --repo owner/other-app
```

Clones each target shallowly and writes `manifest.json` recording the exact
commit, branch and file inventory per repository. The commit is what makes the
report reproducible -- "we found this" only means something next to "at this
commit".

Check the printed `errors` array. A private repository or a typo shows up here;
tell the user which targets failed and why rather than quietly scanning fewer
repositories than they asked for.

### Step 3 - Sweep for candidates

```bash
python scripts/scan_repos.py --manifest .owasp-workspace/manifest.json \
    --taxonomy .owasp-workspace/owasp-taxonomy.json \
    --out .owasp-workspace/findings.json
```

Applies `patterns/owasp-scan-patterns.json` (at the repository root) and classifies each hit by mapping its
CWE through the taxonomy you just fetched. Every candidate comes out as
`verdict: "unreviewed"`.

The pattern file is a starting set, not the rule book. When a repository uses a
framework or a sink the patterns miss -- a template engine, an ORM, an RPC layer
they do not know about -- add a rule and re-run. Give the rule CWE numbers rather
than an OWASP category id, so it keeps classifying correctly when OWASP
renumbers.

### Step 4 - Review (the step that makes the report worth reading)

Work through the candidates and write a reviewed copy of the findings file:

```bash
cp .owasp-workspace/findings.json .owasp-workspace/findings.reviewed.json
# then edit the reviewed copy
```

For each candidate, open the file at the reported line, read enough of the
surrounding code to decide, and set:

- `verdict` -- `confirmed`, `false_positive`, or `needs_verification` when the
  answer depends on runtime configuration or domain knowledge you do not have.
- `analysis` -- one or two sentences of what you found: how untrusted input
  reaches the sink, or why it cannot. This is the field readers trust, so it
  should say something specific about *this* code, not restate the rule.
- `severity` -- adjust it. The pattern file guesses from the rule alone; you can
  see whether the sink is reachable by an unauthenticated request (raise it) or
  sits behind an admin-only maintenance command (lower it).

Rejecting candidates is as valuable as confirming them. An MD5 used for cache
keys, a `.pem` holding only a public certificate, a template literal built from
constants -- mark them `false_positive` with the reason. They appear in an
appendix, which is what stops the next reader re-investigating them.

Then look for what the scan structurally cannot find. Budget real time here.
Read, at minimum:

- **Route and handler definitions**, checking authorization on each one, not
  just authentication. Who can call this, and is that enforced centrally or
  re-implemented per handler? Can an id in the path belong to another tenant?
  This is where the highest-severity findings usually are.
- **The authentication and session code** -- token issuance and validation,
  password storage, session lifetime and invalidation, multi-factor and reset
  flows.
- **The boundaries where untrusted input arrives** and where it ends up: query
  builders, command execution, file paths, deserializers, template rendering,
  outbound HTTP.
- **Configuration and deployment files** for defaults that are unsafe in
  production, and for how secrets reach the application.
- **Error handling and logging**, for failures that are swallowed, and for
  security-relevant events that nothing records or alerts on.

Add findings for anything you see, following `templates/finding.template.json`
at the repository root: `detector: "manual-review"`, an `owasp_id` taken from the
fetched taxonomy, and a `file`/`line` a developer can open. Findings you reasoned your way to are
usually the most valuable part of the report.

Two rules about evidence. Keep snippets short -- a line or two, enough to
recognise the problem. And never paste a live secret into the report: the
scanner masks them, so keep it masked and say clearly that the value must be
treated as disclosed and rotated, because committed secrets stay in git history
after the file changes.

### Step 5 - Render the report

```bash
python scripts/render_report.py --findings .owasp-workspace/findings.reviewed.json \
    --taxonomy .owasp-workspace/owasp-taxonomy.json --out-dir reports
```

Writes `reports/owasp-security-report-<UTC timestamp>.md` and prints the path.
Every run produces a new file; that is deliberate, so a later scan never erases
the evidence of an earlier one.

Read the report before you hand it over. If the summary table disagrees with
what you found, or a section reads as though a machine wrote it and no one
checked, fix the findings file and render again.

Then tell the user, briefly: where the report is, how many repositories were
scanned, the counts by severity, the two or three findings you would fix first,
and anything you could not complete (a repository that failed to clone, a
category you could not assess from source alone).

## Judging severity

Severity is about consequence and reachability, not about which rule fired.
Something an unauthenticated request can reach that exposes or corrupts other
users' data is critical or high. The same weakness behind an admin-only path, or
reachable only by someone who already holds credentials, is lower. A weak
primitive in a non-security context -- a fast hash over a cache key -- may be
informational or not a finding at all.

Where you are unsure, say so in `analysis` and use `needs_verification` rather
than inflating or hiding it. A report that distinguishes what was proven from
what was suspected is one a team will act on twice.

## Artifacts this skill produces

| Path | Purpose |
| --- | --- |
| `reports/owasp-security-report-<stamp>.md` | The deliverable, grouped by repository |
| `.owasp-workspace/owasp-taxonomy.json` | The OWASP rule set used, with fetch time |
| `.owasp-workspace/owasp-taxonomy-<stamp>.md` | Readable snapshot of that rule set |
| `.owasp-workspace/manifest.json` | Repositories and exact commits scanned |
| `.owasp-workspace/findings.json` | Raw pattern candidates |
| `.owasp-workspace/findings.reviewed.json` | Findings after your review |

Finding ids (`<repo>-001`) are stable between the reviewed findings file and the
report, so a later step -- filing tickets, for instance -- can reference a
finding without re-parsing prose.

## When there is nothing to report

Say that, and say what was checked. "No findings across 412 files at commit
abc1234, having reviewed the route definitions, authentication flow and input
handling" is a useful result. An empty report dressed up with filler is not, and
neither is inventing a low-severity finding to look thorough.
