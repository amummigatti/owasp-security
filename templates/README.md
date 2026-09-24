# Templates

Starting points for files that skills and agents produce or consume. Copy one,
fill it in, and pass it to the relevant script.

| File | Used for |
| --- | --- |
| [standards.template.json](standards.template.json) | The OWASP standards a reviewer consulted, merged into the taxonomy snapshot with `fetch_owasp_taxonomy.py --merge` |
| [finding.template.json](finding.template.json) | A finding found by reading the code rather than by a pattern, added to the reviewed findings file |
| [jira.env.template](jira.env.template) | The Jira settings `jira-updates-skill` reads; copy to `.env` at the repository root and fill in |

## A note on .env

`jira.env.template` carries no values on purpose. The real file, `.env`, is
git-ignored because it holds a Jira API token, which grants the same access to
Jira as the account that created it. Never commit it and never print its contents.
