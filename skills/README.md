# Skills

Self-describing capabilities an agent can load. Each skill is a directory
containing a `SKILL.md` (name, description and instructions) plus any scripts it
needs.

| Skill | Purpose |
| --- | --- |
| [owasp-security-skill](owasp-security-skill/SKILL.md) | Scan repositories for OWASP security issues and write a timestamped Markdown report |
| [jira-updates-skill](jira-updates-skill/SKILL.md) | File the findings from a scan report as Jira issues, idempotently |

## Layout

```
skills/<skill-name>/
├── SKILL.md      instructions and metadata
└── scripts/      Python helpers, standard library only
```

Shared inputs live at the repository root rather than inside a skill:
[patterns/](../patterns/) for detection rules and [templates/](../templates/)
for file shapes.

`jira-updates-skill` reads its Jira settings from a git-ignored `.env` at the
repository root; copy [templates/jira.env.template](../templates/jira.env.template)
to create it. The API token in it is a live credential and must never be printed
or committed.
