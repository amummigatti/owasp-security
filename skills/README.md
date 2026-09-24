# Skills

Self-describing capabilities an agent can load. Each skill is a directory
containing a `SKILL.md` (name, description and instructions) plus any scripts it
needs.

| Skill | Purpose |
| --- | --- |
| [owasp-security-skill](owasp-security-skill/SKILL.md) | Scan repositories for OWASP security issues and write a timestamped Markdown report |

Planned: `jira-updates-skill`.

## Layout

```
skills/<skill-name>/
├── SKILL.md      instructions and metadata
└── scripts/      Python helpers, standard library only
```

Shared inputs live at the repository root rather than inside a skill:
[patterns/](../patterns/) for detection rules and [templates/](../templates/)
for file shapes.
