# Agents

Agent definitions. An agent orchestrates one or more skills from
[skills/](../skills/) to complete a larger task.

| Agent | Purpose |
| --- | --- |
| [owasp-security-agent](owasp-security-agent/AGENT.md) | Runs `owasp-security-skill` to scan repositories, then asks whether to log the findings in Jira and, on a yes, runs `jira-updates-skill` |

## How the OWASP agent behaves

1. Scans the repositories you name and writes a timestamped report to `reports/`.
2. Asks whether to log the findings as Jira bugs, stating how many there are and
   which Jira project and epic they would go to.
3. **Yes**: files the bugs and verifies they all reached Jira.
   **No**: says the report is ready to view at its location, and stops without
   contacting Jira.

Jira is never touched before you answer, and an unclear reply is not treated as yes.

## Layout

```
agents/<agent-name>/
└── AGENT.md      name, description, the skills it runs, and its workflow
```

An agent definition is plain Markdown with a small metadata block, so any runtime
that can follow written instructions and load the skills it names can use it.
