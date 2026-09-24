# Agents

Agent definitions. An agent orchestrates one or more skills from
[skills/](../skills/) to complete a larger task.

Planned: `owasp-security-agent`, which runs `owasp-security-skill` and then
`jira-updates-skill` in sequence.

Each agent lives in its own directory (`agents/<agent-name>/`) with its
definition file and any supporting material.
