#!/usr/bin/env python3
"""Checks that the agent definition still points at things that exist.

An agent is prose, so nothing fails when a skill is renamed or a script moves; the
agent just tells its reader to run something that is not there. These tests catch
that: the skills it names must exist, every relative link must resolve, and every
script path it mentions must be a real file. They also pin the two behaviours the
agent exists for: Jira is asked about before it is used, and a "no" never touches it.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "agents" / "owasp-security-agent"
AGENT_FILE = AGENT_DIR / "AGENT.md"


def read_frontmatter(text: str) -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, "AGENT.md must start with a YAML frontmatter block"
    data: dict = {}
    current = None
    for line in match.group(1).splitlines():
        if re.match(r"^\S[^:]*:", line):
            key, _, value = line.partition(":")
            current = key.strip()
            value = value.strip()
            if value in (">", ">-", "|", "|-"):
                data[current] = ""      # folded text follows on indented lines
            elif value == "":
                data[current] = []      # a list follows
            else:
                data[current] = value
        elif line.strip().startswith("- ") and isinstance(data.get(current), list):
            data[current].append(line.strip()[2:].strip())
        elif current and isinstance(data.get(current), str):
            data[current] = (data[current] + " " + line.strip()).strip()
    return data


def flatten(text: str) -> str:
    """Prose is wrapped at arbitrary columns, so phrase checks compare on one line."""
    return " ".join(text.split())


class AgentDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.text = AGENT_FILE.read_text(encoding="utf-8")
        self.meta = read_frontmatter(self.text)
        self.flat = flatten(self.text)

    def test_name_matches_directory(self):
        self.assertEqual(self.meta["name"], AGENT_DIR.name)

    def test_has_a_description_that_says_when_to_use_it(self):
        self.assertGreater(len(self.meta["description"]), 80)
        self.assertIn("Jira", self.meta["description"])

    def test_runs_the_two_skills_in_order(self):
        self.assertEqual(self.meta["skills"], ["owasp-security-skill", "jira-updates-skill"])

    def test_every_named_skill_exists(self):
        for skill in self.meta["skills"]:
            self.assertTrue((ROOT / "skills" / skill / "SKILL.md").is_file(), skill)

    def test_relative_links_resolve(self):
        links = re.findall(r"\]\((\.\./[^)#\s]+)", self.text)
        self.assertTrue(links, "expected links to the skills")
        for link in links:
            self.assertTrue((AGENT_DIR / link).resolve().exists(), link)

    def test_script_paths_exist(self):
        paths = set(re.findall(r"(?:skills|templates)/[\w./-]+\.(?:py|template)", self.text))
        self.assertTrue(paths, "expected the agent to reference scripts or templates")
        for path in paths:
            self.assertTrue((ROOT / path).is_file(), path)

    def test_scan_comes_before_the_question_and_the_question_before_jira(self):
        scan = self.text.index("### Step 1 - Scan")
        ask = self.text.index("### Step 2 - Ask for permission")
        file_bugs = self.text.index("### Step 3a")
        self.assertLess(scan, ask)
        self.assertLess(ask, file_bugs)

    def test_the_no_path_reports_the_location_and_never_touches_jira(self):
        section = flatten(self.text.split("### Step 3b")[1].split("### Any other answer")[0])
        self.assertIn("ready to view", section)
        self.assertIn("do not touch Jira in any way", section)
        self.assertNotIn("jira_client", section, "the no path must not run any Jira script")

    def test_only_an_explicit_yes_counts(self):
        self.assertIn("Only an explicit yes counts", self.flat)
        self.assertIn("An unclear answer is never a yes", self.flat)

    def test_a_scan_with_no_findings_skips_the_question(self):
        self.assertIn("If the report has no findings", self.flat)

    def test_the_token_is_never_exposed(self):
        self.assertIn("must never be printed, echoed or requested in chat", self.flat)
        self.assertIn("Never print, echo or read back `.env`", self.flat)

    def test_does_not_commit_or_push(self):
        self.assertIn("it does not commit or push", self.flat)

    def test_vendor_neutral(self):
        for word in ("Claude", "Anthropic", "Cursor", "Copilot", ".claude"):
            self.assertNotIn(word, self.text)


class FrontmatterParserTests(unittest.TestCase):
    def test_folded_description_and_lists(self):
        meta = read_frontmatter("---\nname: a\ndescription: >-\n  one two\n  three\nskills:\n  - x\n  - y\n---\nbody")
        self.assertEqual(meta["name"], "a")
        self.assertEqual(meta["description"], "one two three")
        self.assertEqual(meta["skills"], ["x", "y"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
