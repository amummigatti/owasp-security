#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Configuration, Jira REST access and document building for the Jira skill.

Imported by sync_jira_issues.py and verify_jira_issues.py; also runnable on its
own as a connection check:

  python jira_client.py --check

Three things in here exist to avoid specific failures:

- **The token is never printed.** It is read from the environment or a .env file,
  held in memory, and every error message passes through redact() before it is
  raised. Jira echoes request context in some error bodies, and a traceback that
  leaks a credential into a terminal or a log is a new incident.
- **Required fields are discovered, not assumed.** Jira projects can mark almost
  any field mandatory, and a create call that omits one fails with a 400 that
  reads like a bug in this script. create_meta() reports what the project
  actually demands so the caller can fill it or explain precisely what is missing.
- **Transient failures are retried.** Jira Cloud rate-limits and returns 5xx
  under load. Retrying with backoff on those, and never on a 4xx that means the
  request itself was wrong, is the difference between a run that half-files a
  report and one that completes.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "/rest/api/3"
USER_AGENT = "jira-updates-skill"

REQUIRED_KEYS = ["JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_PROJECT_ID", "JIRA_ISSUE_TYPE"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]

_SECRETS = set()


def remember_secret(value: str) -> None:
    if value and len(value) >= 8:
        _SECRETS.add(value)


def redact(text: str) -> str:
    """Remove any known secret from a string before it is shown or raised."""
    result = str(text)
    for secret in _SECRETS:
        if secret and secret in result:
            result = result.replace(secret, "<redacted>")
    # Basic auth headers carry the token base64-encoded.
    result = re.sub(r"(Basic|Bearer)\s+[A-Za-z0-9+/=._\-]{8,}", r"\1 <redacted>", result)
    return result


class JiraError(RuntimeError):
    def __init__(self, status: int, messages, url: str = ""):
        self.status = status
        self.messages = messages if isinstance(messages, list) else [str(messages)]
        self.url = url
        super().__init__(redact("Jira API " + str(status) + " for " + url + ": " + "; ".join(self.messages)))


def parse_env_file(path: Path) -> dict:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def find_env_file(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit)
    if os.environ.get("JIRA_ENV_FILE"):
        return Path(os.environ["JIRA_ENV_FILE"])
    start = Path.cwd().resolve()
    for directory in [start] + list(start.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return Path(".env")


def normalize_base_url(raw: str) -> str:
    """Reduce any Jira URL to the site origin the REST API lives on.

    People copy the URL out of the browser, which is a UI deep link such as
    https://site.atlassian.net/jira/software/projects/AI/boards/1. The API is at
    the origin, so keep only scheme and host and drop the rest.
    """
    value = (raw or "").strip().rstrip("/")
    if not value:
        return ""
    if "//" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme + "://" + parsed.netloc


def normalize_issue_key(raw: str) -> str:
    """Accept AI-1, a browse URL, or a selected-issue URL and return the key."""
    value = (raw or "").strip()
    if not value:
        return ""
    match = re.search(r"([A-Za-z][A-Za-z0-9_]*-\d+)", value)
    return match.group(1).upper() if match else value


def load_config(env_path: str = "") -> dict:
    """Build config from the environment, falling back to the .env file.

    Real environment variables win, so CI can inject a token without editing a
    file, and a developer can keep one .env locally.
    """
    env_file = find_env_file(env_path)
    from_file = parse_env_file(env_file) if env_file.is_file() else {}

    def value(key: str, default: str = "") -> str:
        return (os.environ.get(key) or from_file.get(key) or default).strip()

    token = value("JIRA_API_TOKEN")
    remember_secret(token)

    config = {
        "base_url": normalize_base_url(value("JIRA_BASE_URL")),
        "email": value("JIRA_EMAIL"),
        "token": token,
        "project": value("JIRA_PROJECT_ID"),
        "issue_type": value("JIRA_ISSUE_TYPE", "Bug"),
        "epic": normalize_issue_key(value("JIRA_EPIC_ID")),
        "auth_type": (value("JIRA_AUTH_TYPE", "basic") or "basic").lower(),
        "label_prefix": value("JIRA_LABEL_PREFIX", "owasp"),
        "extra_labels": [item.strip() for item in value("JIRA_EXTRA_LABELS").split(",") if item.strip()],
        "env_file": str(env_file) if env_file.is_file() else "",
        "env_file_found": env_file.is_file(),
    }
    return config


def missing_config(config: dict) -> list:
    missing = []
    mapping = {"JIRA_BASE_URL": "base_url", "JIRA_API_TOKEN": "token",
               "JIRA_PROJECT_ID": "project", "JIRA_ISSUE_TYPE": "issue_type"}
    for key in REQUIRED_KEYS:
        if not config.get(mapping[key]):
            missing.append(key)
    # Jira Cloud basic auth is the account email plus an API token; the token
    # alone authenticates nothing.
    if config.get("auth_type") == "basic" and not config.get("email"):
        missing.append("JIRA_EMAIL")
    return missing


# --- Atlassian Document Format -------------------------------------------------
# The v3 API takes descriptions and comments as ADF rather than wiki markup.
# These helpers keep the call sites readable and make the strikethrough on re-run
# a structural operation rather than string munging.

def text(value: str, marks=None) -> dict:
    node = {"type": "text", "text": value if value else " "}
    if marks:
        node["marks"] = [{"type": mark} for mark in marks]
    return node


def paragraph(*nodes) -> dict:
    children = [node if isinstance(node, dict) else text(str(node)) for node in nodes]
    return {"type": "paragraph", "content": children or [text(" ")]}


def heading(value: str, level: int = 3) -> dict:
    return {"type": "heading", "attrs": {"level": level}, "content": [text(value)]}


def bullet_list(items) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [item if isinstance(item, dict) and item.get("type") == "paragraph"
                                             else paragraph(item)]}
            for item in items
        ],
    }


def code_block(value: str, language: str = "") -> dict:
    node = {"type": "codeBlock", "content": [text(value if value.strip() else " ")]}
    if language:
        node["attrs"] = {"language": language}
    return node


def document(*blocks) -> dict:
    content = [block for block in blocks if block]
    return {"type": "doc", "version": 1, "content": content or [paragraph(" ")]}


def strike_document(node):
    """Return a copy of an ADF node with every text run struck through.

    Code block contents are left alone: ADF does not allow marks on text inside a
    codeBlock, and sending them makes Jira reject the whole update.
    """
    if isinstance(node, list):
        return [strike_document(item) for item in node]
    if not isinstance(node, dict):
        return node
    copied = dict(node)
    if copied.get("type") == "codeBlock":
        return copied
    if copied.get("type") == "text":
        # Atlassian's document schema does not allow the code mark to be combined
        # with strike (Jira answers 400 INVALID_INPUT), so struck text drops its
        # code styling: a struck-through marker line reads fine as plain text.
        marks = [mark for mark in copied.get("marks", []) if mark.get("type") not in ("strike", "code")]
        marks.append({"type": "strike"})
        copied["marks"] = marks
        return copied
    if "content" in copied:
        copied["content"] = strike_document(copied["content"])
    return copied


def plain_text(node) -> str:
    """Flatten an ADF document to text, for matching our own past comments."""
    if isinstance(node, list):
        return " ".join(plain_text(item) for item in node)
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "text":
        return node.get("text", "")
    return plain_text(node.get("content", []))


# --- REST client --------------------------------------------------------------

class JiraClient:
    def __init__(self, config: dict, timeout: int = 40, retries: int = 3, dry_run: bool = False):
        self.config = config
        self.timeout = timeout
        self.retries = retries
        self.dry_run = dry_run
        self.base_url = config["base_url"]
        self.calls = 0
        if config.get("auth_type") == "bearer":
            self._auth = "Bearer " + config["token"]
        else:
            raw = (config.get("email", "") + ":" + config["token"]).encode("utf-8")
            self._auth = "Basic " + base64.b64encode(raw).decode("ascii")

    def _request(self, method: str, path: str, body=None, params=None, allow_status=()):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        last_error = None

        for attempt in range(self.retries + 1):
            request = urllib.request.Request(url, data=data, method=method)
            request.add_header("Authorization", self._auth)
            request.add_header("Accept", "application/json")
            request.add_header("User-Agent", USER_AGENT)
            if data is not None:
                request.add_header("Content-Type", "application/json")
            try:
                self.calls += 1
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", "replace")
                    return response.status, (json.loads(raw) if raw.strip() else {})
            except urllib.error.HTTPError as error:
                raw = ""
                try:
                    raw = error.read().decode("utf-8", "replace")
                except Exception:  # noqa: BLE001 - the body is best effort
                    pass
                if error.code in allow_status:
                    try:
                        return error.code, (json.loads(raw) if raw.strip() else {})
                    except json.JSONDecodeError:
                        return error.code, {}
                messages = self._error_messages(raw) or [error.reason or "request failed"]
                # 429 and 5xx are worth another try; a 400 means this request is
                # wrong and repeating it just wastes the user's rate limit.
                if error.code == 429 or 500 <= error.code < 600:
                    last_error = JiraError(error.code, messages, path)
                    if attempt < self.retries:
                        delay = self._retry_delay(error, attempt)
                        time.sleep(delay)
                        continue
                raise JiraError(error.code, messages, path)
            except (urllib.error.URLError, TimeoutError) as error:
                last_error = JiraError(0, "network error: " + str(getattr(error, "reason", error)), path)
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise last_error
        if last_error:
            raise last_error
        raise JiraError(0, "request failed", path)

    @staticmethod
    def _retry_delay(error, attempt: int) -> float:
        header = ""
        try:
            header = error.headers.get("Retry-After", "")
        except Exception:  # noqa: BLE001
            pass
        if header and header.strip().isdigit():
            return min(float(header.strip()), 60.0)
        return float(2 ** attempt)

    @staticmethod
    def _error_messages(raw: str) -> list:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return [redact(raw[:300])] if raw else []
        messages = list(payload.get("errorMessages") or [])
        for field, message in (payload.get("errors") or {}).items():
            messages.append(field + ": " + str(message))
        return [redact(message) for message in messages]

    # --- reads ---------------------------------------------------------------

    def myself(self) -> dict:
        return self._request("GET", API + "/myself")[1]

    def project(self) -> dict:
        return self._request("GET", API + "/project/" + urllib.parse.quote(self.config["project"]))[1]

    def create_meta(self) -> dict:
        """Report the fields this project and issue type require.

        Tries the per-issue-type endpoints first and falls back to the older
        expand form, because which one an instance serves varies.
        """
        project = urllib.parse.quote(self.config["project"])
        wanted = self.config["issue_type"].strip().lower()
        try:
            types = self._request("GET", API + "/issue/createmeta/" + project + "/issuetypes")[1]
            entries = types.get("issueTypes", types.get("values", []))
            match = next((entry for entry in entries
                          if str(entry.get("name", "")).lower() == wanted
                          or str(entry.get("id", "")) == self.config["issue_type"]), None)
            if match:
                fields = self._request(
                    "GET", API + "/issue/createmeta/" + project + "/issuetypes/" + str(match["id"]),
                    params={"maxResults": 200})[1]
                return {"issue_type": match, "fields": fields.get("fields", fields.get("values", [])),
                        "available_types": [entry.get("name") for entry in entries]}
            return {"issue_type": None, "fields": [],
                    "available_types": [entry.get("name") for entry in entries]}
        except JiraError as error:
            if error.status not in (404, 410):
                raise
        legacy = self._request("GET", API + "/issue/createmeta",
                               params={"projectKeys": self.config["project"],
                                       "expand": "projects.issuetypes.fields"})[1]
        projects = legacy.get("projects") or []
        if not projects:
            return {"issue_type": None, "fields": [], "available_types": []}
        types = projects[0].get("issuetypes") or []
        names = [entry.get("name") for entry in types]
        match = next((entry for entry in types if str(entry.get("name", "")).lower() == wanted), None)
        if not match:
            return {"issue_type": None, "fields": [], "available_types": names}
        fields = []
        for key, definition in (match.get("fields") or {}).items():
            item = dict(definition)
            item["fieldId"] = key
            fields.append(item)
        return {"issue_type": match, "fields": fields, "available_types": names}

    def search(self, jql: str, fields=("summary", "status", "labels", "parent"),
               max_results: int = 100) -> list:
        """Run JQL, preferring the current endpoint and falling back to the old one."""
        body = {"jql": jql, "maxResults": max_results, "fields": list(fields)}
        try:
            status, payload = self._request("POST", API + "/search/jql", body=body)
            return payload.get("issues", [])
        except JiraError as error:
            if error.status not in (404, 410, 400):
                raise
        status, payload = self._request("POST", API + "/search", body=body)
        return payload.get("issues", [])

    def comments(self, key: str) -> list:
        payload = self._request("GET", API + "/issue/" + key + "/comment",
                                params={"maxResults": 100, "orderBy": "created"})[1]
        return payload.get("comments", [])

    # --- writes --------------------------------------------------------------

    def create_issue(self, fields: dict) -> dict:
        if self.dry_run:
            return {"key": "DRY-RUN", "dry_run": True}
        return self._request("POST", API + "/issue", body={"fields": fields})[1]

    def update_issue(self, key: str, fields: dict) -> None:
        if self.dry_run:
            return
        self._request("PUT", API + "/issue/" + key, body={"fields": fields})

    def add_comment(self, key: str, adf: dict) -> dict:
        if self.dry_run:
            return {"id": "DRY-RUN", "dry_run": True}
        return self._request("POST", API + "/issue/" + key + "/comment", body={"body": adf})[1]

    def update_comment(self, key: str, comment_id: str, adf: dict) -> None:
        if self.dry_run:
            return
        self._request("PUT", API + "/issue/" + key + "/comment/" + str(comment_id), body={"body": adf})


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Jira configuration and connectivity.")
    parser.add_argument("--check", action="store_true", help="verify credentials and project access")
    parser.add_argument("--env", default="", help="path to the .env file")
    args = parser.parse_args()

    config = load_config(args.env)
    missing = missing_config(config)
    if missing:
        print(json.dumps({
            "ok": False,
            "env_file": config["env_file"] or "not found",
            "missing": missing,
            "hint": "fill these in the .env file (see templates/jira.env.template). "
                    "JIRA_API_TOKEN is created at id.atlassian.com/manage-profile/security/api-tokens",
        }, indent=2))
        return 1

    if not args.check:
        print(json.dumps({"ok": True, "env_file": config["env_file"],
                          "base_url": config["base_url"], "project": config["project"],
                          "issue_type": config["issue_type"], "epic": config["epic"] or None,
                          "note": "pass --check to test the connection"}, indent=2))
        return 0

    client = JiraClient(config)
    try:
        me = client.myself()
        project = client.project()
        meta = client.create_meta()
    except JiraError as error:
        print(json.dumps({"ok": False, "error": redact(str(error)), "status": error.status,
                          "hint": "401/403 usually means the email and API token pair is wrong, "
                                  "404 that the project id or base URL is wrong"}, indent=2))
        return 1

    required = [field.get("name") for field in meta["fields"] if field.get("required")]
    print(json.dumps({
        "ok": True,
        "authenticated_as": me.get("displayName") or me.get("emailAddress", "unknown"),
        "project": {"key": project.get("key"), "name": project.get("name"), "id": project.get("id")},
        "issue_type": (meta["issue_type"] or {}).get("name") or "NOT FOUND",
        "available_issue_types": meta["available_types"],
        "required_fields": required,
        "epic": config["epic"] or None,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
