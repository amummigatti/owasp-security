#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Tests for the secret redactor shared by the OWASP and Jira skills.

Two goals pull in opposite directions and both are tested: real secrets must be
masked wherever they appear, and ordinary code used as evidence must survive, or the
evidence stops being useful to the developer reading it.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWASP_COPY = ROOT / "skills" / "owasp-security-skill" / "scripts" / "redact.py"
JIRA_COPY = ROOT / "skills" / "jira-updates-skill" / "scripts" / "redact.py"

sys.path.insert(0, str(OWASP_COPY.parent))
from redact import redact_list, redact_text  # noqa: E402


class SecretsAreMasked(unittest.TestCase):
    def assertMasked(self, text, secret, label=None):
        cleaned, count = redact_text(text)
        self.assertNotIn(secret, cleaned)
        self.assertGreaterEqual(count, 1)
        if label:
            self.assertIn("<redacted:" + label + ">", cleaned)

    def test_aws_secret_assignment(self):
        self.assertMasked('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                          "wJalrXUtnFEMI", "secret-assignment")

    def test_quoted_password_double_and_single(self):
        self.assertMasked('password = "hunter2hunter2"', "hunter2hunter2")
        self.assertMasked("api_key: 'abcd1234efgh5678'", "abcd1234efgh5678")

    def test_unquoted_env_style_value(self):
        self.assertMasked("STRIPE_SECRET_KEY=sk-live1234567890abcdefghijkl", "sk-live1234567890abcdefghijkl")

    def test_url_credentials_keep_the_rest_of_the_url(self):
        cleaned, _ = redact_text("DB_URL=postgres://admin:s3cr3tpass@db.internal:5432/app")
        self.assertNotIn("s3cr3tpass", cleaned)
        self.assertIn("db.internal:5432/app", cleaned)
        self.assertIn("admin", cleaned)

    def test_bearer_token(self):
        self.assertMasked("Authorization: Bearer abcdefghijklmnop1234567890", "abcdefghijklmnop1234567890",
                          "bearer-token")

    def test_provider_tokens(self):
        self.assertMasked("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")
        self.assertMasked("t " + "ghp_" + "a" * 36, "ghp_" + "a" * 36, "github-token")
        self.assertMasked("xoxb-1234567890-abcdefghij", "xoxb-1234567890", "slack-token")

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        self.assertMasked("token=" + jwt, jwt, "jwt")

    def test_private_key_block_including_body(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----"
        cleaned, count = redact_text(text)
        self.assertNotIn("secretbody", cleaned)
        self.assertEqual(count, 1)

    def test_unterminated_private_key_is_still_masked(self):
        cleaned, _ = redact_text("-----BEGIN PRIVATE KEY-----\nMIIabcdefg")
        self.assertNotIn("MIIabcdefg", cleaned)

    def test_redaction_is_idempotent(self):
        once, _ = redact_text('password = "hunter2hunter2"')
        twice, count = redact_text(once)
        self.assertEqual(once, twice)
        self.assertEqual(count, 0)


class OrdinaryCodeSurvives(unittest.TestCase):
    """Evidence has to stay readable; over-redaction makes findings useless."""

    CASES = [
        "WEBUI_AUTH_COOKIE_SECURE = os.getenv('WEBUI_AUTH_COOKIE_SECURE', 'false') == 'true'",
        "ENABLE_PASSWORD_VALIDATION = os.getenv('ENABLE_PASSWORD_VALIDATION', 'False').lower() == 'true'",
        "token: string",
        "const password = getPassword()",
        "localStorage.token = sessionUser.token;",
        "SOME_LONG_SECRET_CONSTANT_NAME = OTHER_LONG_CONSTANT_NAME",
        "commit 8bd8b4f9a7c1e2d3f4a5b6c7d8e9f0a1b2c3d4e5",
        "if (!authorizationHeader) return false",
        "const tlsOptions = sslEnabled === true ? { tls: { rejectUnauthorized: false } } : {}",
        "cur.execute(\"SELECT * FROM t WHERE id = \" + request.args[\"id\"])",
    ]

    def test_none_of_these_change(self):
        for text in self.CASES:
            cleaned, count = redact_text(text)
            self.assertEqual((cleaned, count), (text, 0), text)


class Helpers(unittest.TestCase):
    def test_empty_and_none_safe(self):
        self.assertEqual(redact_text(""), ("", 0))
        self.assertEqual(redact_list([]), ([], 0))

    def test_list_counts_across_items(self):
        out, count = redact_list(['password = "hunter2hunter2"', "nothing here", 'token: "abcdefgh1234"'])
        self.assertEqual(count, 2)
        self.assertEqual(out[1], "nothing here")


class CopiesStayIdentical(unittest.TestCase):
    """Each skill ships its own redact.py so it can be installed alone. They must not drift."""

    def test_the_two_copies_are_byte_identical(self):
        def normalised(path):
            return path.read_bytes().replace(b"\r\n", b"\n")

        self.assertEqual(normalised(OWASP_COPY), normalised(JIRA_COPY),
                         "skills/owasp-security-skill/scripts/redact.py and "
                         "skills/jira-updates-skill/scripts/redact.py must be edited together")


if __name__ == "__main__":
    unittest.main(verbosity=2)
