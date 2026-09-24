# OWASP Security Scan Report

| Field | Value |
| --- | --- |
| Generated (UTC) | 2026-09-24T04:04:51+00:00 |
| Generated (local) | 2026-09-24T14:04:51+10:00 |
| Repositories in scope | 1 |
| OWASP rule set | read from https://top10.owasp.org/2025/ at 2026-09-24T03:57:56+00:00 |
| Scan run at | 2026-09-24T04:04:41+00:00 |
| Detection | scan_repos.py pattern pass, rules v1, plus agent code review |

## Executive summary

| Repository | Commit | Files | Critical | High | Medium | Low | Reported | Rejected |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| open-webui | `8bd8b4f` | 1185 | 0 | 0 | 6 | 10 | 16 | 89 |
| **All repositories** |  |  | **0** | **0** | **6** | **10** | **16** |  |

### Findings by OWASP category

| Category | Critical | High | Medium | Low | Total |
| --- | --- | --- | --- | --- | --- |
| A02:2025 Security Misconfiguration | 0 | 0 | 2 | 0 | 2 |
| A03:2025 Software Supply Chain Failures | 0 | 0 | 0 | 2 | 2 |
| A05:2025 Injection | 0 | 0 | 1 | 2 | 3 |
| A06:2025 Insecure Design | 0 | 0 | 0 | 1 | 1 |
| A07:2025 Authentication Failures | 0 | 0 | 3 | 1 | 4 |
| A08:2025 Software or Data Integrity Failures | 0 | 0 | 0 | 2 | 2 |
| A09:2025 Security Logging and Alerting Failures | 0 | 0 | 0 | 1 | 1 |
| A10:2025 Mishandling of Exceptional Conditions | 0 | 0 | 0 | 1 | 1 |

## Repository: open-webui

| Field | Value |
| --- | --- |
| Source | https://github.com/open-webui/open-webui |
| Commit scanned | `8bd8b4f` on `main` (2026-09-21T15:25:06-04:00) |
| Languages | Svelte, Python, TypeScript, YAML, JavaScript, Shell, HTML |
| Files scanned | 1185 |
| Findings reported | 16 (plus 89 rejected during review) |

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 6 |
| Low | 10 |

### A02:2025 - Security Misconfiguration (2)

#### open-webui-102 - Auth cookie Secure flag defaults to off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/env.py:772`
- **CWE:** CWE-614
- **Detected by:** manual-review

**Evidence**

```text
WEBUI_AUTH_COOKIE_SECURE = os.getenv('WEBUI_AUTH_COOKIE_SECURE', os.getenv('WEBUI_SESSION_COOKIE_SECURE', 'false')) == 'true'
```

**Why it matters**

A session cookie without Secure is sent over plain HTTP, where anyone on the network path can read it.

**Review notes**

Both the auth token cookie and the session cookie default to Secure=false. A deployment that terminates TLS in front of the app but does not set the variable ships session tokens without the flag.

**Recommended fix**

Default to Secure when the request scheme is https (or when a public HTTPS URL is configured), and make the insecure setting the explicit opt-in.

#### open-webui-069 - Session cookie missing Secure / HttpOnly / SameSite

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/utils/oauth.py:2194`
- **CWE:** CWE-614, CWE-1004, CWE-1275
- **Detected by:** pattern

**Evidence**

```text
httponly=False,  # Required for frontend access
```

**Why it matters**

Without HttpOnly a script can read the session; without Secure it travels in cleartext; SameSite=None widens CSRF exposure.

**Review notes**

The OAuth callback sets the session JWT cookie with httponly=False ('Required for frontend access'), while the password sign-in and sign-up paths in routers/auths.py set httponly=True. An XSS on any page served by the app can therefore read the token from document.cookie for OAuth users.

**Recommended fix**

Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.

### A03:2025 - Software Supply Chain Failures (2)

#### open-webui-078 - Container image pulled without a pinned tag or digest

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `docker-compose.a1111-test.yaml:7`
- **CWE:** CWE-1104, CWE-494
- **Detected by:** pattern

**Evidence**

```text
image: ghcr.io/neggles/sd-webui-docker:latest
```

**Why it matters**

An unpinned base image changes underneath the build, so what was reviewed is not what ships.

**Review notes**

Compose file for an optional test/observability stack pulls a :latest image, so what runs is not what was reviewed. Not part of the production image build.

**Recommended fix**

Reference an immutable digest (image@sha256:...) and update it deliberately.

#### open-webui-080 - Container image pulled without a pinned tag or digest

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `docker-compose.otel.yaml:3`
- **CWE:** CWE-1104, CWE-494
- **Detected by:** pattern

**Evidence**

```text
image: grafana/otel-lgtm:latest
```

**Why it matters**

An unpinned base image changes underneath the build, so what was reviewed is not what ships.

**Review notes**

Compose file for an optional test/observability stack pulls a :latest image, so what runs is not what was reviewed. Not part of the production image build.

**Recommended fix**

Reference an immutable digest (image@sha256:...) and update it deliberately.

### A05:2025 - Injection (3)

#### open-webui-073 - Source evaluated at run time (eval / exec / new Function)

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/utils/plugin.py:241` (also line 291)
- **CWE:** CWE-94, CWE-95
- **Detected by:** pattern

**Evidence**

```text
exec(content, module.__dict__)
exec(content, module.__dict__)
```

**Why it matters**

If any part of the evaluated string is influenced by input, the attacker is writing code rather than supplying data.

**Review notes**

By design, uploaded Tools are compiled and exec'd in the server process (utils/plugin.py). Functions are admin-only. Tool create and content edits require the workspace.tools permission, which defaults to off (USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS=False), so out of the box only admins can run code. Any deployment that grants that permission to ordinary users gives them arbitrary Python execution on the server; there is no sandbox.

**Recommended fix**

Replace with explicit parsing (json.loads, a lookup table, or a small interpreter for the allowed operations).

#### open-webui-008 - SQL statement assembled from a string instead of parameters (Python)

- **Severity:** LOW  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/internal/db.py:302` (also line 384, 386, 388, 390, 392) - 7 occurrences in this file
- **CWE:** CWE-89
- **Detected by:** pattern

**Evidence**

```text
conn.execute(f"PRAGMA key = '{database_password}'")
cursor.execute(f'PRAGMA synchronous={DATABASE_SQLITE_PRAGMA_SYNCHRONOUS}')
cursor.execute(f'PRAGMA busy_timeout={DATABASE_SQLITE_PRAGMA_BUSY_TIMEOUT}')
```

**Why it matters**

The query text is concatenated or interpolated, so any untrusted value in it becomes part of the statement the database parses.

**Review notes**

The SQLCipher key is interpolated into PRAGMA key = '...'. The value comes from the DATABASE_PASSWORD environment variable, not from a request, so an attacker cannot reach it; but a password containing a single quote breaks or alters the statement. Impact is limited to operator configuration.

**Recommended fix**

Pass values as bind parameters (cursor.execute(sql, params)) or use the ORM's query builder; never format user data into SQL text.

#### open-webui-012 - SQL statement assembled from a string instead of parameters (Python)

- **Severity:** LOW  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/migrations/env.py:59`
- **CWE:** CWE-89
- **Detected by:** pattern

**Evidence**

```text
cipher_conn.execute(f"PRAGMA key = '{DATABASE_PASSWORD}'")
```

**Why it matters**

The query text is concatenated or interpolated, so any untrusted value in it becomes part of the statement the database parses.

**Review notes**

Same pattern as open-webui-008 in the Alembic migration environment: DATABASE_PASSWORD interpolated into PRAGMA key. Operator-controlled, low impact.

**Recommended fix**

Pass values as bind parameters (cursor.execute(sql, params)) or use the ORM's query builder; never format user data into SQL text.

### A06:2025 - Insecure Design (1)

#### open-webui-107 - Unauthenticated endpoints disclose deployment metadata and query the database

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/main.py:3010`
- **CWE:** CWE-200, CWE-400
- **Detected by:** manual-review

**Evidence**

```text
@app.get('/health/db')  async def check_db_health(): await async_db_ping()
```

**Why it matters**

Public endpoints that run a database query are a cheap way to add load, and public version and deployment identifiers help target known issues.

**Review notes**

/health/db runs a database ping with no authentication or rate limit, and /api/version returns VERSION and DEPLOYMENT_ID to anyone. Health endpoints are usually meant to be public; the concern is that the query behind /health/db is reachable from the internet if the app is exposed directly.

**Recommended fix**

Serve the database check on an internal-only route or behind a token, and drop deployment_id from the unauthenticated response.

### A07:2025 - Authentication Failures (4)

#### open-webui-106 - Trusted-header sign-in creates and logs in any named user

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Needs verification (requires a running instance or domain knowledge)
- **Location:** `backend/open_webui/routers/auths.py:735`
- **CWE:** CWE-290
- **Detected by:** manual-review

**Evidence**

```text
if WEBUI_AUTH_TRUSTED_EMAIL_HEADER: ... if not await Users.get_user_by_email(email.lower()): await signup_handler(...)
```

**Why it matters**

When header auth is on, whoever can set that header is any user, including an existing admin, with no password.

**Review notes**

Only active when WEBUI_AUTH_TRUSTED_EMAIL_HEADER is configured. It is safe only if every request passes through a proxy that authenticates the user and strips a client-supplied copy of the header; if the app port is reachable directly, it is a full authentication bypass.

**Recommended fix**

Document the proxy requirement prominently, and consider an allowlist of source addresses for the header.

#### open-webui-105 - Sign-in throttling is keyed by email only

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Needs verification (requires a running instance or domain knowledge)
- **Location:** `backend/open_webui/routers/auths.py:818`
- **CWE:** CWE-307, CWE-799
- **Detected by:** manual-review

**Evidence**

```text
if await signin_rate_limiter.is_limited(request.app.state.redis, form_data.email.lower()):   # limiter = RateLimiter(limit=15, window=180)
```

**Why it matters**

A limit keyed only on the account name does not slow one source trying one common password against many accounts, and lets anyone lock a known user out by spending that user's quota.

**Review notes**

The only in-app limiter on password sign-in is per email address (15 attempts per 3 minutes). No per-IP limit was found in the application. A reverse proxy may provide one, which the repository cannot show.

**Recommended fix**

Add a per-source limit next to the per-account one, and consider progressive delays instead of a hard lockout.

#### open-webui-103 - Session JWT persisted in localStorage

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `src/routes/auth/+page.svelte:52`
- **CWE:** CWE-922, CWE-1004
- **Detected by:** manual-review

**Evidence**

```text
localStorage.token = sessionUser.token;  // also line 150; token read from localStorage in ~800 places under src/
```

**Why it matters**

Any script running on the page can read localStorage, so one cross-site scripting bug becomes theft of a long-lived credential that works from any machine.

**Review notes**

The frontend stores the JWT in localStorage and reads it from there throughout the app, alongside the cookie. The HttpOnly attribute the password-login cookie sets (routers/auths.py) therefore protects little, since the same token is also script-readable. The rendering paths reviewed are sanitised with DOMPurify, which lowers the likelihood, but this is the impact multiplier if any sink is missed.

**Recommended fix**

Authenticate API calls with the HttpOnly cookie only, and stop persisting the token in script-readable storage.

#### open-webui-104 - Password complexity validation is disabled by default

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/env.py:814`
- **CWE:** CWE-521
- **Detected by:** manual-review

**Evidence**

```text
ENABLE_PASSWORD_VALIDATION = os.getenv('ENABLE_PASSWORD_VALIDATION', 'False').lower() == 'true'
```

**Why it matters**

Without a password policy, users can register with trivially guessable passwords.

**Review notes**

validate_password() only enforces the bcrypt length limit unless ENABLE_PASSWORD_VALIDATION is turned on, so a one-character password is accepted on signup by default.

**Recommended fix**

Enable a sensible minimum (length over composition rules) by default and let operators tighten it.

### A08:2025 - Software or Data Integrity Failures (2)

#### open-webui-001 - CI action referenced by mutable branch

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `.github/workflows/regression.yaml:30`
- **CWE:** CWE-829, CWE-1357
- **Detected by:** pattern

**Evidence**

```text
uses: open-webui/tests/.github/workflows/regression.yml@main
```

**Why it matters**

Whoever can push to that branch can run code in the pipeline, with access to its secrets.

**Review notes**

The reusable workflow open-webui/tests/.github/workflows/regression.yml is referenced at @main, a mutable ref, so the code that runs on each pull request can change without a change in this repository. Mitigated: same organisation, permissions limited to contents: read.

**Recommended fix**

Pin third-party actions to a full commit SHA.

#### open-webui-083 - Remote script downloaded and executed unverified

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `Dockerfile:194`
- **CWE:** CWE-494
- **Detected by:** pattern

**Evidence**

```text
curl -fsSL https://ollama.com/install.sh | sh && \
```

**Why it matters**

Nothing checks what came back, so a compromised or swapped script executes with the build's privileges.

**Review notes**

Ollama is installed at image build time (only when USE_OLLAMA=true) by piping https://ollama.com/install.sh into sh with no version pin or checksum.

**Recommended fix**

Fetch a pinned artifact, verify its checksum or signature, then run it as a separate step.

### A09:2025 - Security Logging and Alerting Failures (1)

#### open-webui-086 - Secret or personal data written to a log

- **Severity:** LOW  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `src/lib/components/chat/Chat.svelte:1664`
- **CWE:** CWE-532
- **Detected by:** pattern

**Evidence**

```text
console.log('Starting upl<redacted:21 chars> with:', {
```

**Why it matters**

Logs are copied to aggregators and retained for months, spreading the secret to systems with looser access control.

**Review notes**

uploadGoogleDriveFile logs an object containing Authorization: Bearer <token> to the browser console. Console output is visible to browser extensions and is often captured by support tooling and error reporters.

**Recommended fix**

Log identifiers rather than values, and add a redaction filter so a future careless call cannot leak either.

### A10:2025 - Mishandling of Exceptional Conditions (1)

#### open-webui-066 - Exception caught and discarded

- **Severity:** LOW  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `backend/open_webui/utils/filter.py:95`
- **CWE:** CWE-390, CWE-703
- **Detected by:** pattern

**Evidence**

```text
except Exception:
```

**Why it matters**

A failed security check that raises and is silently swallowed reads exactly like success, and nothing is logged for anyone to notice.

**Review notes**

If loading a filter's module or reading its priority fails, the error is swallowed and the filter silently gets priority 0. Filters commonly implement guardrails, so a failure can change their execution order with no log line.

**Recommended fix**

Handle the specific error, or log it and fail closed; never let control flow continue as though the operation succeeded.

### Rejected during review (89)

Candidates the pattern scan raised that reading the code ruled out.

| Candidate | Location | Reason |
| --- | --- | --- |
| Tool credentials file committed to the repository | `.npmrc:1` | .npmrc contains only engine-strict=true; no credentials. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/main.py:2224` | No auth dependency in the signature; public by design (login, discovery or health endpoint). |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/analytics.py:85` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/audio.py:282` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/auths.py:1171` | Authorization is enforced by Depends(get_current_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/automations.py:360` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/calendar.py:347` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/channels.py:238` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/chats.py:609` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/configs.py:118` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/evaluations.py:285` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/functions.py:69` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/groups.py:141` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/images.py:271` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/knowledge.py:1702` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/memories.py:516` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/models.py:381` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/notes.py:714` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/ollama.py:289` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/openai.py:544` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/pipelines.py:366` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/prompts.py:551` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/retrieval.py:629` | Authorization is enforced by Depends(get_admin_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/scim.py:558` | Authorization is enforced by Depends(get_scim_auth) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/skills.py:123` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/tasks.py:108` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/tools.py:316` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| Sensitive route with no authorization decorator above the handler | `backend/open_webui/routers/users.py:457` | Authorization is enforced by Depends(get_verified_user) in the handler signature; FastAPI does not use decorators for this, so the pattern cannot see it. |
| SQL statement assembled from a string instead of parameters (Python) | `backend/open_webui/retrieval/vector/dbs/mariadb_vector.py:166` | Interpolated parts are internal constants (table shape, vector length) or validated identifiers; values are bound parameters. |
| SQL statement assembled from a string instead of parameters (Python) | `backend/open_webui/retrieval/vector/dbs/oracle23ai.py:585` | Interpolated parts are internal constants (table shape, vector length) or validated identifiers; values are bound parameters. |
| Source evaluated at run time (eval / exec / new Function) | `src/lib/utils/index.ts:1736` | Match is in a comment, not a call. |
| Certificate verification switched off | `backend/open_webui/utils/mcp/client.py:28` | verify is a parameter that defaults to True; it is only lowered when the operator configures it. |
| Authentication token kept in localStorage or sessionStorage | `src/lib/apis/configs/index.ts:574` | Stores a tool id used to resume an OAuth redirect, not a credential. |
| Template auto-escaping bypassed (|safe, mark_safe, v-html, triple braces) | `backend/open_webui/retrieval/vector/dbs/valkey.py:128` | Regex or f-string brace escaping, or ProseMirror node markup; not a template engine escaping bypass. |
| Template auto-escaping bypassed (|safe, mark_safe, v-html, triple braces) | `backend/open_webui/utils/task.py:248` | Regex or f-string brace escaping, or ProseMirror node markup; not a template engine escaping bypass. |
| Template auto-escaping bypassed (|safe, mark_safe, v-html, triple braces) | `backend/open_webui/utils/tools.py:1705` | Regex or f-string brace escaping, or ProseMirror node markup; not a template engine escaping bypass. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/chat/FileNav/FilePreview.svelte:154` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/chat/MessageInput.svelte:647` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/common/DocxPreview.svelte:36` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/common/PDFViewer.svelte:232` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Template auto-escaping bypassed (|safe, mark_safe, v-html, triple braces) | `src/lib/components/common/RichTextInput.svelte:331` | Regex or f-string brace escaping, or ProseMirror node markup; not a template engine escaping bypass. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/common/RichTextInput.svelte:441` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/common/RichTextInput/listDragHandlePlugin.js:186` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `src/lib/components/notes/utils.ts:40` | Value is sanitised with DOMPurify (or sanitizeSvg for Mermaid output) before assignment, or the assignment only clears the element. |
| Secret or personal data written to a log | `backend/open_webui/__init__.py:42` | Log message mentions a setting or event name; no secret value is logged. |
| Secret or personal data written to a log | `backend/open_webui/env.py:826` | Log message mentions a setting or event name; no secret value is logged. |
| Secret or personal data written to a log | `backend/open_webui/models/auths.py:172` | Log message mentions a setting or event name; no secret value is logged. |
| Secret or personal data written to a log | `backend/open_webui/utils/oauth.py:457` | Log message mentions a setting or event name; no secret value is logged. |
| Exception caught and discarded | `backend/open_webui/config.py:365` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/env.py:69` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/functions.py:180` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/main.py:1683` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/migrations/versions/f1e2d3c4b5a6_add_access_grant_table.py:132` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/loaders/external_document.py:51` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/loaders/mineru.py:507` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/loaders/pdf.py:33` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/vector/dbs/mariadb_vector.py:153` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/vector/dbs/valkey.py:231` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/vector/dbs/weaviate.py:334` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/web/main.py:37` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/retrieval/web/utils.py:1114` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/audio.py:1183` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/auths.py:988` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/configs.py:258` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/knowledge.py:2009` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/models.py:857` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/openai.py:912` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/pipelines.py:114` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/retrieval.py:2290` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/routers/terminals.py:412` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/socket/main.py:299` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/tools/builtin.py:188` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/utils/anthropic.py:76` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/utils/middleware.py:1187` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/utils/oauth.py:994` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/utils/payload.py:110` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `backend/open_webui/utils/task.py:69` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `src/lib/components/OnBoarding.svelte:24` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `src/lib/components/admin/Settings/Images.svelte:172` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `src/lib/components/common/Valves/MapSelector.svelte:55` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Exception caught and discarded | `src/routes/+layout.svelte:1307` | Best-effort cleanup or parsing fallback; no security decision depends on the swallowed error. |
| Cleartext http:// endpoint in code or configuration | `backend/open_webui/config.py:260` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Cleartext http:// endpoint in code or configuration | `backend/open_webui/main.py:2927` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Cleartext http:// endpoint in code or configuration | `backend/open_webui/routers/images.py:461` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Cleartext http:// endpoint in code or configuration | `docker-compose.a1111-test.yaml:29` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Cleartext http:// endpoint in code or configuration | `docker-compose.otel.yaml:28` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Cleartext http:// endpoint in code or configuration | `docker-compose.yaml:24` | Internal service default (docker-compose hostname, host.docker.internal), XML namespace or a comment; not an external cleartext endpoint. |
| Exception detail or stack trace returned to the caller | `backend/open_webui/routers/scim.py:286` | Traceback is written to the server log only and is not returned in the response. |
| Exception detail or stack trace returned to the caller | `backend/open_webui/utils/telemetry/instrumentors.py:95` | Traceback is written to the server log only and is not returned in the response. |

## Method

1. The current OWASP rule set was read from the OWASP website at the time shown above, so the categories used here are the ones OWASP publishes now rather than a copy held in this tool.
2. Each repository was cloned at the commit recorded in its table and swept for candidate issues, which are classified by mapping their CWE to the live OWASP categories.
3. Every candidate was then reviewed against the surrounding code: confirmed, rejected, or marked as needing verification. Issues that pattern matching cannot see - missing authorization checks, flawed trust boundaries, weak design decisions - were looked for by reading the code paths that handle authentication, authorization and untrusted input.

## Scope and limitations

- This is a static review of source code at one commit. It cannot observe runtime configuration, deployed infrastructure, secrets held outside the repository, or the behaviour of third-party services.
- No dependency CVE lookup was performed against a vulnerability database; supply chain findings here are about how dependencies are declared and pinned.
- Secrets found in source are masked in the evidence above. Treat any of them as disclosed and rotate them - masking the report does not undo the exposure in version control.
- An empty result for a repository means these checks found nothing, not that the repository is secure.

## OWASP categories referenced

- A02:2025 Security Misconfiguration - https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/
- A03:2025 Software Supply Chain Failures - https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/
- A05:2025 Injection - https://top10.owasp.org/2025/A05_2025-Injection/
- A06:2025 Insecure Design - https://top10.owasp.org/2025/A06_2025-Insecure_Design/
- A07:2025 Authentication Failures - https://top10.owasp.org/2025/A07_2025-Authentication_Failures/
- A08:2025 Software or Data Integrity Failures - https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/
- A09:2025 Security Logging and Alerting Failures - https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/
- A10:2025 Mishandling of Exceptional Conditions - https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
