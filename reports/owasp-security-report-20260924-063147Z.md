# OWASP Security Scan Report

| Field | Value |
| --- | --- |
| Generated (UTC) | 2026-09-24T06:31:47+00:00 |
| Generated (local) | 2026-09-24T16:31:47+10:00 |
| Repositories in scope | 1 |
| OWASP rule set | read from https://top10.owasp.org/2025/ at 2026-09-24T06:27:02+00:00 |
| Scan run at | 2026-09-24T06:30:27+00:00 |
| Detection | scan_repos.py pattern pass, rules v1, plus agent code review |

## Executive summary

| Repository | Commit | Files | Critical | High | Medium | Low | Reported | Rejected |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| flowise | `9291856` | 2066 | 0 | 0 | 8 | 5 | 13 | 72 |
| **All repositories** |  |  | **0** | **0** | **8** | **5** | **13** |  |

### Findings by OWASP category

| Category | Critical | High | Medium | Low | Total |
| --- | --- | --- | --- | --- | --- |
| A01:2025 Broken Access Control | 0 | 0 | 1 | 0 | 1 |
| A03:2025 Software Supply Chain Failures | 0 | 0 | 0 | 4 | 4 |
| A04:2025 Cryptographic Failures | 0 | 0 | 0 | 1 | 1 |
| A06:2025 Insecure Design | 0 | 0 | 1 | 0 | 1 |
| A07:2025 Authentication Failures | 0 | 0 | 6 | 0 | 6 |

## Repository: flowise

| Field | Value |
| --- | --- |
| Source | https://github.com/flowiseai/flowise |
| Commit scanned | `9291856` on `main` (2026-08-13T13:38:19+01:00) |
| Languages | TypeScript, JavaScript, YAML, HTML |
| Files scanned | 2066 |
| Scan coverage | Complete |
| Findings reported | 13 (plus 72 rejected during review) |

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 8 |
| Low | 5 |

### A01:2025 - Broken Access Control (1)

#### flowise-084 - Unauthenticated text-to-speech endpoint accepts a caller-supplied credential id

- **Severity:** MEDIUM  |  **Confidence:** medium  |  **Status:** Confirmed by review
- **Location:** `packages/server/src/controllers/text-to-speech/index.ts:72`
- **CWE:** CWE-862, CWE-639
- **Detected by:** manual-review

**Evidence**

```text
} else { // Use TTS config from request body
    provider = bodyProvider
    credentialId = bodyCredentialId
```

**Why it matters**

An endpoint that spends a stored provider credential should only do so for a caller who is entitled to it. Here the only thing standing between an anonymous request and a stored credential is knowing its id.

**Review notes**

POST /api/v1/text-to-speech/generate is on the unauthenticated route whitelist (utils/constants.ts) and its router adds no permission check. When the request names a chatflowId the handler correctly requires the chatflow to be public. When it omits chatflowId, the handler takes provider and credentialId straight from the body and passes them to convertTextToSpeechStream, which decrypts the stored credential with a lookup by id alone (getCredentialData in components/src/utils.ts), with no workspace or organisation check. A caller who obtains a credential id can therefore generate speech at the credential owner's expense. Credential ids are random UUIDs and the public chatbot config strips credential references, so exploitation needs an id from elsewhere, which is why this is medium rather than high. POST /text-to-speech/abort is unauthenticated in the same way.

**Recommended fix**

Require authentication on /generate and /abort. When there is no chatflowId, reject the request or authorise the credential against the caller's workspace before decrypting it; never accept a credential id from an unauthenticated body.

### A03:2025 - Software Supply Chain Failures (4)

#### flowise-004 - Container image pulled without a pinned tag or digest

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `docker/docker-compose-queue-prebuilt.yml:16` (also line 184)
- **CWE:** CWE-1104, CWE-494
- **Detected by:** pattern

**Evidence**

```text
image: flowiseai/flowise:latest
image: flowiseai/flowise-worker:latest
```

**Why it matters**

An unpinned base image changes underneath the build, so what was reviewed is not what ships.

**Review notes**

The shipped queue compose file pulls flowiseai/flowise:latest, so what runs changes whenever a new image is published.

**Recommended fix**

Reference an immutable digest (image@sha256:...) and update it deliberately.

#### flowise-005 - Container image pulled without a pinned tag or digest

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `docker/docker-compose.yml:5`
- **CWE:** CWE-1104, CWE-494
- **Detected by:** pattern

**Evidence**

```text
image: flowiseai/flowise:latest
```

**Why it matters**

An unpinned base image changes underneath the build, so what was reviewed is not what ships.

**Review notes**

The main compose file pulls flowiseai/flowise:latest, so what runs changes whenever a new image is published.

**Recommended fix**

Reference an immutable digest (image@sha256:...) and update it deliberately.

#### flowise-007 - Container image pulled without a pinned tag or digest

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `docker/worker/docker-compose.yml:5`
- **CWE:** CWE-1104, CWE-494
- **Detected by:** pattern

**Evidence**

```text
image: flowiseai/flowise-worker:latest
```

**Why it matters**

An unpinned base image changes underneath the build, so what was reviewed is not what ships.

**Review notes**

The worker compose file pulls flowiseai/flowise-worker:latest, so what runs changes whenever a new image is published.

**Recommended fix**

Reference an immutable digest (image@sha256:...) and update it deliberately.

#### flowise-077 - Dependency accepts any version (* or latest)

- **Severity:** LOW  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/ui/package.json:74` (also line 75, 76)
- **CWE:** CWE-1104, CWE-829
- **Detected by:** pattern

**Evidence**

```text
"flowise-embed": "latest",
"flowise-embed-react": "latest",
"flowise-react-json-view": "*",
```

**Why it matters**

A floating range means the build resolves to whatever the registry serves that day, including a compromised release.

**Review notes**

packages/ui depends on flowise-embed at 'latest'. A lockfile mitigates this for reproducible installs, but the manifest does not express the intent to pin.

**Recommended fix**

Pin a version range and commit a lockfile so builds are reproducible and reviewable.

### A04:2025 - Cryptographic Failures (1)

#### flowise-026 - Cleartext http:// endpoint in code or configuration

- **Severity:** LOW  |  **Confidence:** low  |  **Status:** Confirmed by review
- **Location:** `packages/components/nodes/tools/Arxiv/core.ts:132` (also line 168)
- **CWE:** CWE-319
- **Detected by:** pattern

**Evidence**

```text
const baseUrl = 'http://export.arxiv.org/api/query'
const cleanId = arxivId.replace('http://arxiv.org/abs/', '').replace('https://arxiv.org/abs/', '')
```

**Why it matters**

Credentials and tokens sent over cleartext are readable and modifiable in transit; documentation links are harmless, real endpoints are not.

**Review notes**

The arXiv tool queries http://export.arxiv.org over plain HTTP. The data is public, but the query is visible in transit and the response can be altered, and that response is fed into the model's prompt.

**Recommended fix**

Use https for anything carrying data or credentials, and enforce HSTS on services you own.

### A06:2025 - Insecure Design (1)

#### flowise-085 - User-authored code runs in an in-process vm2 sandbox unless E2B is configured

- **Severity:** MEDIUM  |  **Confidence:** low  |  **Status:** Needs verification (requires a running instance or domain knowledge)
- **Location:** `packages/components/src/utils.ts:1732`
- **CWE:** CWE-94, CWE-693
- **Detected by:** manual-review

**Evidence**

```text
} else { const builtinDeps = ... defaultAllowBuiltInDep ...   // executeJavaScriptCode falls back to NodeVM (vm2)
```

**Why it matters**

Running user-written code in the same process as the server means the sandbox is the only isolation. JavaScript in-process sandboxes have a history of escapes, and a single escape yields the server's credentials and database.

**Review notes**

executeJavaScriptCode uses a remote E2B sandbox only when E2B_APIKEY is set; otherwise custom functions and tools run in vm2 inside the server process. The configuration itself is tight: builtins are allowlisted (no fs or child_process), HTTP libraries are replaced with wrapped clients, eval and wasm are off, and options passed by callers cannot loosen the require settings. The remaining concern is the boundary, not the settings. vm2 is pinned at 3.11.2 in packages/components/package.json; whether that release has open sandbox-escape advisories was not checked here and should be confirmed.

**Recommended fix**

Check current advisories for vm2 3.11.2. For deployments that let users author code, prefer the E2B path or run the server in a locked-down container, and document that the in-process sandbox is not a security boundary against a determined author.

### A07:2025 - Authentication Failures (6)

#### flowise-014 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/components/nodes/cache/RedisCache/RedisCache.ts:122`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
const tlsOptions = sslEnabled === true ? { tls: { rejectUnauthorized: false } } : {}
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for the Redis cache node whenever SSL is enabled. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

#### flowise-015 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/components/nodes/cache/RedisCache/RedisEmbeddingsCache.ts:79`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
const tlsOptions = sslEnabled === true ? { tls: { rejectUnauthorized: false } } : {}
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for the Redis embeddings cache node whenever SSL is enabled. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

#### flowise-022 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/components/nodes/memory/RedisBackedChatMemory/RedisBackedChatMemory.ts:100`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
tls: getCredentialParam('redisCacheSslEnabled', credentialData, nodeData) ? { rejectUnauthorized: false } : undefined
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for the Redis chat memory node whenever SSL is enabled. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

#### flowise-029 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/components/nodes/vectorstores/Elasticsearch/Elasticsearch.ts:284`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
rejectUnauthorized: false
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for the Elasticsearch vector store when a node URL is used. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it. The username and password are sent on that connection.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

#### flowise-066 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/server/src/queue/QueueManager.ts:34`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
rejectUnauthorized: false
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for Redis connections made from a rediss:// URL in the queue manager. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it. This carries job payloads between the server and its workers.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

#### flowise-075 - Certificate verification switched off

- **Severity:** MEDIUM  |  **Confidence:** high  |  **Status:** Confirmed by review
- **Location:** `packages/server/src/utils/rateLimit.ts:62`
- **CWE:** CWE-295
- **Detected by:** pattern

**Evidence**

```text
rejectUnauthorized: false
```

**Why it matters**

Without verification, TLS still encrypts but no longer proves who is on the other end, so an interceptor is undetectable.

**Review notes**

Certificate verification is switched off unconditionally for Redis connections made from a rediss:// URL in the rate limiter. Traffic is still encrypted, but the client cannot tell who it is talking to, so anyone able to intercept the connection can read and alter it.

**Recommended fix**

Re-enable verification and trust the internal CA explicitly where private certificates are in play.

### Rejected during review (72)

Candidates the pattern scan raised that reading the code ruled out.

| Candidate | Location | Reason |
| --- | --- | --- |
| Tool credentials file committed to the repository | `.npmrc:1` | .npmrc holds pnpm settings only; no registry token. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/memory/AgentMemory/MySQLAgentMemory/mysqlSaver.ts:54` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/memory/AgentMemory/PostgresAgentMemory/pgSaver.ts:56` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/memory/AgentMemory/SQLiteAgentMemory/sqliteSaver.ts:49` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/recordmanager/MySQLRecordManager/MySQLrecordManager.ts:226` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/recordmanager/PostgresRecordManager/PostgresRecordManager.ts:228` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/recordmanager/SQLiteRecordManager/SQLiteRecordManager.ts:186` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/components/nodes/vectorstores/Postgres/driver/TypeORM.ts:184` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/postgres/1694658756136-AddChatHistory.ts:20` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/postgres/1743758056188-FixOpenSourceAssistantTable.ts:16` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/postgres/1755066758601-ModifyChatflowType.ts:6` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/postgres/1765360298674-AddApiKeyPermission.ts:13` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/sqlite/1694657778173-AddChatHistory.ts:18` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/sqlite/1743758056188-FixOpenSourceAssistantTable.ts:13` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/database/migrations/sqlite/1765360298674-AddApiKeyPermission.ts:13` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/mariadb/mariaDbCustomFunctions.ts:24` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/mysql/mysqlCustomFunctions.ts:24` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/postgres/1734074497540-AddPersonalWorkspace.ts:14` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/postgres/1737076223692-RefactorEnterpriseDatabase.ts:46` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/sqlite/1734074497540-AddPersonalWorkspace.ts:14` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/sqlite/1737076223692-RefactorEnterpriseDatabase.ts:193` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| SQL statement assembled from a template literal or concatenation (JS/TS) | `packages/server/src/enterprise/database/migrations/sqlite/sqlliteCustomFunctions.ts:10` | Runtime identifiers are allowlisted by regex (sanitizeTableName) and quoted, and values are bound parameters; the migration statements are built from constants or the migration's own database rows, not request input. |
| Credential literal committed to source | `packages/components/nodes/chatmodels/ChatFireworks/core.ts:42` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/components/nodes/chatmodels/ChatHuggingFace/core.ts:22` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/components/nodes/llms/HuggingFaceInference/core.ts:35` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Certificate verification switched off | `packages/components/src/sanitizeDataSourceOptions.test.ts:15` | Unit test fixture. |
| Credential literal committed to source | `packages/server/marketplaces/tools/SendGrid Email.json:7` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/server/src/database/migrations/mariadb/1765360298674-AddApiKeyPermission.ts:22` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/server/src/database/migrations/mysql/1765360298674-AddApiKeyPermission.ts:22` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/server/src/database/migrations/postgres/1765360298674-AddApiKeyPermission.ts:22` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/server/src/database/migrations/sqlite/1765360298674-AddApiKeyPermission.ts:22` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Certificate verification switched off | `packages/server/src/enterprise/utils/sendEmail.ts:24` | Only applies when the operator sets ALLOW_UNAUTHORIZED_CERTS, an explicit opt-in. |
| Credential literal committed to source | `packages/server/src/utils/index.ts:1777` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Credential literal committed to source | `packages/ui/src/views/docstore/DocStoreAPIDialog.jsx:43` | Not a credential: an environment variable name, a permission string, a mask string or a documentation placeholder. |
| Debug or developer error mode enabled in committed config | `CONTRIBUTING.md:236` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `docker/.env.example:38` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `docker/worker/.env.example:38` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `i18n/CONTRIBUTING-ZH.md:154` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `packages/server/.env.example:38` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `packages/server/README-ZH.md:32` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `packages/server/README.md:32` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| Debug or developer error mode enabled in committed config | `packages/server/src/utils/logger.test.ts:126` | Documentation, a commented-out line in .env.example, or a test title; no debug setting is enabled in shipped code. |
| dangerouslySetInnerHTML used | `packages/agentflow/examples/src/TestRunDialog.tsx:191` | Content is sanitised before rendering (SafeHTML), or it is the developer example app using markdown-it with raw HTML disabled by default. |
| dangerouslySetInnerHTML used | `packages/ui/src/ui-component/safe/SafeHTML.jsx:51` | Content is sanitised before rendering (SafeHTML), or it is the developer example app using markdown-it with raw HTML disabled by default. |
| Untrusted markup sink (innerHTML, document.write, insertAdjacentHTML) | `packages/ui/src/views/chatmessage/audio-recording.js:165` | Assigns a formatted elapsed-time string, not untrusted markup. |
| Secret or personal data written to a log | `packages/agentflow/src/core/utils/flowExport.ts:34` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/components/nodes/agents/OpenAIAssistant/OpenAIAssistant.ts:172` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/components/nodes/tools/GoogleDrive/core.ts:394` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/commands/user.ts:33` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/database/migrations/mariadb/1765360298674-AddApiKeyPermission.ts:33` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/database/migrations/mysql/1765360298674-AddApiKeyPermission.ts:33` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/database/migrations/postgres/1765360298674-AddApiKeyPermission.ts:33` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/database/migrations/sqlite/1765360298674-AddApiKeyPermission.ts:33` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/server/src/enterprise/services/account.service.ts:573` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Secret or personal data written to a log | `packages/ui/src/views/credentials/AddEditCredentialDialog.jsx:359` | Log message names a setting or event; no secret value is logged (Authorization is explicitly redacted where headers are logged). |
| Exception caught and discarded | `packages/server/src/controllers/webhook-listener/index.ts:80` | Best-effort cleanup call (heartbeat, close, unregister) where a failure has no security consequence. |
| Exception caught and discarded | `packages/server/src/services/mcp-endpoint/index.ts:318` | Best-effort cleanup call (heartbeat, close, unregister) where a failure has no security consequence. |
| Exception caught and discarded | `packages/server/src/services/webhook-listener/registry.ts:98` | Best-effort cleanup call (heartbeat, close, unregister) where a failure has no security consequence. |
| Exception caught and discarded | `packages/ui/src/views/webhooklistener/WebhookListenerDrawer.jsx:490` | Best-effort cleanup call (heartbeat, close, unregister) where a failure has no security consequence. |
| Cleartext http:// endpoint in code or configuration | `artillery-load-test.yml:6` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/agentflow/src/atoms/Dropdown.test.tsx:10` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/agentflow/src/features/node-editor/AsyncInput.test.tsx:277` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/components/nodes/tools/MCP/Teradata/TeradataMCP.ts:41` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/components/src/validator.test.ts:677` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/enterprise/utils/url.util.test.ts:113` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/index.ts:336` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/services/custom-mcp-servers/index.test.ts:633` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/utils/ipValidation.test.ts:108` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/utils/oauth2Security.test.ts:124` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Cleartext http:// endpoint in code or configuration | `packages/server/src/utils/sanitize.util.test.ts:388` | Test fixture, placeholder text, documentation or an internal example URL; not a cleartext call to an external service. |
| Exception detail or stack trace returned to the caller | `packages/server/src/controllers/text-to-speech/index.ts:213` | Returns a validation or abort message, not a stack trace or internal detail. |
| Exception detail or stack trace returned to the caller | `packages/server/src/routes/oauth2/index.ts:133` | Returns a validation or abort message, not a stack trace or internal detail. |

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

- A01:2025 Broken Access Control - https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/
- A03:2025 Software Supply Chain Failures - https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/
- A04:2025 Cryptographic Failures - https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/
- A06:2025 Insecure Design - https://top10.owasp.org/2025/A06_2025-Insecure_Design/
- A07:2025 Authentication Failures - https://top10.owasp.org/2025/A07_2025-Authentication_Failures/
