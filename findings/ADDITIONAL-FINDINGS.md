# Additional Findings — deep-audit second pass

Produced in a full-intensity second pass against the stock **v1.2.44 baseline** (same isolated lab; no third-party systems). These extras are **not** fixed in `kanboard-patched` — the assessment's required scope was one code fix (CVE-2025-46825) plus one mitigation (CVE-2026-56774), both already verified. Each extra finding below carries its upstream remediation reference instead.

## A. CVE-2026-33058 / GHSA-f62r-m4mr-2xhh — authenticated SQL injection — **REPRODUCED**

**Severity:** High (CVSS 4.0 8.4) · **Affected:** Kanboard <= 1.2.50 · **Patched:** 1.2.51

**Root cause** (`app/Model/UserModel.php`, `getOrCreateExternalUserId`):

```php
$userId = $this->db->table(self::TABLE)->eq($externalIdColumn, $externalId)->findOneColumn('id');
```

`external_id_column` is attacker-controlled input passed to `ProjectPermissionController::addUser`, and it is spliced into the WHERE clause **as a column name** — column names cannot be bound as values, and 1.2.44 does not whitelist it. The same input is then used as an array key in the INSERT path. The field is a first-class form input on the project-members page, reachable by anyone with permission to add users to a project — the same app-manager persona the XSS PoC uses.

**PoC:** `scripts/poc_sqli.py` — time-based oracle:

| Request (as app-manager) | Elapsed |
|---|---|
| control, `external_id_column=id` | 0.02s |
| `external_id_column=IF(1=1, SLEEP(6), id)` | 18.01s |

The oracle then extracts `version()` character-by-character: **`10.11.`** — the lab's actual MariaDB 10.11 series. Transcript: `evidence/04-deep-audit/sqli-timing-transcript.txt`.

**Impact:** per the advisory, an attacker with add-user permission can dump the entire Kanboard database (users, password hashes, API tokens, project data).

**Remediation:** upstream 1.2.51 validates the column. Not backported into `kanboard-patched` (outside the assessment's required fix scope) — stated honestly rather than silently patched. Exit contract: `0` vulnerable / `1` setup error; there is deliberately no exit-2 path because the patched image intentionally fixes only the two in-scope CVEs.

## B. CVE-2025-55011 / GHSA-26f4-rx96-xc55 — path traversal in file write — **CODE PRESENCE VERIFIED**

**Severity:** Moderate 5.3 · **Affected:** <= 1.2.46 · **Patched:** 1.2.47

`TaskFileProcedure::createTaskFile` authorizes `project_id` but passes `task_id` straight into `uploadContent`; `FileStorage` writes `baseDir . '/' . $key` with no traversal check — both verified present in our image's source. Advisory impact: write a file anywhere the app user can write, limited because the filename is hashed with no extension. Not exploited end-to-end in this pass (it requires an API token flow; the code-level verification plus advisory is recorded as evidence instead of overclaiming).

## C. Documented but config-gated (not reproducible in this lab's configuration)

| CVE | Gate this lab does not satisfy |
|---|---|
| CVE-2026-21880 — LDAP injection (<= 1.2.48) | LDAP auth; lab uses database auth |
| GHSA-wwpf-3j4p-739w — reverse-proxy auth bypass | `REVERSE_PROXY_AUTH`; not enabled |
| CVE-2026-25924 — plugin-installer authorization bypass -> admin RCE | plugin installer disabled by default |

## D. Hardening observations (no CVE, recorded for the walkthrough)

- `KB_SID` and `KB_RM` cookies: `HttpOnly` is set, but **no `SameSite` attribute** and no `Secure` flag (lab is plain HTTP; production deployments should set both).
- Default credentials `admin/admin` are active on a fresh install (the lab uses them deliberately; production must force a change).
- Header baseline is decent: CSP `default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

## Verification status

| Finding | Status | Evidence |
|---|---|---|
| CVE-2026-33058 SQLi | **reproduced** (exit 0) | `scripts/poc_sqli.py`, `evidence/04-deep-audit/sqli-timing-transcript.txt` |
| CVE-2025-55011 traversal | code presence verified, not exploited | source inspection (section B) |
| LDAP injection / proxy bypass / plugin RCE | documented, config-gated off | advisories (section C) |
