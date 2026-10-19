# Security Findings — Kanboard v1.2.44 (isolated lab)

**Candidate:** Swyam Sharma
**Target:** Kanboard v1.2.44 (official `kanboard/kanboard` image) with MariaDB 10.11
**Environment:** local, isolated Docker lab — two subnets (`appnet` 172.28.10.0/24, `dbnet` 172.28.20.0/24) joined by an iptables router; no third-party systems were touched
**Method:** documented CVEs reproduced with scripted PoCs (exit-code contract below), fixes mirrored from upstream commits, evidence captured raw under `evidence/`

## Summary

| # | Finding | Component | Severity | Status |
|---|---------|-----------|----------|--------|
| 1 | CVE-2025-46825 — stored XSS via project name | `Template/project_view/importTasks.php` | High | fixed in code (`kanboard-patched`) |
| 2 | CVE-2026-56774 — IDOR in remember-me session removal | `UserViewController`, `RememberMeSessionModel`, `AuthSubscriber` | Moderate (chain-amplified) | fixed in code (`kanboard-patched`) |
| 3 | MariaDB published to the host on `0.0.0.0:3306` | `docker-compose.yml` (baseline) | High pattern in production | mitigated in `docker-compose.fixed.yml` |

Both application fixes are the exact upstream remediations, applied as file replacements and verified end-to-end by `scripts/verify_fixes.sh` (both PoCs exit 2 on the patched image, self-service control still works, and the container is md5-verified to run the repo's patched files).

---

## Finding 1 — Stored XSS (CVE-2025-46825)

**Where:** `app/Template/project_view/importTasks.php` renders `$project['name']` into an `<option>` node without HTML-escaping.

**Attack chain (as scripted in `scripts/poc_xss.py`):**
1. A user with the project-manager role creates a project whose name is the payload: `<script>alert(document.domain)</script>`.
2. The manager adds the administrator as a member of that project — the Import-Tasks dropdown lists only projects the victim belongs to, so membership is required for delivery.
3. The administrator opens the Import-Tasks page; the template prints the project name raw:
   `<option value="2"><script>alert(document.domain)</script></option>`
4. The payload executes in the administrator's browser at the application origin (`document.domain` demonstrates the origin).

**Impact:** classic privilege escalation by stored XSS — a low-privileged manager poisons a page only an admin renders. Cookie theft (session or, if not httpOnly, the remember-me cookie — see Finding 2's chain note), silent administrative actions via the same origin, defacement.

**Why the fix is what it is:** escape at the sink with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')` — `ENT_QUOTES` covers both quote contexts the name can land in, `UTF-8` matches the application's output encoding. Output-encoding at the point of interpolation is the correct control for template-rendered user data (no need to reject the name at input — names legitimately contain punctuation and international text).

**Verification:** `poc_xss.py` exits `0` (VULNERABLE) against `docker-compose.yml` and `2` (FIXED, payload served HTML-escaped) against `docker-compose.fixed.yml`; `1` signals a setup error. Verdicts match the exact `<option>` line, not a whole-page substring.

**A nuance documented on purpose:** the project-switcher widget embeds the raw name inside a JSON `data-params` *attribute* on both builds. That is attribute context, not an executed node — the string only becomes executable if client-side JS were to write it into the DOM as HTML. The PoC therefore judges the `<option>` node (the actual sink, and what upstream patched); the attribute appears as informational context in the transcripts.

**Evidence:** `evidence/01-xss/vulnerable/import-page.html` (raw `<script>` in the `<option>`), `evidence/01-xss/fixed/import-page.html` (escaped `&lt;script&gt;`), run transcripts in both directories.

---

## Finding 2 — IDOR in remember-me session removal (CVE-2026-56774)

**Background (how Kanboard persistent login works):** "remember me" issues cookie `KB_RM` carrying a token + sequence validated against a row in the `remember_me` table (`RememberMeSessionModel::find`); `RememberMeAuth` uses it to re-authenticate. Logout invalidates the persistent login by **deleting that row** (`AuthSubscriber::afterLogout` → `remove()`).

**Where:** `UserViewController::removeSession` passed only the request's `id` parameter to `RememberMeSessionModel::remove($session_id)` — the query matched by session id alone, so the `user_id` scoping never happened and any authenticated user could remove **any other user's** remember-me row with their own CSRF token and user id.

**Attack chain (as scripted in `scripts/poc_idor.py`):**
1. Two regular users (app-user role), alice and bob, each log in with "remember me" — both get `remember_me` rows.
2. alice opens her own sessions page and harvests the CSRF token from the Remove links (the token is bound to her session, which is the point: the request is fully legitimate *except* for whose row it targets).
3. **Control step:** alice removes **her own** session by id — this works on both builds and proves the feature itself is intact.
4. **Attack step:** the same request with only the `id` swapped for bob's session id (`user_id` still alice's). On the vulnerable build bob's `remember_me` row is deleted (verified by querying the table before/after — the PoC uses the database as the oracle, not the HTTP response, because the endpoint redirects either way).

**Impact:** targeted invalidation of a victim's persistent login — an attacker can force-logout any user whose session id they know, or (chained with any cookie-reading XSS) destroy sessions at scale. Honest severity assessment: the attack requires knowing the victim's random session id, which on its own is hard to obtain — that is why this is Moderate rather than High, and why the XSS above is the natural chain partner. The row deletion is exactly how Kanboard's own logout kills the cookie, so the impact is precise, not speculative.

**Why the fix is what it is:** scope the removal to the authenticated user — `remove($session_id, $user_id)` with `->eq('user_id', $user_id)` in the model, and both call sites (`UserViewController::removeSession`, `AuthSubscriber::afterLogout`) pass the current user's id. This mirrors upstream commit `928c68a` exactly. Both parameters must now match the acting user, so a legitimate self-removal still works while a swapped id is a no-op.

**Verification:** `poc_idor.py` exits `0` (VULNERABLE — control ok, bob's row deleted) and `2` (FIXED — control ok, bob's row survives); `1` signals a setup error. The control step is deliberately part of the contract: it prevents a naive "row still exists" false-positive verdict from counting as fixed.

**Evidence:** `evidence/02-idor/{vulnerable,fixed}/01…09` — remember_me table before/attack/after, alice's sessions page, control and attack requests with the exact URL + CSRF token, responses, replay notes.

---

## Finding 3 (network) — MariaDB published to the host on 0.0.0.0:3306

**Where:** the baseline `docker-compose.yml` publishes `3306:3306`, which binds `0.0.0.0` on the host (all interfaces, not just loopback).

**Evidence:** `evidence/03-networking/vulnerable/host-published-ports.txt` shows `3306/tcp -> 0.0.0.0:3306`, and `host-db-reachability.txt` shows a host-level process (`com.docker.backend`) listening on `*:3306` with a successful connect. The fixed build publishes nothing for MariaDB and the same probe is **REFUSED** (`evidence/03-networking/fixed/…`).

**Why it matters:** publishing a database port exposes it to every process and interface on the host and, depending on host firewalling, the local network — an attacker on the same LAN gets a direct TCP handshake to the DB, bypassing the entire application layer (auth, CSRF, roles). In production this is the single most common way internal databases leak.

**Mitigation:** remove the `ports:` stanza — the database stays reachable only via the routed internal path (appnet → router → dbnet) guarded by the router's deny-by-default firewall, which allows exactly one flow: `172.28.10.10 → 172.28.20.10:3306`. Same application, same data, zero host exposure. Full network analysis in `findings/NETWORK-ASSESSMENT.md`.

---

## Verification matrix

| Finding | Vulnerable lab | Fixed lab | Script |
|---|---|---|---|
| Stored XSS | exit 0 — raw `<script>` in `<option>` | exit 2 — `&lt;script&gt;` escaped | `scripts/poc_xss.py` |
| IDOR | exit 0 — bob's row deleted, control ok | exit 2 — bob's row survives, control ok | `scripts/poc_idor.py` |
| DB exposed to host | `localhost:3306` CONNECTED | REFUSED | `scripts/network_evidence.sh` |

**Regression suite:** `scripts/verify_fixes.sh` rebuilds the patched image, resets the lab, runs both PoCs asserting exit 2, and md5-compares the four patched files inside the running container against the repo. Raw transcript: `evidence/verify_fixes_run.txt` (`RESULT: ALL FIXES VERIFIED`).

## Limitations (stated plainly)

- The XSS PoC asserts the served HTML (the injection and its exact DOM position), not a browser screenshot; the payload is present unescaped where the browser will execute it. A headless-browser step would raise confidence from "HTML is poisoned" to "JS ran".
- The IDOR PoC proves the row deletion via the database oracle; it does not demonstrate obtaining the victim's session id (that is a chaining problem, noted above).
- Kernel drop logs (`RT-DROP` via `dmesg`) are not readable inside the container (`CAP_SYSLOG` is withheld), so firewall-drop proof is the iptables LOG-rule packet counter delta (0 → 7 packets) plus the SYN-retransmit capture.
- Reverse DNS is not configured on the lab resolver (PTR probe returns REFUSED) — a deliberate scope choice, documented in the network assessment.

## References

- CVE-2025-46825 (Kanboard stored XSS) and CVE-2026-56774 (session-removal IDOR) — publicly documented; the applied fixes mirror upstream Kanboard commit `928c68a` (reference diff kept at `kanboard-patched/patches/`).
- Exact code changes: `diff -ru kanboard-patched/vuln-src kanboard-patched/files` — reproduced in the appendix below.

## Appendix — the exact code changes

Output of `diff -ru kanboard-patched/vuln-src kanboard-patched/files` (vulnerable originals extracted from the stock v1.2.44 image vs the patched files the fixed image runs):

```diff
diff -ru kanboard-patched/vuln-src/app/Controller/UserViewController.php kanboard-patched/files/app/Controller/UserViewController.php
--- kanboard-patched/vuln-src/app/Controller/UserViewController.php	2026-10-19 23:37:29
+++ kanboard-patched/files/app/Controller/UserViewController.php	2026-10-19 23:41:30
@@ -123,7 +123,7 @@
     {
         $this->checkCSRFParam();
         $user = $this->getUser();
-        $this->rememberMeSessionModel->remove($this->request->getIntegerParam('id'));
+        $this->rememberMeSessionModel->remove($this->request->getIntegerParam('id'), $user['id']);
 
         if ($this->request->isAjax()) {
             $this->sessions();
diff -ru kanboard-patched/vuln-src/app/Model/RememberMeSessionModel.php kanboard-patched/files/app/Model/RememberMeSessionModel.php
--- kanboard-patched/vuln-src/app/Model/RememberMeSessionModel.php	2026-10-19 23:37:29
+++ kanboard-patched/files/app/Model/RememberMeSessionModel.php	2026-10-19 23:41:30
@@ -104,13 +104,15 @@
      *
      * @access public
      * @param  integer  $session_id   Session id
+     * @param  integer  $user_id      User id
      * @return mixed
      */
-    public function remove($session_id)
+    public function remove($session_id, $user_id)
     {
         return $this->db
             ->table(self::TABLE)
             ->eq('id', $session_id)
+            ->eq('user_id', $user_id)
             ->remove();
     }
 
diff -ru kanboard-patched/vuln-src/app/Subscriber/AuthSubscriber.php kanboard-patched/files/app/Subscriber/AuthSubscriber.php
--- kanboard-patched/vuln-src/app/Subscriber/AuthSubscriber.php	2026-10-19 23:37:29
+++ kanboard-patched/files/app/Subscriber/AuthSubscriber.php	2026-10-19 23:41:30
@@ -78,7 +78,7 @@
             $session = $this->rememberMeSessionModel->find($credentials['token'], $credentials['sequence']);
 
             if (! empty($session)) {
-                $this->rememberMeSessionModel->remove($session['id']);
+                $this->rememberMeSessionModel->remove($session['id'], $session['user_id']);
             }
 
             $this->rememberMeCookie->remove();
diff -ru kanboard-patched/vuln-src/app/Template/project_view/importTasks.php kanboard-patched/files/app/Template/project_view/importTasks.php
--- kanboard-patched/vuln-src/app/Template/project_view/importTasks.php	2026-10-19 23:37:29
+++ kanboard-patched/files/app/Template/project_view/importTasks.php	2026-10-19 23:37:28
@@ -8,7 +8,7 @@
         <select name="projects" id="projects">
             <option value="" disabled selected><?= t('Choose a project') ?></option>
             <?php foreach ($projects as $projectId => $projectName) { ?>
-                <option value="<?= $projectId?>"><?= $projectName ?></option>
+                <option value="<?= $projectId?>"><?= htmlspecialchars($projectName, ENT_QUOTES, 'UTF-8') ?></option>
             <?php } ?>
         </select>
         <div class="form-actions">
```
