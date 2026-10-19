# Live Walkthrough Script (15–20 minutes)

My demo order. Every command is copy-pasteable; expected key output is quoted. If anything breaks live, the committed transcripts under `evidence/` are the fallback — say so plainly and keep moving.

## Preparation (before the call)

```bash
cd ~/Desktop/tesselonix-assessment
docker compose -f docker-compose.yml down -v --remove-orphans
docker compose -f docker-compose.fixed.yml down -v --remove-orphans
```

Know these cold: subnets `172.28.10.0/24` (appnet) / `172.28.20.0/24` (dbnet); IPs kanboard `.10.10`, client `.10.20`, mariadb `.20.10`, router `.254`; only allowed forwarded flow = kanboard→mariadb:3306; PoC exits `0` vulnerable / `2` fixed / `1` setup error; CVE-2025-46825 (XSS), CVE-2026-56774 (IDOR), upstream fix commit `928c68a`.

## 0:00–2:00 — Framing

"I stood up Kanboard v1.2.44 with MariaDB in an isolated Docker lab — two subnets joined by an iptables router, deny-by-default forwarding, dnsmasq for DNS. Everything runs from one repo; two findings are documented CVEs I reproduced and fixed in code, and the third is a network-exposure finding I mitigated. AI assistance is disclosed in TOOLS_AND_AI.md; every artifact in evidence/ is a raw capture from this lab."

Show: `git log --oneline` (the build history tells the story), repo tree.

## 2:00–6:00 — Finding 1, XSS (CVE-2025-46825)

```bash
./scripts/lab_up.sh vulnerable && python3 scripts/poc_xss.py; echo "exit=$?"
```

Expected end: `[VERDICT] VULNERABLE — raw <script> payload served unescaped in an <option> node`, exit 0.

Narrate the chain: manager creates project named `<script>alert(document.domain)</script>` → adds admin as a member (dropdown shows member projects only — that's why the add-user step exists) → admin opens Import-Tasks → payload lands raw in the option node. Show the poisoned line:

```bash
grep -n "option value" evidence/01-xss/vulnerable/import-page.html | head -2
```

Point at the root cause and the one-line fix: `diff -ru kanboard-patched/vuln-src kanboard-patched/files` — `htmlspecialchars($project['name'], ENT_QUOTES, 'UTF-8')` at the sink.

## 6:00–10:00 — Finding 2, IDOR (CVE-2026-56774)

```bash
python3 scripts/poc_idor.py; echo "exit=$?"
```

(The lab is already up and freshly reset by the previous run's users; if starting clean, run `./scripts/lab_up.sh vulnerable` first.)

Expected: `[5] remember_me before: alice row 2, bob row 1` → `[8] CONTROL: alice removed her own session -> works` → `[10] remember_me after attack: []` → VULNERABLE, exit 0. The database is the oracle: the attack request uses alice's own user_id, CSRF token, and session — only the `id` is bob's.

Explain the control step: it proves the feature (self-service session removal) still works after the fix, so the fixed verdict can't be a false positive from breaking the endpoint. Fix = scope the removal: `remove($session_id, $user_id)` with `eq('user_id', $user_id)` — upstream commit `928c68a`, three files. Show `evidence/02-idor/vulnerable/06-attack-request.txt`.

## 10:00–12:00 — The fixes, verified

```bash
./scripts/verify_fixes.sh
```

Expected tail: both PoCs exit 2, four `OK` md5 lines, `RESULT: ALL FIXES VERIFIED`. Explain the md5 check: it proves the running container serves the repo's patched files — the test can't pass on a stock image. If time is short, show `evidence/verify_fixes_run.txt` instead of running it.

## 12:00–16:00 — Networking

Open `findings/NETWORK-ASSESSMENT.md` (diagram), then show three pieces of evidence:

```bash
grep -h "host -> localhost:3306" evidence/03-networking/{vulnerable,fixed}/host-db-reachability.txt
sed -n '/tcpdump readback/,$p' evidence/03-networking/vulnerable/tcp-filtered.txt | head -9
sed -n '/tcpdump readback/,$p' evidence/03-networking/vulnerable/udp-unreachable.txt | tail -3
```

Story: (1) the network finding — baseline publishes MariaDB on `0.0.0.0:3306`, host connects; fixed build REFUSED (one stanza removed). (2) client→mariadb:3306 is *filtered*: seven SYN retransmits visible on the router, never forwarded, no RST — that contrast is closed-vs-filtered. (3) UDP to a closed port draws ICMP port-unreachable; DNS answers positively for `kanboard.lab.internal`, NXDOMAIN for unknown in-zone names, REFUSED for external — isolation demonstrated. Mention the router's LOG counter delta (0→7) since `dmesg` isn't readable in-container.

## 16:00–18:00 — Engineering honesty

- Evidence integrity: transcripts are raw captures; verdicts use exact DOM/table checks, not substring greps (the widget attribute nuance shows why that matters).
- Limitations I own: no headless-browser execution step for the XSS; IDOR needs the victim's session id (chaining problem); no phpunit suite for the model (end-to-end contract instead).
- AI disclosure: TOOLS_AND_AI.md — I directed the engagement, validated every finding, and can defend every line here.

## Anticipated questions

1. **Why is the payload raw in the widget's `data-params` but you don't call that vulnerable?** It's HTML attribute context (JSON-encoded); it only executes if JS writes it into the DOM as HTML. Upstream patched the `<option>` node — the actual sink. My verdict matches that line for exactly this reason.
2. **Why does deleting the row matter?** Remember-me = cookie token/sequence validated against the `remember_me` row; deleting the row is precisely how Kanboard's own logout kills the persistent cookie. The PoC replays the cookie and watches the table.
3. **Why `eq('user_id', $user_id)` rather than only checking the id?** Defense in depth: both the session id and the owner must match the authenticated user. Mirrors upstream `928c68a`.
4. **Why ENT_QUOTES?** Both quote contexts must be encoded for attribute injection; UTF-8 matches app output.
5. **How do you know the container runs the patched files?** `verify_fixes.sh` md5-compares the four files inside the running container against the repo.
6. **Closed vs filtered?** Closed = RST (reachable, no listener). Filtered = silence (something dropped it). Our dbnet matrix is all-filtered from the client; same-subnet hosts answer RSTs.
7. **Why does the allowed flow work at all?** Return-route sidecars: Docker drops cross-bridge return traffic, so mariadb needs `172.28.10.0/24 via 172.28.20.254` — otherwise the ACCEPT rule would blackhole its own replies.
8. **Why ip_forward via compose sysctls?** `/proc/sys` is read-only in containers; the namespaced sysctl is whitelisted at container create; the entrypoint verifies it.
9. **Why does dnsmasq bind by address?** Docker's eth0/eth1 attach order is nondeterministic; `listen-address=172.28.10.254` is order-proof.
10. **Why lab.internal?** `.local` is reserved for mDNS (RFC 6762); `.internal` is reserved for private use. dig warns on `.local` queries.
11. **Severity of the IDOR?** Moderate alone — attacker needs the victim's random session id; chain-amplified by any cookie-reading XSS. I say so in FINDINGS.md.
12. **What would you add with more time?** Headless-browser XSS execution, phpunit tests for the model scoping, CSRF token per-action rotation review, and CI running verify_fixes.sh.
13. **Did you test anything outside the lab?** No — an earlier live-testing idea was abandoned before this submission; its two test artifacts are disclosed privately to the reviewer (details sent with the cover email, kept out of the public repo because they concern a third party's systems). This submission is 100% local lab work.
14. **How was AI used?** Interactive coding agent for scaffolding and drafts under my direction; I chose the target, validated every finding, ran the PoCs, and own this walkthrough. Details in TOOLS_AND_AI.md.

## Cheat sheet

- Subnets: appnet `172.28.10.0/24`, dbnet `172.28.20.0/24`; router `.254` in both.
- Services: kanboard 80 (+443 stock), mariadb 3306 (internal), dnsmasq 53 (appnet side).
- Zone: `lab.internal` — positive / NXDOMAIN (in-zone unknown) / REFUSED (external).
- Exits: `poc_xss.py`, `poc_idor.py` → 0 vulnerable, 2 fixed, 1 setup error.
- CVEs: 2025-46825 (XSS), 2026-56774 (IDOR); upstream fix commit `928c68a`.
- Scripts: `lab_up.sh vulnerable|fixed`, `network_evidence.sh` (NET_TAG), `verify_fixes.sh`.
