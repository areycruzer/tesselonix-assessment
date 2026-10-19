# Kanboard Security Assessment

![Kanboard](https://img.shields.io/badge/Kanboard-v1.2.44-blue)
![MariaDB](https://img.shields.io/badge/MariaDB-10.11-blueviolet)
![Reproduced](https://img.shields.io/badge/CVEs_reproduced-3-red)
![Fixes](https://img.shields.io/badge/Fixes-verified-brightgreen)
![Lab](https://img.shields.io/badge/Lab-isolated_Docker-2496ed)

My submission for a 3-day cybersecurity job assessment: a full audit of **Kanboard v1.2.44** with **MariaDB 10.11**, run entirely inside an isolated Docker lab. Two documented CVEs are reproduced with scripted PoCs and **fixed in code**, verified by an automated regression suite. A third finding is mitigated by configuration. A deep-audit pass reproduced one more High SQL injection and documented two further advisories.

Every file under `evidence/` is a raw capture produced by the scripts against the live lab. No third-party system is part of this work.

**Candidate:** Swyam Sharma

## TL;DR for the reviewer

| Finding | Result |
|---|---|
| CVE-2025-46825, stored XSS via project name | Reproduced, **fixed in code**, regression-verified |
| CVE-2026-56774, IDOR in remember-me session removal | Reproduced, **fixed in code**, regression-verified |
| MariaDB published to the host on 0.0.0.0:3306 | Reproduced, **mitigated by configuration** |
| CVE-2026-33058, authenticated SQL injection (deep audit) | **Reproduced**: timing oracle extracts `version()`. Upstream 1.2.51 is the fix |
| CVE-2025-55011, path traversal in file write | Documented, vulnerable code verified in the image, not exploited |
| LDAP injection, reverse-proxy bypass, plugin-installer RCE | Documented, config-gated off in this lab |

Four commands reproduce all of it: [Reproduce everything](#reproduce-everything-in-five-commands).

## The lab

```
                    host (macOS)
                    published :8080 -> 80     (both builds)
                    published :3306 -> 3306   (vulnerable baseline only)
                           |
    -----------------------+-------------------------
    |                  Docker                      |
    |  appnet 172.28.10.0/24     dbnet 172.28.20.0/24
    |  kanboard  .10  :80        mariadb  .10  :3306
    |  client    .20  (nmap,     router   .254
    |  router    .254   dig,     (no services on
    |  dnsmasq   :53     tcpdump)  the dbnet side)
    |        |
    |  iptables FORWARD, policy DROP
    |  allow: kanboard -> mariadb:3306, plus ESTABLISHED,RELATED
    |  drop everything else (rate-limited RT-DROP log)
    -------------------------------------------------
```

Design choices worth knowing:

- **Two subnets behind a router.** Docker already isolates bridges; the router makes routing and firewalling observable in one place, like a small DMZ.
- **Deny by default.** The FORWARD chain allows exactly one flow, `kanboard -> mariadb:3306`, plus replies to established connections. Every other forwarded packet is dropped and rate-limit-logged as `RT-DROP`.
- **Route init sidecars.** Docker drops cross-bridge return traffic, so mariadb needs an explicit return route or the one allowed flow would blackhole its own replies.
- **Internal DNS with three distinct behaviours.** Positive answers for `kanboard.lab.internal` and `mariadb.lab.internal`, NXDOMAIN for unknown names inside the zone, REFUSED for anything outside it. Isolation is demonstrated, not asserted.
- **Two compose files, two differences.** The app image and the published DB port. The network finding and its mitigation are one stanza apart, so the before and after are trivially reviewable.

## Findings

| # | Finding | Severity | Status | PoC | Evidence |
|---|---|---|---|---|---|
| 1 | CVE-2025-46825, stored XSS via project name | High | Fixed in code, verified | `scripts/poc_xss.py` | `evidence/01-xss/` |
| 2 | CVE-2026-56774, IDOR in remember-me session removal | Moderate, chain amplified | Fixed in code, verified | `scripts/poc_idor.py` | `evidence/02-idor/` |
| 3 | MariaDB published to the host on 0.0.0.0:3306 | High pattern in production | Mitigated by configuration | `scripts/network_evidence.sh` | `evidence/03-networking/` |
| 4 | CVE-2026-33058, SQL injection in project permissions | High (CVSS 4.0 8.4) | Reproduced, documented, upstream 1.2.51 | `scripts/poc_sqli.py` | `evidence/04-deep-audit/` |

Full analysis per finding, with root cause, attack chain, impact, fix rationale, and the byte-exact code diff in the appendix: [`findings/FINDINGS.md`](findings/FINDINGS.md). The SQLi and the other deep-audit extras: [`findings/ADDITIONAL-FINDINGS.md`](findings/ADDITIONAL-FINDINGS.md).

## Reproduce everything in five commands

Prerequisites: Docker with Compose v2, Python 3 (stdlib only, nothing to install).

```bash
# 1. Start the vulnerable baseline (fresh database every time)
./scripts/lab_up.sh vulnerable

# 2. Stored XSS: exit 0, a raw <script> lands in the admin's <option> node
python3 scripts/poc_xss.py

# 3. IDOR: exit 0, alice deletes bob's remember_me row with her own credentials
python3 scripts/poc_idor.py

# 4. SQLi (deep audit): exit 0, 0.02s control vs 18s SLEEP payload,
#    extracts MariaDB version() character by character
python3 scripts/poc_sqli.py

# 5. Switch to the patched build: every PoC flips, and the container is
#    md5-verified to run the repo's patched files
./scripts/verify_fixes.sh          # ends with: RESULT: ALL FIXES VERIFIED
```

Exit codes: `0` vulnerable, `2` fixed, `1` setup error. `poc_sqli.py` has no exit 2 by design: the patched image intentionally fixes only the two in-scope CVEs, and the SQLi's real remediation is upstream 1.2.51. That scope choice is stated honestly in `findings/ADDITIONAL-FINDINGS.md`.

Networking evidence is captured the same way, for both builds:

```bash
NET_TAG=vulnerable scripts/network_evidence.sh
NET_TAG=fixed      scripts/network_evidence.sh
```

## Evidence map

| Path | What it proves |
|---|---|
| `evidence/01-xss/{vulnerable,fixed}/` | The exact HTML served to the admin: raw payload vs HTML-escaped, plus run transcripts |
| `evidence/02-idor/{vulnerable,fixed}/` | Steps 01 to 09: remember_me table before and after, the attack request with CSRF token, the control step, replay checks |
| `evidence/03-networking/{vulnerable,fixed}/` | The network finding before and after, nmap TCP matrix, UDP scan, packet captures (.pcap and text) for allowed, refused and filtered TCP, DNS, ICMP port-unreachable, firewall counters |
| `evidence/04-deep-audit/` | SQLi timing transcript |
| `evidence/verify_fixes_run.txt` | Regression suite output, run from a clean clone |

## Repo layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Vulnerable baseline (DB port published: the network finding) |
| `docker-compose.fixed.yml` | Hardened build (patched image, no published DB port) |
| `kanboard-patched/files/` | The patched application files |
| `kanboard-patched/vuln-src/` | Vulnerable originals, so `diff -ru vuln-src files` shows the exact fix |
| `scripts/lab_up.sh` | Start one variant: `vulnerable` or `fixed` |
| `scripts/poc_xss.py`, `poc_idor.py`, `poc_sqli.py` | The PoCs |
| `scripts/verify_fixes.sh` | Regression suite |
| `scripts/network_evidence.sh` | Networking evidence capture, `NET_TAG=vulnerable` or `fixed` |
| `evidence/` | Raw captures, one directory per finding |
| `findings/` | `FINDINGS.md`, `NETWORK-ASSESSMENT.md`, `ADDITIONAL-FINDINGS.md`, `WALKTHROUGH.md` |
| `router/`, `client/` | Router/firewall/DNS image and the attacker toolbox image |
| `TOOLS_AND_AI.md` | AI and scope disclosure |

## Reading order for a 15-minute review

1. This README (3 min)
2. [`findings/FINDINGS.md`](findings/FINDINGS.md) (5 min)
3. [`evidence/verify_fixes_run.txt`](evidence/verify_fixes_run.txt) (1 min)
4. [`findings/NETWORK-ASSESSMENT.md`](findings/NETWORK-ASSESSMENT.md) (3 min)
5. Spot-check any directory under [`evidence/`](evidence) (3 min)

## AI assistance and scope

AI tooling was used interactively and is disclosed honestly in [`TOOLS_AND_AI.md`](TOOLS_AND_AI.md), including an early, abandoned testing episode whose specific details were sent privately to the reviewer rather than published here. I directed the engagement, validated every finding, ran the PoCs myself, and can defend every step in a live walkthrough.
