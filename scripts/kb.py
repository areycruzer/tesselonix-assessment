#!/usr/bin/env python3
"""Tiny Kanboard HTTP helper for the lab (stdlib only).

Handles cookie sessions and Kanboard's CSRF token (form field `csrf_token`).
Usage pattern:
    kb = KB("http://localhost:8080")
    kb.login("admin", "admin")
    html = kb.get("/?controller=ProjectViewController&action=importTasks&project_id=1")
"""
import re
import sys
import urllib.parse
import urllib.request
import http.cookiejar


class KB:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.logged_in = False

    def get(self, path):
        resp = self.opener.open(self.base + path, timeout=20)
        return resp.read().decode("utf-8", "replace")

    def post(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(self.base + path, data=body)
        resp = self.opener.open(req, timeout=20)
        return resp.read().decode("utf-8", "replace")

    @staticmethod
    def csrf_token(html):
        m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        if not m:
            m = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
        return m.group(1) if m else None

    def login(self, username, password, remember=False):
        login_html = self.get("/?controller=AuthController&action=login")
        token = self.csrf_token(login_html)
        if token is None:
            raise RuntimeError("csrf_token not found on login page")
        data = {"username": username, "password": password, "csrf_token": token}
        if remember:
            data["remember_me"] = "1"
        # The login form posts to AuthController::check (login only renders it).
        self.post("/?controller=AuthController&action=check", data)
        check = self.get("/")
        self.logged_in = "action=logout" in check
        return self.logged_in

    def form_action(self, html):
        """Action URL of the first POST form (Kanboard forms post to dedicated
        save/check actions, not to the URL that renders them)."""
        m = re.search(r'<form[^>]*method="post"[^>]*action="([^"]+)"', html)
        return m.group(1).replace("&amp;", "&") if m else None

    def remember_cookie(self):
        """The first non-session cookie in the jar (Kanboard's remember-me
        cookie after a login with remember_me enabled)."""
        for c in self.cj:
            if c.name != "KB_SID":
                return c
        return None

    def set_cookie(self, name, value):
        """Inject a cookie for localhost so a fresh instance can replay a
        remember-me cookie exactly like a new browser would."""
        self.cj.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain="localhost", domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=True, comment=None, comment_url=None, rest={}, rfc2109=False))
