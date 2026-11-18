"""
auth_handling.py -- what to do when a target has a login.

Recon already records the auth surface (``auth_paths`` and the
``auth_flows`` login analysis) on the SystemMap, and context.py can load
credentials/cookies. This module ties the two together and answers one
question clearly, for the console, the report and the engagement summary:

    Does this target have a login, and -- given what the operator supplied --
    are we testing it anonymously, authenticated, or not at all?

It never brute-forces or guesses credentials; authenticated testing happens
only with credentials or a session cookie the operator provides for a target
they are authorized to test. When none are supplied, the point of this module
is to say so loudly and tell the operator exactly how to supply them, instead
of silently leaving the authenticated surface untested.

Pure over dicts; no tools, LLM or network.
"""

from __future__ import annotations

from typing import Any

# Auth-gated OWASP categories: without an authenticated session these can only
# be partially assessed from the outside.
AUTH_GATED_OWASP = {
    "A01": "Broken Access Control",
    "A07": "Identification & Authentication Failures",
}


def detect_login(system_map: dict[str, Any]) -> dict[str, Any]:
    """What recon found about a login surface on this target."""
    smap = system_map or {}
    auth_paths = [str(p) for p in (smap.get("auth_paths") or [])]
    flows = smap.get("auth_flows") or {}
    results = flows.get("auth_results") or []

    login_urls: list[str] = []
    has_form = False
    mechanisms: list[str] = []
    mfa = bool(flows.get("mfa_detected"))
    csrf = bool(flows.get("csrf_protected"))
    _login_path = ("login", "signin", "sign-in", "auth", "sso", "oauth",
                   "account", "admin", "session")
    for r in results:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "")
        mechs = [str(m) for m in (r.get("mechanisms") or []) if m]
        is_form = bool(r.get("login_form") or r.get("has_password_field"))
        # A login surface is a password form OR an SSO/OAuth/SAML/Basic login
        # OR a login-ish URL that answered. OAuth logins (no password field on
        # the first page) are still logins -- not counting them was wrong.
        is_auth = is_form or any(
            m.lower() in ("oauth", "saml", "sso", "form", "basic", "oidc", "openid")
            for m in mechs) or any(h in url.lower() for h in _login_path)
        if is_form:
            has_form = True
        if is_auth and url:
            login_urls.append(url)
        for m in mechs:
            if m not in mechanisms:
                mechanisms.append(m)
        if r.get("mfa_hint"):
            mfa = True
    login_url = flows.get("login_url")
    if login_url and login_url not in login_urls:
        login_urls.append(str(login_url))

    # auth_paths (…/login, …/admin, …/signin) are a weaker signal than a real
    # password form, but still mean "there is an authenticated area here".
    for p in auth_paths:
        low = p.lower()
        if p not in login_urls and any(
                h in low for h in ("login", "signin", "sign-in", "auth", "account", "admin")):
            login_urls.append(p)

    # Anonymous (pre-login) testable surface: query endpoints, parameters and
    # sensitive endpoints that are NOT the login itself. A login-wall target
    # (SPA/portal where the root is the login) has almost none of this, so
    # there is little to test until a session is supplied.
    login_set = {u.rstrip("/") for u in login_urls}
    anon = 0
    for ep in (smap.get("endpoints") or []):
        s = str(ep)
        if s.rstrip("/") in login_set:
            continue
        if "?" in s or s.rstrip("/") not in {a.rstrip("/") for a in auth_paths}:
            anon += 1
    anon += len(smap.get("parameters") or [])
    anon += len(smap.get("sensitive_endpoints") or [])
    login_detected = bool(login_urls or has_form or auth_paths)
    login_wall = bool(login_detected and anon <= 2)

    return {
        "login_detected": login_detected,
        "login_wall": login_wall,
        "anon_surface": anon,
        "has_password_form": has_form,
        "login_urls": login_urls[:10],
        "auth_paths": auth_paths[:10],
        "mechanisms": mechanisms,
        "mfa_detected": mfa,
        "csrf_protected": csrf,
    }


def _ctx_summary(context: Any) -> dict[str, Any]:
    """Normalise an EngagementContext (object or dict) into creds/cookies/identity."""
    if context is None:
        return {"credentials": 0, "cookies": 0, "identity": "anonymous", "labels": []}
    if isinstance(context, dict):
        creds = context.get("credentials") or []
        cookies = context.get("cookies") or {}
        identity = context.get("identity") or "anonymous"
        labels = [c.get("identity") for c in creds
                  if isinstance(c, dict) and c.get("identity") not in (None, "", "anonymous")]
    else:
        creds = getattr(context, "credentials", []) or []
        cookies = getattr(context, "cookies", {}) or {}
        identity = getattr(context, "identity", "anonymous") or "anonymous"
        labels = context.identity_labels() if hasattr(context, "identity_labels") else []
    return {"credentials": len(creds), "cookies": len(cookies),
            "identity": identity, "labels": sorted(set(labels))}


def _guidance(target: str, login: dict[str, Any], ctx: dict[str, Any]) -> str:
    where = login["login_urls"][0] if login["login_urls"] else "the target"
    return (
        f"A login was detected ({where}). To test the authenticated surface "
        f"(session management, access control, and anything behind the login), "
        f"re-run with a session cookie or credentials for an account you are "
        f"authorized to use:\n"
        f"  cyberswarm attack {target} --cookies-file session.txt\n"
        f"    session.txt: a 'Cookie: name=value; ...' line, a JSON cookie map, "
        f"or a HAR export.\n"
        f"  cyberswarm attack {target} --creds-file creds.json [--identity A]\n"
        f"    creds.json: {{\"users\":[{{\"identity\":\"A\",\"username\":\"...\","
        f"\"password\":\"...\"}}]}}\n"
        f"Without them, authenticated areas are reported as NOT TESTED rather "
        f"than assumed secure."
    )


def auth_status(system_map: dict[str, Any], context: Any = None,
                target: str | None = None) -> dict[str, Any]:
    """Combine login detection with what the operator supplied.

    mode:
      anonymous_no_login         no login found; anonymous testing is complete
      authenticated              a session/credentials were supplied and will be used
      login_detected_no_creds    a login exists but nothing was supplied to test it
    """
    login = detect_login(system_map)
    ctx = _ctx_summary(context)
    target = target or str((system_map or {}).get("target") or "the-target")
    have_auth = ctx["credentials"] > 0 or ctx["cookies"] > 0

    if not login["login_detected"]:
        mode = "anonymous_no_login"
        headline = "No login surface detected; testing the anonymous surface only."
        guidance = ""
    elif have_auth:
        mode = "authenticated"
        how = []
        if ctx["cookies"]:
            how.append(f"{ctx['cookies']} session cookie(s)")
        if ctx["credentials"]:
            how.append(f"{ctx['credentials']} credential(s) "
                       f"[{', '.join(ctx['labels']) or ctx['identity']}]")
        headline = ("Login detected and " + " and ".join(how)
                    + " supplied — authenticated testing is enabled.")
        guidance = ""
    else:
        mode = "login_detected_no_creds"
        if login["login_wall"]:
            headline = ("This target is a LOGIN WALL — almost everything is behind "
                        "the login and no session was supplied, so there is very "
                        "little to test. Supply a session to go further.")
        else:
            headline = ("Login detected but no credentials or session cookie supplied "
                        "— the authenticated surface will NOT be tested.")
        guidance = _guidance(target, login, ctx)

    return {
        "mode": mode,
        "headline": headline,
        "guidance": guidance,
        "login": login,
        "context": ctx,
        "auth_gated_owasp": sorted(AUTH_GATED_OWASP) if login["login_detected"] else [],
    }


def console_notice(status: dict[str, Any]) -> str:
    """One block to print at the start of an attack run."""
    lines = ["", "=" * 60, "[auth] " + status["headline"]]
    login = status["login"]
    if login["login_detected"]:
        if login["login_urls"]:
            lines.append("[auth] login at: " + ", ".join(login["login_urls"][:5]))
        tags = []
        if login["has_password_form"]:
            tags.append("password form")
        if login["mechanisms"]:
            tags.append("mechanisms: " + ", ".join(login["mechanisms"][:4]))
        if login["mfa_detected"]:
            tags.append("MFA hint")
        if login["csrf_protected"]:
            tags.append("CSRF-protected")
        if tags:
            lines.append("[auth] " + "; ".join(tags))
    if status["guidance"]:
        lines += ["[auth] " + ln for ln in status["guidance"].splitlines()]
    lines.append("=" * 60)
    return "\n".join(lines)


def render_auth_section(status: dict[str, Any]) -> str:
    """Markdown 'Authentication' section for the attack report."""
    login = status["login"]
    L = ["## Authentication", "", status["headline"], ""]
    if login["login_detected"]:
        if login["login_urls"]:
            L.append("- Login surface: " + ", ".join(f"`{u}`" for u in login["login_urls"][:5]))
        if login["mechanisms"]:
            L.append("- Mechanisms: " + ", ".join(login["mechanisms"][:5]))
        L.append(f"- Password form observed: {'yes' if login['has_password_form'] else 'no'}")
        L.append(f"- MFA hint: {'yes' if login['mfa_detected'] else 'no'}  |  "
                 f"CSRF-protected: {'yes' if login['csrf_protected'] else 'no'}")
        c = status["context"]
        L.append(f"- Session supplied: {c['cookies']} cookie(s), {c['credentials']} "
                 f"credential(s), identity `{c['identity']}`")
        if login.get("login_wall"):
            L.append("- **Login wall:** the anonymous surface is minimal "
                     f"({login['anon_surface']} testable item(s)); most testing needs a session.")
        if status["mode"] == "login_detected_no_creds":
            L += ["", "> The authenticated surface was **not tested** (no credentials "
                  "supplied). OWASP A01 (Broken Access Control) and A07 "
                  "(Authentication Failures) can only be partially assessed from "
                  "outside the login.", ""]
            L.append("```")
            L += status["guidance"].splitlines()
            L.append("```")
    return "\n".join(L).rstrip() + "\n"


def parse_cookie_line(line: str) -> dict[str, str]:
    """Parse a pasted 'Cookie: a=b; c=d' header (or a bare 'a=b; c=d') into a
    name->value dict. Lenient: ignores blanks and malformed pairs."""
    s = (line or "").strip()
    if s.lower().startswith("cookie:"):
        s = s[len("cookie:"):]
    out: dict[str, str] = {}
    for part in s.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            if k.strip():
                out[k.strip()] = v.strip()
    return out


_MENU = """\
[auth] This target has a login. How do you want to handle it?
  1) Enter a username and password now  (I'll prompt you; password is hidden)
  2) Paste a session cookie now         (best for SPA / OAuth / login-wall sites)
  3) Point me at a file                 (--cookies-file / --creds-file)
  4) Continue anonymously               (only the pre-login surface is tested)
  5) Abort
Choose [1/2/3/4/5] (default 4): """


def _default_result() -> dict[str, Any]:
    return {"action": "proceed", "cookies": {}, "credentials": [], "message": ""}


def _prompt_credentials(input_fn, getpass_fn) -> dict[str, Any]:
    """Prompt for one username/password/identity. Returns an 'authenticated'
    result dict, or a 'continue_anonymous' one if input is incomplete."""
    try:
        username = (input_fn("[auth] Username: ") or "").strip()
        password = getpass_fn("[auth] Password (hidden): ") or ""
        identity = (input_fn("[auth] Identity label for this account [A]: ")
                    or "A").strip() or "A"
        login_url = (input_fn("[auth] Login URL (optional, Enter to skip): ") or "").strip()
    except (EOFError, KeyboardInterrupt):
        return {"action": "continue_anonymous", "cookies": {}, "credentials": [],
                "message": "cancelled; continuing anonymously"}
    if username and password:
        cred = {"username": username, "password": password, "identity": identity}
        if login_url:
            cred["source_url"] = login_url
        return {"action": "authenticated", "cookies": {}, "credentials": [cred],
                "identity": identity,
                "message": f"using credentials for identity '{identity}'"}
    return {"action": "continue_anonymous", "cookies": {}, "credentials": [],
            "message": "username/password incomplete; continuing anonymously"}


def _prompt_cookie(input_fn) -> dict[str, Any]:
    """Prompt for a pasted Cookie header. Returns an 'authenticated' result
    dict, or a 'continue_anonymous' one if nothing parseable was pasted."""
    try:
        raw = input_fn("[auth] Paste the Cookie header (one line), then Enter:\n")
    except (EOFError, KeyboardInterrupt):
        raw = ""
    cookies = parse_cookie_line(raw)
    if cookies:
        return {"action": "authenticated", "cookies": cookies, "credentials": [],
                "message": f"using {len(cookies)} pasted cookie(s)"}
    return {"action": "continue_anonymous", "cookies": {}, "credentials": [],
            "message": "no valid cookie parsed; continuing anonymously"}


_PRELAUNCH_MENU = """\
[auth] Before scanning {target}: will this target need a login to reach most of
       its functionality? Supplying access now lets the whole run use it.
  1) Yes — enter a username and password now  (password hidden)
  2) Yes — paste a session cookie now         (best for SPA / OAuth sites)
  3) No / not sure — continue                 (I'll detect a login and ask if found)
Choose [1/2/3] (default 3): """


def prelaunch_auth(target: str, input_fn=input, getpass_fn=None,
                   is_tty: bool | None = None, auto: bool = False) -> dict[str, Any]:
    """Ask about authentication at the very START of an engagement, before
    recon, so credentials are supplied once and used throughout.

    Returns the same result shape as interactive_resolve. 'proceed' means
    nothing was supplied up front (a login found during recon will still
    prompt). Non-interactive / --auto-approve runs never block.
    """
    import sys
    if getpass_fn is None:
        import getpass
        getpass_fn = getpass.getpass
    if is_tty is None:
        is_tty = sys.stdin.isatty()
    if auto or not is_tty:
        return _default_result()
    try:
        choice = (input_fn(_PRELAUNCH_MENU.format(target=target)) or "").strip() or "3"
    except (EOFError, KeyboardInterrupt):
        return _default_result()
    if choice == "1":
        r = _prompt_credentials(input_fn, getpass_fn)
    elif choice == "2":
        r = _prompt_cookie(input_fn)
    else:
        return _default_result()
    # On this up-front prompt, incomplete input just means "continue; ask later".
    if r["action"] != "authenticated":
        return _default_result()
    return r


def interactive_resolve(status: dict[str, Any], target: str,
                        input_fn=input, getpass_fn=None, is_tty: bool | None = None,
                        auto: bool = False) -> dict[str, Any]:
    """Friendly, interactive handling when a login is detected and nothing was
    supplied. Returns {"action", "cookies", "credentials", "message"}:

      proceed            nothing to ask (no login, already authenticated, or
                         non-interactive) -- run as-is
      authenticated      the operator supplied a session cookie OR a
                         username/password -> use it
      continue_anonymous run but only the pre-login surface is tested
      abort              stop; the operator will re-run with a session

    Non-interactive runs (no TTY, or --auto-approve/auto=True) never block: they
    return 'proceed' and rely on the printed guidance, so scheduled/CI runs are
    unaffected. `getpass_fn` reads the password without echoing it (defaults to
    getpass.getpass); tests inject their own.
    """
    import sys
    if getpass_fn is None:
        import getpass
        getpass_fn = getpass.getpass
    if is_tty is None:
        is_tty = sys.stdin.isatty()
    if status["mode"] != "login_detected_no_creds" or auto or not is_tty:
        return _default_result()

    def _anon(msg):
        return {"action": "continue_anonymous", "cookies": {}, "credentials": [], "message": msg}

    try:
        choice = (input_fn(_MENU) or "").strip() or "4"
    except (EOFError, KeyboardInterrupt):
        return _anon("no input; continuing anonymously")

    if choice == "1":
        return _prompt_credentials(input_fn, getpass_fn)
    if choice == "2":
        return _prompt_cookie(input_fn)
    if choice == "3":
        return {"action": "abort", "cookies": {}, "credentials": [],
                "message": (f"Re-run with a file, e.g.:\n"
                            f"  cyberswarm attack {target} --cookies-file session.txt\n"
                            f"  cyberswarm attack {target} --creds-file creds.json --identity A")}
    if choice == "5":
        return {"action": "abort", "cookies": {}, "credentials": [],
                "message": "aborted by operator"}
    return _anon("continuing anonymously (pre-login surface only)")
