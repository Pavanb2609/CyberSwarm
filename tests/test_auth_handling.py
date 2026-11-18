"""auth_handling: detect a login, and report whether the authenticated surface
is being tested given what the operator supplied."""

import json
from pathlib import Path

import auth_handling as a
from context import EngagementContext

ROOT = Path(__file__).resolve().parent.parent


def _map_with_login(password_form=True, mechanisms=("form",), url="https://t/login"):
    # Include some anonymous surface so this is a normal login, not a login wall
    # (wall behaviour has its own tests below).
    return {"target": "t", "auth_paths": [url],
            "endpoints": ["https://t/search?q=x", "https://t/products?id=1",
                          "https://t/about", "https://t/help"],
            "auth_flows": {"auth_results": [
                {"url": url, "login_form": password_form,
                 "has_password_field": password_form, "mechanisms": list(mechanisms)}]}}


def test_no_login_surface():
    st = a.auth_status({"target": "t", "auth_paths": [], "auth_flows": {}}, None, target="t")
    assert st["mode"] == "anonymous_no_login"
    assert st["guidance"] == ""
    assert "No login" in st["headline"]


def test_login_detected_without_credentials_gives_guidance():
    st = a.auth_status(_map_with_login(), None, target="shop.example")
    assert st["mode"] == "login_detected_no_creds"
    assert "NOT be tested" in st["headline"]
    assert "--cookies-file" in st["guidance"] and "--creds-file" in st["guidance"]
    assert st["auth_gated_owasp"] == ["A01", "A07"]


def test_oauth_login_without_password_form_still_detected():
    # OAuth / SSO logins have no password field on the first page; they are
    # still logins and must be detected.
    smap = _map_with_login(password_form=False, mechanisms=("oauth",),
                           url="https://t/login")
    st = a.auth_status(smap, None, target="t")
    assert st["login"]["login_detected"] is True
    assert st["mode"] == "login_detected_no_creds"


def test_cookies_enable_authenticated_mode():
    ctx = EngagementContext(target="t", cookies={"session": "abc"})
    st = a.auth_status(_map_with_login(), ctx, target="t")
    assert st["mode"] == "authenticated"
    assert "authenticated testing is enabled" in st["headline"]
    assert st["guidance"] == ""


def test_credentials_enable_authenticated_mode():
    from context import Credential
    ctx = EngagementContext(target="t",
                            credentials=[Credential(username="u", password="p", identity="A")],
                            identity="A")
    st = a.auth_status(_map_with_login(), ctx, target="t")
    assert st["mode"] == "authenticated"
    assert "A" in st["context"]["labels"]


def test_console_notice_and_report_section_render():
    st = a.auth_status(_map_with_login(), None, target="t")
    notice = a.console_notice(st)
    assert "[auth]" in notice and "login at" in notice
    section = a.render_auth_section(st)
    assert section.startswith("## Authentication")
    assert "not tested" in section.lower()


def test_context_accepts_dict_shape():
    st = a.auth_status(_map_with_login(), {"cookies": {"s": "1"}, "credentials": [],
                                           "identity": "anonymous"}, target="t")
    assert st["mode"] == "authenticated"


def test_real_wolt_map_detects_oauth_login():
    p = ROOT / "results" / "system_map" / "wolt.com.json"
    if not p.exists():
        return
    st = a.auth_status(json.loads(p.read_text()), None, target="wolt.com")
    assert st["login"]["login_detected"] is True
    assert any("login" in u for u in st["login"]["login_urls"])
    assert st["mode"] == "login_detected_no_creds"


# ── login-wall detection + interactive resolver ─────────────────────────────

def _wall_map():
    return {"target": "portal", "auth_paths": ["https://portal/login"],
            "endpoints": [], "parameters": [], "sensitive_endpoints": [],
            "auth_flows": {"auth_results": [
                {"url": "https://portal/login", "has_password_field": True,
                 "mechanisms": ["form"]}]}}


def test_login_wall_detected_when_anon_surface_tiny():
    st = a.auth_status(_wall_map(), None, target="portal")
    assert st["login"]["login_wall"] is True
    assert st["login"]["anon_surface"] == 0
    assert "LOGIN WALL" in st["headline"]


def test_not_a_wall_when_anonymous_surface_exists():
    m = _wall_map()
    m["endpoints"] = ["https://portal/search?q=x", "https://portal/products?id=1",
                      "https://portal/about", "https://portal/contact"]
    st = a.auth_status(m, None, target="portal")
    assert st["login"]["login_wall"] is False


def test_interactive_enter_username_password():
    st = a.auth_status(_wall_map(), None, target="portal")
    feed = iter(["1", "alice", "A", ""])  # choice, username, identity, login-url
    r = a.interactive_resolve(st, "portal", input_fn=lambda *_: next(feed),
                              getpass_fn=lambda *_: "Passw0rd!", is_tty=True)
    assert r["action"] == "authenticated"
    assert r["credentials"] == [{"username": "alice", "password": "Passw0rd!",
                                 "identity": "A"}]
    assert r["identity"] == "A"


def test_interactive_username_password_incomplete_falls_back():
    st = a.auth_status(_wall_map(), None, target="portal")
    feed = iter(["1", "bob", "B", ""])
    r = a.interactive_resolve(st, "portal", input_fn=lambda *_: next(feed),
                              getpass_fn=lambda *_: "", is_tty=True)  # blank password
    assert r["action"] == "continue_anonymous"


def test_interactive_paste_cookie_enables_auth():
    st = a.auth_status(_wall_map(), None, target="portal")
    feed = iter(["2", "Cookie: sid=abc; csrf=xyz"])
    r = a.interactive_resolve(st, "portal", input_fn=lambda *_: next(feed), is_tty=True)
    assert r["action"] == "authenticated"
    assert r["cookies"] == {"sid": "abc", "csrf": "xyz"}


def test_interactive_default_is_continue_anonymous():
    st = a.auth_status(_wall_map(), None, target="portal")
    r = a.interactive_resolve(st, "portal", input_fn=lambda *_: "", is_tty=True)
    assert r["action"] == "continue_anonymous"


def test_interactive_file_option_aborts_with_instructions():
    st = a.auth_status(_wall_map(), None, target="portal")
    r = a.interactive_resolve(st, "portal", input_fn=lambda *_: "3", is_tty=True)
    assert r["action"] == "abort" and "--cookies-file" in r["message"]


def test_interactive_never_blocks_non_tty_or_auto():
    st = a.auth_status(_wall_map(), None, target="portal")

    def boom(*_):
        raise AssertionError("must not prompt")
    assert a.interactive_resolve(st, "portal", input_fn=boom, is_tty=False)["action"] == "proceed"
    assert a.interactive_resolve(st, "portal", input_fn=boom, is_tty=True, auto=True)["action"] == "proceed"


def test_interactive_proceeds_when_no_login():
    st = a.auth_status({"target": "t", "auth_paths": [], "auth_flows": {}}, None, target="t")
    r = a.interactive_resolve(st, "t", input_fn=lambda *_: "1", is_tty=True)
    assert r["action"] == "proceed"


def test_parse_cookie_line_variants():
    assert a.parse_cookie_line("Cookie: a=1; b=2") == {"a": "1", "b": "2"}
    assert a.parse_cookie_line("a=1; b=2; junk") == {"a": "1", "b": "2"}
    assert a.parse_cookie_line("") == {}


# ── prelaunch (ask before recon) ────────────────────────────────────────────

def test_prelaunch_collects_credentials_up_front():
    feed = iter(["1", "alice", "A", ""])
    r = a.prelaunch_auth("shop.example", input_fn=lambda *_: next(feed),
                         getpass_fn=lambda *_: "Passw0rd!", is_tty=True)
    assert r["action"] == "authenticated"
    assert r["credentials"][0]["username"] == "alice"


def test_prelaunch_collects_cookie_up_front():
    feed = iter(["2", "Cookie: sid=1"])
    r = a.prelaunch_auth("x", input_fn=lambda *_: next(feed), is_tty=True)
    assert r["action"] == "authenticated" and r["cookies"] == {"sid": "1"}


def test_prelaunch_continue_option_proceeds():
    r = a.prelaunch_auth("x", input_fn=lambda *_: "3", is_tty=True)
    assert r["action"] == "proceed"


def test_prelaunch_default_proceeds():
    r = a.prelaunch_auth("x", input_fn=lambda *_: "", is_tty=True)
    assert r["action"] == "proceed"


def test_prelaunch_never_blocks_non_interactive():
    def boom(*_):
        raise AssertionError("must not prompt")
    assert a.prelaunch_auth("x", input_fn=boom, is_tty=False)["action"] == "proceed"
    assert a.prelaunch_auth("x", input_fn=boom, is_tty=True, auto=True)["action"] == "proceed"


def test_prelaunch_incomplete_creds_proceeds_not_blocks():
    feed = iter(["1", "", "", ""])  # blank username
    r = a.prelaunch_auth("x", input_fn=lambda *_: next(feed),
                         getpass_fn=lambda *_: "", is_tty=True)
    assert r["action"] == "proceed"
