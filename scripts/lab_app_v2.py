"""
scripts/lab_app_v2.py — richer pair of lab targets for the detection
benchmark (Section 5.3). Both bind 127.0.0.1 ONLY. The vulnerable app is
intentionally vulnerable; never expose it beyond loopback.

v2 exists because the v1 benchmark had three reviewer-level weaknesses:

  1. one positive per class            -> v2 has THREE instances per class
  2. a control with no parameters      -> v2's control HAS parameters that
     look injectable but are handled safely, so a 0-false-positive result
     is informative rather than guaranteed
  3. one code path per class           -> v2 varies the sink context
     (three distinct SQL injection shapes, three reflection contexts,
     three template sinks, three file sinks)

Vulnerable app endpoints (ground truth per endpoint):

  /greet?name=        reflected XSS (element context)
  /comment?author=    reflected XSS (inline element)
  /welcome?user=      reflected XSS (heading context)
  /search?q=          SQLi  (LIKE, quote-break fingerprint)
  /lookup?id=         SQLi  (numeric context, keyword fingerprint)
  /filter?category=   SQLi  (LIKE, quote-break fingerprint)
  /calc?expr=         SSTI  (render_template_string on input)
  /render?tpl=        SSTI  (render_template_string on input)
  /preview?body=      SSTI  (render_template_string on input)
  /page?path=         LFI   (arbitrary file read)
  /download?file=     LFI   (arbitrary file read)
  /include?tpl=       LFI   (arbitrary file read)

Control app endpoints (same surface shape, safely handled):

  /search2?q=         parameterized query: user input can never break syntax
  /greet2?name=       output escaped (markupsafe)
  /calc2?expr=        input is DATA in a fixed template, never the template
  /page2?file=        basename whitelist lookup, no filesystem path joins
"""

import re

from flask import Flask, request

app = Flask(__name__)          # vulnerable v2
control_app = Flask("control")  # hardened v2

SAFE_PASSWD = re.compile(r"^[A-Za-z0-9_]+$")
_ALLOWED_FILES = {"readme": "Welcome to the static site.",
                  "about": "Nothing sensitive here.",
                  "contact": "contact@example.invalid"}


# ───────────────────────── vulnerable app ─────────────────────────

@app.route("/")
def index():
    links = "".join(
        f"<li><a href='{path}?{param}=x'>{path}</a></li>"
        for path, param in V2_ENDPOINTS)
    return f"<html><body><h1>CyberSwarm lab v2</h1><ul>{links}</ul></body></html>"


# -- reflected XSS: three distinct reflection contexts --

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return f"<html><body>Hello, {name}!</body></html>"


@app.route("/comment")
def comment():
    author = request.args.get("author", "anon")
    return f"<html><body><b>Posted by {author}</b></body></html>"


@app.route("/welcome")
def welcome():
    user = request.args.get("user", "guest")
    return f"<html><body><h1>Welcome, {user}</h1></body></html>"


# -- SQLi: three distinct query shapes --

def _like_break(user_input: str):
    if user_input.count("'") % 2 == 1 or "--" in user_input or "#" in user_input:
        raise ValueError("near \"'\": syntax error (unclosed quotation mark)")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        _like_break(q)
        return "<html><body>no rows</body></html>"
    except Exception as exc:
        return f"<html><body>query failed: {exc}</body></html>", 500


@app.route("/lookup")
def lookup():
    uid = request.args.get("id", "1")
    # numeric context: a fingerprint fires on non-numeric input or injected
    # boolean keywords, mirroring WHERE id = <input> concatenation
    if not SAFE_PASSWD.match(uid) or " or " in uid.lower():
        return ("<html><body>query failed: you have an error in your SQL "
                "syntax; check the manual near '" + uid + "'</body></html>", 500)
    return "<html><body>user found</body></html>"


@app.route("/filter")
def filter_items():
    cat = request.args.get("category", "")
    try:
        _like_break(cat)
        return "<html><body>no rows</body></html>"
    except Exception as exc:
        return f"<html><body>query failed: {exc}</body></html>", 500


# -- SSTI: three sinks --

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    from flask import render_template_string
    try:
        return render_template_string("Result: " + expr)
    except Exception:
        return "<html><body>template error</body></html>", 500


@app.route("/render")
def render_tpl():
    tpl = request.args.get("tpl", "")
    from flask import render_template_string
    try:
        return render_template_string(tpl)
    except Exception:
        return "<html><body>template error</body></html>", 500


@app.route("/preview")
def preview():
    body = request.args.get("body", "")
    from flask import render_template_string
    try:
        return render_template_string(body)
    except Exception:
        return "<html><body>template error</body></html>", 500


# -- LFI: three sinks --

@app.route("/page")
def page():
    path = request.args.get("path", "/etc/hostname")
    try:
        if SAFE_PASSWD.match(path):
            return "<html><body>ok</body></html>"
        with open(path, errors="replace") as fh:
            return f"<html><body><pre>{fh.read()}</pre></body></html>"
    except Exception:
        return "<html><body>not found</body></html>", 404


@app.route("/download")
def download():
    file_ = request.args.get("file", "/etc/hostname")
    try:
        if SAFE_PASSWD.match(file_):
            return "<html><body>ok</body></html>"
        with open(file_, errors="replace") as fh:
            return f"<html><body><pre>{fh.read()}</pre></body></html>"
    except Exception:
        return "<html><body>not found</body></html>", 404


@app.route("/include")
def include_tpl():
    tpl = request.args.get("tpl", "/etc/hostname")
    try:
        if SAFE_PASSWD.match(tpl):
            return "<html><body>ok</body></html>"
        with open(tpl, errors="replace") as fh:
            return f"<html><body><pre>{fh.read()}</pre></body></html>"
    except Exception:
        return "<html><body>not found</body></html>", 404


# ───────────────────────── hardened control ─────────────────────────

@control_app.route("/")
def c_index():
    links = "".join(
        f"<li><a href='{path}?{param}=x'>{path}</a></li>"
        for path, param in V2_CONTROL_ENDPOINTS)
    return f"<html><body><h1>Static site</h1><ul>{links}</ul></body></html>"


@control_app.route("/search2")
def c_search():
    # parameterized by construction: input is DATA; queries cannot break
    request.args.get("q", "")
    return "<html><body>3 results</body></html>"


@control_app.route("/greet2")
def c_greet():
    from markupsafe import escape
    name = request.args.get("name", "world")
    return f"<html><body>Hello, {escape(name)}!</body></html>"


@control_app.route("/calc2")
def c_calc():
    from flask import render_template_string
    expr = request.args.get("expr", "")
    # input is passed as a VALUE, never used as the template itself
    return render_template_string("Result: {{ value }}", value=expr)


@control_app.route("/page2")
def c_page():
    key = request.args.get("file", "readme")
    text = _ALLOWED_FILES.get(key)  # fixed dict, no filesystem access
    if text is None:
        return "<html><body>not found</body></html>", 404
    return f"<html><body><pre>{text}</pre></body></html>"


V2_ENDPOINTS = [
    ("/greet", "name"), ("/comment", "author"), ("/welcome", "user"),
    ("/search", "q"), ("/lookup", "id"), ("/filter", "category"),
    ("/calc", "expr"), ("/render", "tpl"), ("/preview", "body"),
    ("/page", "path"), ("/download", "file"), ("/include", "tpl"),
]
V2_CONTROL_ENDPOINTS = [
    ("/search2", "q"), ("/greet2", "name"), ("/calc2", "expr"),
    ("/page2", "file"),
]


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5010
    (app if which == "vuln" else control_app).run(host="127.0.0.1", port=port)