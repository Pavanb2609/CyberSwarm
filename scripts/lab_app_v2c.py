"""
scripts/lab_app_v2c.py — hardened control for the scanner benchmark (v2c).

Twelve endpoints, one mirroring each lab-v2 vulnerable instance, each with the
sink hardened (this is the "12 hardened control endpoints" set):

  /greet2 /comment2 /welcome2       XSS  -> output escaped (markupsafe.escape)
  /search2 /lookup2 /filter2        SQLi -> parameterized / validated
  /calc2 /render2 /preview2         SSTI -> input passed as a template VALUE
  /page2 /download2 /include2       LFI  -> fixed whitelist, no filesystem

The attack surface is identical to lab v2 (same paths+params, same response
shapes) so scanners cannot distinguish the two apps by surface alone. Loopback
only.
"""

from flask import Flask, request
from markupsafe import escape

control_app = Flask("lab_v2c_control")

_ALLOWED_FILES = {
    "readme": "lab v2c readme file: nothing else is served from here.",
    "terms": "terms of service placeholder.",
    "contact": "contact page placeholder.",
}


@control_app.route("/")
def index():
    paths = [("greet2", "name"), ("comment2", "author"), ("welcome2", "user"),
             ("search2", "q"), ("lookup2", "id"), ("filter2", "category"),
             ("calc2", "expr"), ("render2", "tpl"), ("preview2", "body"),
             ("page2", "file"), ("download2", "file"), ("include2", "tpl")]
    links = "".join(
        f"<li><a href='/{p}?{param}=x'>/{p}</a></li>" for p, param in paths)
    return f"<html><body><h1>Static site</h1><ul>{links}</ul></body></html>"


# -- XSS instances hardened: every reflection escaped ------------------------

@control_app.route("/greet2")
def greet2():
    name = request.args.get("name", "world")
    return f"<html><body>Hello, {escape(name)}!</body></html>"


@control_app.route("/comment2")
def comment2():
    author = request.args.get("author", "anon")
    return f"<html><body><b>Posted by {escape(author)}</b></body></html>"


@control_app.route("/welcome2")
def welcome2():
    user = request.args.get("user", "guest")
    return f"<html><body><h1>Welcome, {escape(user)}</h1></body></html>"


# -- SQLi instances hardened: validation + parameterized storage -------------

@control_app.route("/search2")
def search2():
    request.args.get("q", "")
    return "<html><body>3 results</body></html>"


@control_app.route("/lookup2")
def lookup2():
    uid = request.args.get("id", "1")
    if not uid.isdigit():
        return "<html><body>bad id</body></html>", 400
    return "<html><body>user found</body></html>"


@control_app.route("/filter2")
def filter2():
    request.args.get("category", "")
    return "<html><body>no rows</body></html>"


# -- SSTI instances hardened: input is a VALUE, never the template -----------

def _safe_render(param_name, default=""):
    value = request.args.get(param_name, default)
    from flask import render_template_string
    return render_template_string("Result: {{ value }}", value=value)


@control_app.route("/calc2")
def calc2():
    return _safe_render("expr")


@control_app.route("/render2")
def render2():
    return _safe_render("tpl")


@control_app.route("/preview2")
def preview2():
    return _safe_render("body")


# -- LFI instances hardened: fixed whitelist, no filesystem access -----------

def _served_file(param_name):
    key = request.args.get(param_name, "readme")
    text = _ALLOWED_FILES.get(key)
    if text is None:
        return "<html><body>not found</body></html>", 404
    return f"<html><body><pre>{text}</pre></body></html>"


@control_app.route("/page2")
def page2():
    return _served_file("file")


@control_app.route("/download2")
def download2():
    return _served_file("file")


@control_app.route("/include2")
def include2():
    return _served_file("tpl")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5012
    control_app.run(host="127.0.0.1", port=port)
