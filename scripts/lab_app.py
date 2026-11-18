"""
scripts/lab_app.py — self-contained intentionally-vulnerable Flask app used
for the authorized LOCAL lab (127.0.0.1 only). The system's authorization
gate always allows localhost. Never expose this beyond the loopback
interface: it intentionally reflects unsanitized input, renders Jinja
templates from user input and reads arbitrary files.

Endpoints:
  /              base page
  /greet?name=   reflects `name` UN-escaped  -> reflected XSS test bed
  /search?q=     interpolates `q` into a SQL WHERE and returns the SQL
                 error message verbatim          -> SQLi fingerprint test bed
  /calc?expr=    render_template_string(user input) -> SSTI test bed
  /page?path=    reads `path` as a file path      -> LFI test bed
"""

import re

from flask import Flask, request

app = Flask(__name__)

SAFE_PASSWD = re.compile(r"^[A-Za-z0-9_]+$")


@app.route("/")
def index():
    # A real app exposes its surface through links; a scanner's crawler and
    # parameter-discovery follow them. The earlier version linked nothing, so
    # recon found no endpoints and the attack phase had nothing to test
    # (benchmark read 0% — a discovery gap, not a detection failure).
    return (
        "<html><body><h1>CyberSwarm lab</h1>"
        "<ul>"
        "<li><a href='/greet?name=world'>greet</a></li>"
        "<li><a href='/search?q=test'>search</a></li>"
        "<li><a href='/calc?expr=1'>calc</a></li>"
        "<li><a href='/page?path=/etc/hostname'>page</a></li>"
        "</ul></body></html>"
    )


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return f"<html><body>Hello, {name}!</body></html>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Deliberately vulnerable concatenated SQL. The error fires only when the
    # USER INPUT breaks the quoting (a classic SQLi fingerprint), so a benign
    # baseline request returns rows and only an injected quote/comment errors.
    # (The old version matched 'SELECT' in the static query, so it errored on
    # every request — making the error non-differential and correctly ignored
    # by any scanner that compares against a baseline.)
    try:
        _exec_simulated("SELECT * FROM users WHERE name LIKE '%" + q + "%'", q)
        return "<html><body>no rows</body></html>"
    except Exception as exc:
        return f"<html><body>query failed: {exc}</body></html>", 500


def _exec_simulated(sql, user_input=""):
    # Unbalanced quote or a SQL comment introduced by the user => broken query.
    if user_input.count("'") % 2 == 1 or "--" in user_input or "#" in user_input:
        raise ValueError("near \"'\": syntax error (unclosed quotation mark)")


@app.errorhandler(Exception)
def _unhandled(exc):
    # keep unhandled errors visible WITHOUT leaking them (steer to a static
    # message so only the /search handler above is a genuine fingerprint)
    return "<html><body>internal error</body></html>", 500


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    from flask import render_template_string
    try:
        return render_template_string("Result: " + expr)
    except Exception:
        return "<html><body>template error</body></html>", 500


@app.route("/page")
def page():
    path = request.args.get("path", "/etc/hostname")
    try:
        if SAFE_PASSWD.match(path):
            return "<html><body>ok</body></html>"
        with open(path, errors="replace") as fh:
            data = fh.read()
        return f"<html><body><pre>{data}</pre></body></html>"
    except Exception:
        return "<html><body>not found</body></html>", 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5009)
