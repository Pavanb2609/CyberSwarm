"""
scripts/lab_app_v3.py — lab v3: v1's endpoint surface with a REAL SQLite
backend, so SQLi is confirmable end-to-end.

Why v3 exists: the v1 /search endpoint simulated SQL (it only ever raised a
fixed syntax error on user input), so no row-conditional evidence could ever
exist on it — the critic could not confirm sqli on this test bed no matter
what the pipeline did (5.5/5.6). v3 keeps v1's four endpoints and behaviour
for xss/ssti/lfi, and replaces the /search simulation with a real sqlite3
in-memory database. Row-conditional responses are now real:

  ?q=test                -> rows whose name LIKE '%test%'  (or none)
  ?q=' OR 1=1 --         -> every row (boolean-differential)
  ?q=' UNION SELECT ...  -> union results
  ?q='                   -> genuine sqlite3.OperationalError message

The hardened control (control_app) exposes the identical surface and the same
database, but builds every query with bound parameters — a differential
control in the spirit of lab v2.

Self-contained and loopback-only. Never expose beyond 127.0.0.1.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
control_app = Flask(__name__)


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?,?)",
        [(1, "alice", "alice@lab.local", "admin"),
         (2, "bob", "bob@lab.local", "user"),
         (3, "charlie", "charlie@lab.local", "user"),
         (4, "dave", "dave@lab.local", "auditor"),
         (5, "eve", "eve@lab.local", "user")])
    conn.commit()
    return conn


def _rows_html(rows):
    if not rows:
        return "<html><body>no rows</body></html>"
    lis = "".join(f"<li>{r[0]}: {r[1]} &lt;{r[2]}&gt; ({r[3]})</li>" for r in rows)
    return f"<html><body><h2>Users</h2><ul>{lis}</ul></body></html>"


def _index(title):
    return (
        f"<html><body><h1>{title}</h1>"
        "<ul>"
        "<li><a href='/greet?name=world'>greet</a></li>"
        "<li><a href='/search?q=test'>search</a></li>"
        "<li><a href='/calc?expr=1'>calc</a></li>"
        "<li><a href='/page?path=/etc/hostname'>page</a></li>"
        "</ul></body></html>"
    )


def _register(surface, hardened: bool = False):
    """Register the shared surface on a lab app.

    hardened=False (vulnerable app): greet reflects unescaped, calc renders
    user input through the template engine, page opens any path.

    hardened=True (control, fixed 2026-11-14): the ORIGINAL control reused
    the same implementations for every endpoint and only hardened /search —
    so the "hardened mirror" was genuinely vulnerable to XSS (calc/greet)
    and path traversal (page), and the e2e v3 runs confirmed HIGH-severity
    findings on it in every repeat. The control now escapes reflected input,
    renders no template engine over user input, and allowlists file reads.
    """
    @surface.route("/")
    def index():
        return _index(surface.name)

    @surface.route("/greet")
    def greet():
        name = request.args.get("name", "world")
        if hardened:
            from markupsafe import escape
            name = escape(name)
        return f"<html><body>Hello, {name}!</body></html>"

    @surface.route("/calc")
    def calc():
        expr = request.args.get("expr", "")
        if hardened:
            from markupsafe import escape
            return "<html><body>Result: " + escape(expr) + "</body></html>"
        from flask import render_template_string
        try:
            return render_template_string("Result: " + expr)
        except Exception:
            return "<html><body>template error</body></html>", 500

    @surface.route("/page")
    def page():
        import posixpath
        path = request.args.get("path", "/etc/hostname")
        if hardened:
            allowed = {"hostname": "localhost\n"}
            base = posixpath.basename(path or "")
            if base in allowed:
                return ("<html><body><pre>" + allowed[base]
                        + "</pre></body></html>")
            return "<html><body>not found</body></html>", 404
        try:
            import re
            if re.match(r"^[A-Za-z0-9_]+$", path):
                return "<html><body>ok</body></html>"
            with open(path, errors="replace") as fh:
                data = fh.read()
            return f"<html><body><pre>{data}</pre></body></html>"
        except Exception:
            return "<html><body>not found</body></html>", 404


def _search_vulnerable(q):
    """Deliberately concatenated SQL against a real database."""
    conn = _db()
    try:
        sql = "SELECT id, name, email, role FROM users WHERE name LIKE '%" + q + "%'"
        rows = conn.execute(sql).fetchall()
        return _rows_html(rows)
    except Exception as exc:
        return f"<html><body>query failed: {exc}</body></html>", 500
    finally:
        conn.close()


def _search_hardened(q):
    """Same database, bound parameters — no injection possible."""
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT id, name, email, role FROM users WHERE name LIKE ?",
            (f"%{q}%",)).fetchall()
        return _rows_html(rows)
    finally:
        conn.close()


@app.route("/search")
def search():
    return _search_vulnerable(request.args.get("q", ""))


@control_app.route("/search")
def search_control():
    return _search_hardened(request.args.get("q", ""))


_register(app)
_register(control_app, hardened=True)


@app.errorhandler(Exception)
def _unhandled(exc):
    return "<html><body>internal error</body></html>", 500


@control_app.errorhandler(Exception)
def _unhandled_control(exc):
    return "<html><body>internal error</body></html>", 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5009)
