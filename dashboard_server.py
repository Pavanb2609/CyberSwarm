"""
dashboard_server.py — read-only, stdlib-only HTTP server for the
CyberSwarm real-time dashboard (spec §20).

    GET /                              the dashboard page (embedded HTML/CSS/JS)
    GET /cyberswarm/targets            {"targets": [...]}
    GET /cyberswarm/state/<target>     dashboard_data.build_snapshot(target)

Deliberately stdlib-only (http.server -- no Flask/FastAPI dependency) and
strictly read-only: no route here ever writes to a store, runs a tool, or
calls a model, so it can never interfere with an in-progress assessment.
The page polls /cyberswarm/state every few seconds client-side for a "live"
feel without needing WebSockets or a new dependency, and every asset/log
panel loads from local disk only -- no CDN calls, consistent with the
project being usable fully offline.

Route naming note: the API is under /cyberswarm/... rather than the more
obvious /api/... on purpose. A bare /api/ prefix collides with the
control-plane routes some remote dev environments (Codespaces-style
containers, notebook proxies, tunnelling tools) reserve for themselves,
which silently swallows requests before they ever reach this server --
symptom: the page itself loads fine (that request goes through the
proxy's default passthrough) but every /api/* fetch just hangs with no
response and no error. If you're still seeing that after this rename,
it's almost certainly the --host binding instead -- see run() below.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import dashboard_data

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberSwarm Dashboard</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #121821; --border: #22303f; --text: #d7e2ea;
    --muted: #7d93a3; --accent: #4fd1c5; --warn: #f0b73a; --bad: #f0554f;
    --good: #58d68d; --mono: "SF Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, Segoe UI, Roboto, sans-serif; font-size: 14px;
  }
  header {
    display: flex; align-items: center; gap: 16px; padding: 14px 20px;
    border-bottom: 1px solid var(--border); position: sticky; top: 0;
    background: var(--bg); z-index: 5; flex-wrap: wrap;
  }
  header h1 { font-size: 16px; margin: 0; letter-spacing: .02em; }
  header h1 span { color: var(--accent); }
  select, button {
    background: var(--panel); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 10px; font-size: 13px;
  }
  button:hover { border-color: var(--accent); cursor: pointer; }
  #status { margin-left: auto; color: var(--muted); font-family: var(--mono); font-size: 12px; }
  #status.live { color: var(--good); }
  #status.err { color: var(--bad); }
  main { padding: 18px; display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; }
  .panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px; min-height: 80px;
  }
  .panel h2 {
    font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted);
    margin: 0 0 10px 0; display: flex; justify-content: space-between; align-items: center;
  }
  .panel h2 .count { color: var(--accent); font-family: var(--mono); }
  .panel.wide { grid-column: span 2; }
  .row { display: flex; justify-content: space-between; gap: 8px; padding: 4px 0; border-bottom: 1px dashed var(--border); font-size: 13px; }
  .row:last-child { border-bottom: none; }
  .row .k { color: var(--text); font-family: var(--mono); word-break: break-all; }
  .row .v { color: var(--muted); flex-shrink: 0; white-space: nowrap; }
  .badge { padding: 1px 7px; border-radius: 999px; font-size: 11px; font-family: var(--mono); }
  .badge.success, .badge.CONFIRMED, .badge.HIGH, .badge.active, .badge.ran { background: rgba(88,214,141,.15); color: var(--good); }
  .badge.error, .badge.timeout, .badge.LOW, .badge.idle { background: rgba(240,85,79,.12); color: var(--bad); }
  .badge.not_installed, .badge.unsupported, .badge.MEDIUM { background: rgba(240,183,58,.15); color: var(--warn); }
  .empty { color: var(--muted); font-style: italic; font-size: 13px; }
  .scroll { max-height: 320px; overflow-y: auto; }
  .asset-group summary { cursor: pointer; color: var(--text); font-family: var(--mono); padding: 4px 0; }
  .asset-group summary .n { color: var(--accent); }
  .asset-val { font-size: 12px; color: var(--muted); padding: 2px 0 2px 14px; font-family: var(--mono); word-break: break-all; }
  .gap-chip {
    display: inline-block; background: rgba(240,183,58,.12); color: var(--warn);
    border-radius: 6px; padding: 2px 8px; font-size: 11px; margin: 2px; font-family: var(--mono);
  }
  #placeholder { padding: 60px 20px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
  <header>
    <h1>Cyber<span>Swarm</span> Dashboard</h1>
    <select id="targetSelect"><option value="">Loading targets…</option></select>
    <button id="refreshBtn">Refresh now</button>
    <span id="status">connecting…</span>
  </header>

  <div id="placeholder">No target selected yet — pick one above once a target has a saved state.</div>
  <main id="main" style="display:none"></main>

<script>
const POLL_MS = 4000;
let currentTarget = null;
let pollTimer = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function setStatus(msg, cls) {
  const s = document.getElementById('status');
  s.textContent = msg;
  s.className = cls || '';
}

async function fetchJSON(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 6000);
  try {
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) {
      let detail = '';
      try { detail = (await res.json()).error || ''; } catch (_) {}
      throw new Error('HTTP ' + res.status + (detail ? ': ' + detail : ''));
    }
    return await res.json();
  } catch (e) {
    clearTimeout(timer);
    if (e.name === 'AbortError') {
      throw new Error('timed out after ' + (timeoutMs || 6000) + 'ms — server not responding at ' + url);
    }
    throw new Error(e.message || String(e));
  }
}

async function loadTargets() {
  const sel = document.getElementById('targetSelect');
  try {
    const data = await fetchJSON('/cyberswarm/targets', 6000);
    sel.innerHTML = '';
    if (!data.targets || !data.targets.length) {
      sel.innerHTML = '<option value="">No targets yet</option>';
      setStatus('connected, but no targets have a saved state yet', '');
      return;
    }
    for (const t of data.targets) {
      const opt = el('option'); opt.value = t; opt.textContent = t;
      sel.appendChild(opt);
    }
    if (!currentTarget) selectTarget(data.targets[0]);
  } catch (e) {
    sel.innerHTML = '<option value="">(failed to load)</option>';
    setStatus('cannot reach /cyberswarm/targets — ' + e.message, 'err');
  }
}

function selectTarget(t) {
  currentTarget = t;
  document.getElementById('targetSelect').value = t;
  document.getElementById('placeholder').style.display = 'none';
  document.getElementById('main').style.display = 'grid';
  clearTimeout(pollTimer);
  poll();
}

async function poll() {
  if (!currentTarget) return;
  try {
    const snap = await fetchJSON('/cyberswarm/state/' + encodeURIComponent(currentTarget), 6000);
    render(snap);
    setStatus('live · updated ' + new Date(snap.generated_at).toLocaleTimeString(), 'live');
  } catch (e) {
    setStatus('connection lost — ' + e.message, 'err');
  }
  pollTimer = setTimeout(poll, POLL_MS);
}

function badge(text, cls) {
  const b = el('span', 'badge ' + (cls || text), text);
  return b;
}

function panel(title, countText) {
  const p = el('div', 'panel');
  const h = el('h2');
  h.appendChild(el('span', null, title));
  if (countText !== undefined) h.appendChild(el('span', 'count', countText));
  p.appendChild(h);
  return p;
}

function row(k, vNode) {
  const r = el('div', 'row');
  r.appendChild(el('span', 'k', k));
  const v = el('span', 'v');
  if (typeof vNode === 'string') v.textContent = vNode; else if (vNode) v.appendChild(vNode);
  r.appendChild(v);
  return r;
}

function render(s) {
  const main = document.getElementById('main');
  main.innerHTML = '';

  const overview = panel('Target');
  overview.appendChild(row('hostname', s.target));
  if (s.data_source === 'legacy') {
    overview.appendChild(row('data source', badge('legacy (pre-Controller run)', 'MEDIUM')));
  }
  overview.appendChild(row('risk rating', badge(s.risk_rating || 'UNKNOWN')));
  overview.appendChild(row('state last updated', new Date(s.state_updated).toLocaleString()));
  overview.appendChild(row('evidence items', String(s.evidence_count)));
  overview.appendChild(row('relationships (state graph)', String((s.relationships || []).length)));
  main.appendChild(overview);

  const totalAssets = Object.values(s.asset_counts || {}).reduce((a, b) => a + b, 0);
  const assetsP = panel('Assets', String(totalAssets));
  const types = Object.keys(s.assets || {}).sort();
  if (!types.length) assetsP.appendChild(el('div', 'empty', 'No assets discovered yet.'));
  const scrollA = el('div', 'scroll');
  for (const t of types) {
    const details = el('details', 'asset-group');
    const summary = el('summary');
    summary.appendChild(document.createTextNode(t + ' '));
    summary.appendChild(el('span', 'n', '(' + s.assets[t].length + ')'));
    details.appendChild(summary);
    for (const a of s.assets[t].slice(0, 30)) {
      details.appendChild(el('div', 'asset-val', a.value + '  · conf ' + a.confidence + '  · ' + a.source));
    }
    scrollA.appendChild(details);
  }
  assetsP.appendChild(scrollA);
  main.appendChild(assetsP);

  const agentsP = panel('Agents', String((s.agents || []).length));
  for (const a of (s.agents || [])) {
    agentsP.appendChild(row(a.name + ' — ' + a.role, badge(a.status)));
  }
  main.appendChild(agentsP);

  const actionsP = panel('Actions');
  if (s.current_action) {
    actionsP.appendChild(row('current / most recent',
      badge(s.current_action.action + ' (' + s.current_action.tool + ')', s.current_action.status)));
  }
  actionsP.appendChild(row('completed', String((s.completed_actions || []).length)));
  actionsP.appendChild(row('failed', String((s.failed_actions || []).length)));
  const scrollAct = el('div', 'scroll');
  for (const a of [...(s.failed_actions || [])].reverse().slice(0, 15)) {
    scrollAct.appendChild(row(a.action + ' → ' + a.tool, badge(a.status, a.status)));
  }
  if (!(s.failed_actions || []).length) scrollAct.appendChild(el('div', 'empty', 'No failed actions.'));
  actionsP.appendChild(scrollAct);
  main.appendChild(actionsP);

  const confP = panel('Confidence levels');
  const c = s.confidence || {};
  confP.appendChild(row('average asset confidence', c.average != null ? String(c.average) : '—'));
  for (const label of Object.keys(c.by_label || {})) {
    confP.appendChild(row(label, String(c.by_label[label])));
  }
  if (!c.by_label || !Object.keys(c.by_label).length) confP.appendChild(el('div', 'empty', 'No scored assets yet.'));
  main.appendChild(confP);

  const findP = panel('Findings', String((s.findings || []).length));
  if (!(s.findings || []).length) findP.appendChild(el('div', 'empty', 'No findings recorded yet.'));
  const scrollF = el('div', 'scroll');
  for (const f of (s.findings || [])) {
    const sev = f.cvss_severity || f.severity || 'UNKNOWN';
    const cvssNote = f.cvss_score != null ? ' · CVSS ' + f.cvss_score : '';
    scrollF.appendChild(row((f.title || f.name || 'finding') + cvssNote, badge(sev)));
  }
  findP.appendChild(scrollF);
  main.appendChild(findP);

  const chainsP = panel('Attack chains \u26a0\ufe0f verify', String((s.attack_chains || []).length));
  const scrollCh = el('div', 'scroll');
  for (const c of (s.attack_chains || [])) {
    scrollCh.appendChild(row(c.name + ' — ' + c.host, badge(c.cvss_severity || 'UNKNOWN', c.cvss_severity)));
  }
  if (!(s.attack_chains || []).length) scrollCh.appendChild(el('div', 'empty', 'None detected from current findings.'));
  chainsP.appendChild(scrollCh);
  main.appendChild(chainsP);

  const evP = panel('Evidence (most recent)');
  const scrollE = el('div', 'scroll');
  for (const e of [...(s.evidence_sample || [])].reverse()) {
    scrollE.appendChild(row(e.source_tool + ' → ' + e.capability, badge(e.status, e.status)));
  }
  if (!(s.evidence_sample || []).length) scrollE.appendChild(el('div', 'empty', 'No evidence recorded yet.'));
  evP.appendChild(scrollE);
  main.appendChild(evP);

  const apP = panel('Human approval requests', String((s.approval_history || []).length));
  const scrollAp = el('div', 'scroll');
  for (const a of (s.approval_history || [])) {
    const outcome = a.approved ? (a.override_capability ? 'OVERRIDDEN' : 'APPROVED') : 'REJECTED';
    const label = (a.model_decision && a.model_decision.next_capability) || a.phase;
    scrollAp.appendChild(row('[' + a.phase + '] ' + label, badge(outcome, outcome === 'APPROVED' ? 'success' : (outcome === 'REJECTED' ? 'error' : 'MEDIUM'))));
  }
  if (!(s.approval_history || []).length) scrollAp.appendChild(el('div', 'empty', 'No approval decisions logged yet (or none required so far).'));
  apP.appendChild(scrollAp);
  main.appendChild(apP);

  const dtP = panel('Decision timeline', String((s.decision_timeline || []).length));
  dtP.className += ' wide';
  const scrollDt = el('div', 'scroll');
  (s.decision_timeline || []).forEach((d, i) => {
    scrollDt.appendChild(row('#' + i + '  ' + d.selected_action + (d.selected_tool ? ' → ' + d.selected_tool : ''),
      badge(d.result_status || 'planned', d.result_status || '')));
  });
  if (!(s.decision_timeline || []).length) scrollDt.appendChild(el('div', 'empty', 'No decisions recorded yet.'));
  dtP.appendChild(scrollDt);
  main.appendChild(dtP);

  const gapsP = panel('Open knowledge gaps', String((s.open_knowledge_gaps || []).length));
  if (!(s.open_knowledge_gaps || []).length) {
    gapsP.appendChild(el('div', 'empty', 'None — every tracked capability has been attempted.'));
  } else {
    const wrap = el('div');
    for (const g of s.open_knowledge_gaps) wrap.appendChild(el('span', 'gap-chip', g));
    gapsP.appendChild(wrap);
  }
  main.appendChild(gapsP);

  const smP = panel('System map (legacy `cli.py map`)');
  const sm = s.system_map_summary || {};
  smP.appendChild(row('web surfaces', String(sm.web_surfaces || 0)));
  smP.appendChild(row('technologies', String(sm.technologies || 0)));
  smP.appendChild(row('endpoints', String(sm.endpoints || 0)));
  smP.appendChild(row('links', String(sm.links || 0)));
  if (!sm.web_surfaces && !sm.technologies && !sm.endpoints && !sm.links) {
    smP.appendChild(el('div', 'empty', 'Empty — this target hasn\'t been run through `cyberswarm map` yet (only the newer state-graph relationships above are populated by the assess pipeline).'));
  }
  main.appendChild(smP);

  const trP = panel('Tool reliability', String(Object.keys(s.tool_reliability || {}).length));
  trP.className += ' wide';
  const scrollTr = el('div', 'scroll');
  const entries = Object.entries(s.tool_reliability || {})
    .sort((a, b) => (b[1].attempts || 0) - (a[1].attempts || 0));
  for (const [name, st] of entries) {
    const attempts = st.attempts || 0;
    const rate = attempts ? Math.round((st.successes / attempts) * 100) : null;
    scrollTr.appendChild(row(name + '  (' + attempts + ' runs)', rate == null ? '—' : rate + '% success'));
  }
  if (!entries.length) scrollTr.appendChild(el('div', 'empty', 'No tool executions recorded yet.'));
  trP.appendChild(scrollTr);
  main.appendChild(trP);
}

document.getElementById('targetSelect').addEventListener('change', (e) => selectTarget(e.target.value));
document.getElementById('refreshBtn').addEventListener('click', poll);
loadTargets();
setInterval(loadTargets, 15000);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "CyberSwarmDashboard/0.1"

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # keep CLI/test output quiet; failures still return error JSON

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path

        if path in ("/", "/index.html"):
            self._send_html(DASHBOARD_HTML)
            return

        if path == "/cyberswarm/targets":
            try:
                self._send_json({"targets": dashboard_data.list_targets()})
            except Exception as e:  # noqa: BLE001 - surface as JSON, never let the request hang
                self._send_json({"error": str(e)}, status=500)
            return

        if path.startswith("/cyberswarm/state/"):
            target = unquote(path[len("/cyberswarm/state/"):])
            if not target:
                self._send_json({"error": "missing target"}, status=400)
                return
            try:
                snapshot = dashboard_data.build_snapshot(target)
            except Exception as e:  # noqa: BLE001 - surface any read failure as JSON, not a stack trace
                self._send_json({"error": str(e)}, status=500)
                return
            self._send_json(snapshot)
            return

        self._send_json({"error": "not found"}, status=404)

    def _reject_write(self) -> None:
        # The dashboard is strictly read-only -- it must never be able to
        # trigger a scan, approve a decision, or write state.
        self._send_json({"error": "read-only dashboard: this method is not supported"}, status=405)

    def do_POST(self) -> None:  # noqa: N802
        self._reject_write()

    do_PUT = _reject_write
    do_DELETE = _reject_write
    do_PATCH = _reject_write


def make_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), DashboardHandler)


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    httpd = make_server(host, port)
    url = f"http://{host}:{port}/"
    print(f"[dashboard] serving at {url} (read-only -- Ctrl+C to stop)")
    if host in ("127.0.0.1", "localhost"):
        print("[dashboard] bound to localhost only. If you're viewing this from a browser "
              "on a *different* machine than the one running this process (SSH remote, "
              "container/devcontainer, cloud VM, Codespaces-style environment, etc.), that "
              "browser can't reach 127.0.0.1 on the server -- re-run with --host 0.0.0.0 "
              "(and forward/open the port on that host) instead.")
    if open_browser:
        import webbrowser
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
