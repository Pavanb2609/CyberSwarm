"""
payload_probe.py — deliver generated payloads and record continuous proof.

For every payload this sends against one parameter the tool records an
XSStrike-style proof entry: the exact payload, the full HTTP request that
carried it, and the response that came back, plus whether it matched a
detection criterion (marker reflection, SQL error, SSTI truth value, ...).

Nothing runs a payload in a browser — execution proof is the xss_proof tool's
job. This is the request/response layer: it tells you what the application
*echoed back*, which is the substrate every later verdict is built on.

Output: ToolResult.results = {
    "proofs": [ {payload, category, matched, match_criteria,
                 request: {method,url,headers,body}, response: {status,headers,body}} ],
    "hits": n, "url": url, "param": param, "probed": n
}
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from tools.base import Tool, ToolResult
# Reuse the ONE canonical SQL-error fingerprint so the probe and the verdict
# helpers can never drift apart again. The probe's private copy had drifted
# narrower (no "unclosed quotation", only empty quotes in the
# "near ...: syntax error" form), so it missed common SQLite / Postgres error
# strings and under-reported SQL injection.
from tools.attack.verdict import SQL_ERROR_MARKER as _SQL_ERROR_MARKER

DEFAULT_TIMEOUT_S = 8
MAX_HEADERS = 10
# A payload that isn't sleep/waitfor-style shouldn't get credited for a slow
# response — ordinary server jitter across dozens of requests is not blind
# injection. Only payloads that actually ask the backend to delay get this
# check at all, and only a delay at least this large counts.
BLIND_DELAY_THRESHOLD_S = 4.0
# Headers that vary on every request regardless of any payload — seeing a
# NEW header appear vs baseline is the CRLF signal, but these two are noise.
_VOLATILE_HEADERS = {"date", "content-length"}

# Detection markers. Every marker must be a *server* fingerprint, never a
# string the payload itself would echo back unchanged (that is how echoes turn
# into false positives). The LFI marker therefore requires real passwd-style
# entries (``name:x:uid:gid:``), not the literal path text.
_PROOF_MARKER = re.compile(r"__cyberswarm_proof", re.IGNORECASE)
_SQL_ERROR = re.compile(_SQL_ERROR_MARKER, re.IGNORECASE)
_SSTI_TRUTH = re.compile(r"\b49\b")

# No line-start anchor: a real leak is almost always wrapped in surrounding
# markup (<pre>root:x:0:0:...</pre>, JSON, XML), so "root:x:0:0:" is rarely
# at true line-start. Requiring a "/"-prefixed homedir field after the
# gid/gecos fields is what rejects a bare "name:x:0:0:" colon-fragment that
# isn't really passwd output — a real entry always has one.
_PASSWD_ENTRIES = re.compile(r"\b[A-Za-z0-9_.-]+:x:[0-9]+:[0-9]+:[^:\n]*:/[^:\n]*:")
_INJECTED_HEADER = re.compile(r"X-Injected", re.IGNORECASE)

# "whoami"/"id enabled" were removed: both are literal substrings of the
# payload's OWN vector text ("&whoami" is a real cmdi vector), so a target
# that merely echoes its input back — vulnerable or not — always contains
# them. That is an echo, not command output. uid=<n>( is real `id` output
# that a payload never contains verbatim, so it stays a safe fingerprint.
_CMD_EXEC = re.compile(r"uid=\d+\(", re.IGNORECASE)


def _ssti_truth(resp_text: str, payload: str, category: str) -> bool:
    return (category == "ssti" or "{{" in payload or "${{" in payload) \
        and bool(_SSTI_TRUTH.search(resp_text))


def _unknown_classify(resp_text: str) -> tuple:
    """Fingerprints checked for payloads with no specific category."""
    if _SQL_ERROR.search(resp_text):
        return True, "SQL error string in response"
    if _PASSWD_ENTRIES.search(resp_text):
        return True, "etc/passwd content leaked (passwd-style entries)"
    if _INJECTED_HEADER.search(resp_text):
        return True, "injected header present"
    if _CMD_EXEC.search(resp_text):
        return True, "command execution marker"
    return False, ""


def _time_based_blind(ctx: Dict[str, Any], payload: str) -> bool:
    """A payload asked the backend to sleep, and the response actually took
    that much longer than the same request with a benign value. Guarded on
    the payload text itself so ordinary latency jitter across a 40-payload
    sweep never gets mistaken for blind injection."""
    if not any(m in payload.lower() for m in ("sleep", "waitfor", "benchmark(")):
        return False
    elapsed = ctx.get("elapsed")
    baseline_elapsed = ctx.get("baseline_elapsed")
    if elapsed is None or baseline_elapsed is None:
        return False
    return (elapsed - baseline_elapsed) >= BLIND_DELAY_THRESHOLD_S


def _extract_payload_host(payload: str) -> str:
    """Best-effort host extraction from an open-redirect vector: '//host',
    'https://host/...', '\\\\host', '@host', or a bare host string."""
    p = payload.strip()
    if p.startswith("//"):
        return urlparse("http:" + p).netloc.lower()
    if "://" in p:
        return urlparse(p).netloc.lower()
    return p.lstrip("\\@/").split("/")[0].lower()


def _fire(resp_text: str, category: str, payload: str,
          ctx: Optional[Dict[str, Any]] = None) -> tuple:
    """(matched, criterion) — the raw fingerprint check, with no
    body-text-baseline awareness (header/timing categories do their own
    baseline comparison inline, against ctx, since their signal never lives
    in the body at all). The payload's OWN class is checked first so a
    cross-category server fingerprint cannot steal its verdict (e.g. an SSTI
    payload that also trips the SQL-error handler stays an SSTI result only
    when its truth marker fired; otherwise it is reported as SQL error).

    The reflected-proof-marker fingerprint belongs to the XSS class alone and
    additionally requires the *literal, unescaped* payload in the response:
    HTML-escaped output (`&lt;svg/...`) is exactly the case where there is NO
    cross-site scripting, so it must count as a miss."""
    ctx = ctx or {}
    if category == "ssti":
        if _ssti_truth(resp_text, payload, category):
            return True, "numeric truth marker ({{7*7}})"
        if _SQL_ERROR.search(resp_text):
            return True, "SQL error string in response"
        return _unknown_classify(resp_text)
    if category == "sqli":
        if _SQL_ERROR.search(resp_text):
            return True, "SQL error string in response"
        if _time_based_blind(ctx, payload):
            return True, "time-based blind response delay"
        return _unknown_classify(resp_text)
    if category == "lfi":
        if _PASSWD_ENTRIES.search(resp_text):
            return True, "etc/passwd content leaked (passwd-style entries)"
        return _unknown_classify(resp_text)
    if category == "xxe":
        if _PASSWD_ENTRIES.search(resp_text):
            return True, "etc/passwd content leaked (passwd-style entries)"
        return _unknown_classify(resp_text)
    if category == "cmdi":
        if _CMD_EXEC.search(resp_text) or _PASSWD_ENTRIES.search(resp_text) \
                or _ssti_truth(resp_text, payload, category):
            return True, "command execution marker"
        if _time_based_blind(ctx, payload):
            return True, "time-based blind response delay"
        return _unknown_classify(resp_text)
    if category == "crlf":
        # The real signal lives in the response HEADERS, not the body: a
        # header that appears now but wasn't present in the baseline at all
        # (or the legacy literal-echo check, kept for compatibility).
        resp_headers = ctx.get("resp_headers") or {}
        baseline_headers = ctx.get("baseline_headers") or {}
        new_names = ({k.lower() for k in resp_headers}
                     - {k.lower() for k in baseline_headers}
                     - _VOLATILE_HEADERS)
        if new_names or _INJECTED_HEADER.search(resp_text):
            return True, "response header injected (not present in baseline)"
        return _unknown_classify(resp_text)
    if category == "open_redirect":
        status = ctx.get("resp_status")
        resp_headers = ctx.get("resp_headers") or {}
        location = resp_headers.get("Location") or resp_headers.get("location") or ""
        target_host = str(ctx.get("target_host") or "").lower()
        if status in (301, 302, 303, 307, 308) and location:
            loc_host = _extract_payload_host(location) if (
                location.startswith("//") or "://" in location) else ""
            payload_host = _extract_payload_host(payload)
            if loc_host and payload_host and payload_host == loc_host \
                    and loc_host != target_host:
                return True, "redirect Location points to injected off-host target"
        return _unknown_classify(resp_text)
    if category == "xss":
        # The marker must appear together with the literal payload AND the
        # payload must carry a context-breaking delimiter (<, >, ", '). A
        # javascript: URI echoed back verbatim (no delimiters) cannot break
        # out of any attribute, and escaped output (`&lt;svg/...`) never
        # contains the literal payload — both count as misses.
        if payload and _PROOF_MARKER.search(resp_text) and payload in resp_text \
                and any(c in payload for c in "<>\"'"):
            return True, "proof-marker reflected in response"
        return _unknown_classify(resp_text)
    if _PROOF_MARKER.search(resp_text):
        return True, "proof-marker reflected in response"
    return _unknown_classify(resp_text)


def _classify(resp_text: str, category: str, payload: str,
              baseline_text: str = "", ctx: Optional[Dict[str, Any]] = None) -> tuple:
    """(matched, criterion) — ``_fire`` plus a baseline check.

    A body-text fingerprint match only counts if it appears in the PAYLOADED
    response but not in a control response from the same endpoint with no
    payload applied. This is what stops a page that always contains e.g.
    "SQL syntax" boilerplate, or an unrelated "$49" price, from being
    reported as a confirmed finding on every single probe: if the exact same
    criterion already fires with no payload at all, it is a property of the
    page, not evidence of injection, and is suppressed back to a miss.

    crlf/open_redirect skip this second pass — their own baseline comparison
    already happened inside ``_fire`` against ``ctx["baseline_headers"]``,
    since their signal lives in headers, not body text, and re-running the
    body-text diff for them would compare the wrong thing.

    ``baseline_text``/``ctx`` default to ""/None (no baseline available or
    attempted), which reproduces the old, non-differential behavior exactly
    — callers that don't have a baseline still get a sensible result, just
    without the extra safety net."""
    matched, criteria = _fire(resp_text, category, payload, ctx)
    if matched and baseline_text and category not in ("crlf", "open_redirect"):
        baseline_matched, baseline_criteria = _fire(baseline_text, category, payload)
        if baseline_matched and baseline_criteria == criteria:
            return False, ""
    return matched, criteria


class PayloadProbeTool(Tool):
    name = "payload_probe"
    capability = "PAYLOAD_PROBE"
    binary = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config if isinstance(config, dict) else {}

    @staticmethod
    def _http():
        try:
            import requests  # noqa: F401
            return "requests"
        except Exception:  # noqa: BLE001
            return None

    def is_available(self) -> bool:
        return self._http() is not None

    def validate(self) -> Optional[str]:
        return None if self._http() else "requests/urllib unavailable"

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-payload-probe", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 240, **kwargs) -> ToolResult:
        import requests

        url = str(kwargs.get("url") or target)
        param = str(kwargs.get("param") or "")
        payloads = kwargs.get("payloads") or []
        method = str(kwargs.get("method", "get")).upper()
        # "form" (default) = application/x-www-form-urlencoded, one field.
        # "json" = the same one field, delivered as a JSON POST body — most
        # real APIs never expose an injectable field any other way.
        # "xml" = the payload IS the entire body (used for XXE, where the
        # attack is a whole malicious document, not one field's value).
        body_format = str(kwargs.get("body_format", "form")).lower()
        extra_headers = kwargs.get("headers") or {}
        max_probe = int(kwargs.get("max_payloads", 120))
        nonce = kwargs.get("nonce") or ""
        target_host = urlparse(url).netloc

        if not param:
            return ToolResult(tool=self.name, capability=self.capability,
                              status="success", results={
                "proofs": [], "hits": 0, "url": url,
                "param": param, "probed": 0, "error": "no parameter supplied"})

        payloads = payloads[:max_probe]
        proofs: List[Dict[str, Any]] = []
        hits: List[Dict[str, Any]] = []
        timeout_s = float(self._config.get("timeout", DEFAULT_TIMEOUT_S)
                          if isinstance(self._config, dict) else DEFAULT_TIMEOUT_S)

        # One control request per (url, param), reused for every payload
        # below. A benign value that no fingerprint should ever fire on;
        # if the baseline request itself fails, we fail OPEN (empty
        # string/None, i.e. no differential check) rather than dropping the
        # whole probe.
        baseline_text = ""
        baseline_headers: Dict[str, str] = {}
        baseline_elapsed: Optional[float] = None
        try:
            b_parsed = urlparse(url)
            b_headers = {k: str(v) for k, v in (extra_headers or {}).items()}
            if body_format == "xml":
                b_headers.setdefault("Content-Type", "application/xml")
                b_body = "<baseline>cyberswarm_baseline_9182</baseline>"
                b_url = url
            elif method == "POST" and body_format == "json":
                b_headers.setdefault("Content-Type", "application/json")
                b_body = json.dumps({param: "cyberswarm_baseline_9182"})
                b_url = url
            elif method == "POST":
                b_headers.setdefault("Content-Type",
                                     "application/x-www-form-urlencoded")
                b_body = urlencode({param: "cyberswarm_baseline_9182"})
                b_url = url
            else:
                b_query = dict(parse_qsl(b_parsed.query, keep_blank_values=True))
                b_query[param] = "cyberswarm_baseline_9182"
                b_url = urlunparse(b_parsed._replace(
                    query=urlencode(b_query, doseq=True)))
                b_body = None
            b_resp = requests.request(
                "GET" if (method != "POST" and body_format != "xml") else "POST",
                b_url, data=b_body, headers=b_headers, timeout=timeout_s,
                allow_redirects=False, verify=False if "https" in b_url else True)
            baseline_text = b_resp.text or ""
            baseline_headers = dict(b_resp.headers)
            _b_el = getattr(b_resp, "elapsed", None)
            baseline_elapsed = _b_el.total_seconds() if _b_el is not None else None
        except Exception:  # noqa: BLE001
            baseline_text = ""
            baseline_headers = {}
            baseline_elapsed = None

        for item in payloads:
            if isinstance(item, str):
                pl = {"payload": item, "category": "custom"}
            else:
                pl = item
            payload = str(pl.get("payload", ""))
            if not payload:
                continue
            body = None
            headers = {k: str(v) for k, v in (extra_headers or {}).items()}
            req_method = method
            if body_format == "xml":
                # The payload IS the whole document — there is no single
                # field to substitute a value into.
                headers.setdefault("Content-Type", "application/xml")
                body = payload
                req_url = url
                req_method = "POST"
            elif method == "POST" and body_format == "json":
                headers.setdefault("Content-Type", "application/json")
                body = json.dumps({param: payload})
                req_url = url
            elif method == "POST":
                headers.setdefault("Content-Type",
                                   "application/x-www-form-urlencoded")
                body = urlencode({param: payload})
                req_url = url
            else:
                parsed = urlparse(url)
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                query[param] = payload
                req_url = urlunparse(parsed._replace(
                    query=urlencode(query, doseq=True)))
            req_hdrs = dict(headers)
            try:
                resp = requests.request(
                    req_method, req_url, data=body, headers=headers,
                    timeout=timeout_s, allow_redirects=False,
                    verify=False if "https" in req_url else True)
                resp_text = resp.text or ""
            except Exception as e:  # noqa: BLE001
                proofs.append({"payload": payload, "category": pl.get("category"),
                               "matched": False,
                               "match_criteria": f"request failed: {e}",
                               "request": {"method": req_method, "url": req_url,
                                           "headers": req_hdrs,
                                           "body": body or ""},
                               "response": {"status": 0, "headers": {},
                                            "body": ""}})
                continue

            _el = getattr(resp, "elapsed", None)
            ctx = {
                "resp_headers": dict(resp.headers),
                "resp_status": resp.status_code,
                "target_host": target_host,
                "baseline_headers": baseline_headers,
                "elapsed": _el.total_seconds() if _el is not None else None,
                "baseline_elapsed": baseline_elapsed,
            }
            matched, criteria = _classify(resp_text, str(pl.get("category") or ""),
                                          payload, baseline_text, ctx)

            proof = {
                "payload": payload,
                "category": pl.get("category"),
                "matched": matched,
                "match_criteria": criteria,
                "request": {
                    "method": req_method,
                    "url": req_url,
                    "headers": req_hdrs,
                    "body": body or "",
                },
                "response": {
                    "status": resp.status_code,
                    "headers": dict(list(resp.headers.items())[:MAX_HEADERS]),
                    "body": resp_text[:1500],
                },
            }
            proofs.append(proof)
            if matched:
                hits.append(proof)

        return ToolResult(tool=self.name, capability=self.capability,
                            status="success", results={
            "proofs": proofs,
            "hits": len(hits),
            "url": url,
            "param": param,
            "probed": len(proofs),
            "hit_details": hits[:20],
        }, raw_stdout=(
            f"payload_probe: {len(proofs)} sent, {len(hits)} matched "
            f"on {param} @ {url}"))