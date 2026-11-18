"""
xss_proof.py — prove a reflected XSS actually executes.

Reflection is not execution. `dalfox` and `nuclei` report that a payload came
back in the response, which is necessary but not sufficient: the reflection may
sit inside an attribute that never fires, be escaped by a framework, be blocked
by CSP, or land in a context the browser treats as text. Those are the reports
that waste a tester's afternoon.

This tool loads the candidate URL in a real headless browser and reports XSS
only when the payload's JavaScript *ran* — proven by a callback the page cannot
fake:

  * a `window.__cyberswarm_proof` assignment the payload performs
  * a `dialog` event (alert/confirm/prompt), captured and dismissed
  * a console message carrying the run's unique nonce

Nothing is typed, clicked or submitted, and nothing leaves the page: the proof
payload sets a variable in its own page and nothing else. The point is a
truthful severity, not a bigger one.

Optional dependency. Without Playwright installed the tool reports
``not_installed`` and the pipeline carries on with the unproven finding, exactly
as before.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT_S = 20
MAX_URLS = 25

# Each payload sets the proof variable rather than doing anything to the page.
# `{n}` is the per-run nonce, so a page echoing a *previous* run's marker
# cannot register as a hit.
_PAYLOAD_TEMPLATES = [
    '"><script>window.__cyberswarm_proof="{n}"</script>',
    "'><script>window.__cyberswarm_proof='{n}'</script>",
    '<img src=x onerror=\'window.__cyberswarm_proof="{n}"\'>',
    '"><svg onload=\'window.__cyberswarm_proof="{n}"\'>',
    'javascript:window.__cyberswarm_proof="{n}"',
    '";window.__cyberswarm_proof="{n}";//',
    "</script><script>window.__cyberswarm_proof='{n}'</script>",
]


class XSSProofTool(Tool):
    name = "xss_proof"
    capability = "XSS_PROOF"
    binary = ""  # browser-driven, not a subprocess

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config if isinstance(config, dict) else {}

    # ── availability ─────────────────────────────────────────────────────────

    @staticmethod
    def _playwright():
        try:
            from playwright.sync_api import sync_playwright
            return sync_playwright
        except Exception:  # noqa: BLE001
            return None

    _browser_ok: Optional[bool] = None

    def is_available(self) -> bool:
        """True only if Playwright imports AND its browser actually launches.

        Checking the import alone is not enough: `pip install playwright`
        gives you the module, but the Chromium binary is a separate
        `playwright install chromium` step. Without it the module imports
        cleanly and then the driver dies on launch. The launch probe is cached
        so it runs once per process, not once per URL.
        """
        if self._playwright() is None:
            return False
        cls = type(self)
        if cls._browser_ok is None:
            cls._browser_ok = self._probe_browser()
        return cls._browser_ok

    @classmethod
    def _probe_browser(cls) -> bool:
        sync_playwright = cls._playwright()
        if sync_playwright is None:
            return False
        try:
            with sync_playwright() as driver:
                browser = driver.chromium.launch(args=["--no-sandbox"])
                browser.close()
            return True
        except Exception:  # noqa: BLE001 - any launch failure means unusable
            return False

    def validate(self) -> Optional[str]:
        if self._playwright() is None:
            return ("Playwright is not installed, so XSS findings cannot be "
                    "proven to execute. Install with `pip install playwright` "
                    "then `playwright install chromium`. Detection still works; "
                    "findings stay unproven.")
        if not self.is_available():
            return ("Playwright is installed but its browser will not launch "
                    "(run `playwright install chromium`). XSS findings stay "
                    "unproven; detection is unaffected.")
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    # ── payload construction ─────────────────────────────────────────────────

    @staticmethod
    def candidate_urls(url: str, nonce: str,
                       param: Optional[str] = None) -> List[str]:
        """Build one URL per payload, injecting into query parameters.

        With no query string there is nothing to inject into, so the URL is
        returned unchanged and will simply not prove anything.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return [url]

        targets = [param] if param else [k for k, _ in params]
        out: List[str] = []
        for template in _PAYLOAD_TEMPLATES:
            payload = template.format(n=nonce)
            for name in targets:
                mutated = [(k, payload if k == name else v) for k, v in params]
                out.append(urlunparse(parsed._replace(query=urlencode(mutated))))
        return out

    # ── execution ────────────────────────────────────────────────────────────

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT_S,
            **kwargs: Any) -> ToolResult:
        problem = self.validate()
        if problem:
            return ToolResult(tool=self.name, status="not_installed",
                              capability=self.capability, error=problem)

        urls = kwargs.get("urls") or [target]
        param = kwargs.get("param")
        nonce = secrets.token_hex(8)

        candidates: List[str] = []
        for url in urls[:MAX_URLS]:
            candidates.extend(self.candidate_urls(str(url), nonce, param))
        if not candidates:
            return ToolResult(tool=self.name, status="success",
                              capability=self.capability,
                              results={"proven": [], "tested": 0,
                                       "note": "no injectable parameters"})

        try:
            proven, tested = self._drive(candidates, nonce, timeout)
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            # A driver/browser fault is an environment problem, not a finding
            # failure -- surface it as not_installed so the pipeline carries on
            # with the unproven finding rather than logging a hard error.
            driverish = any(term in message.lower() for term in
                            ("playwright", "driver", "connection closed",
                             "browser", "executable", "cli.js"))
            status = "not_installed" if driverish else "error"
            type(self)._browser_ok = False   # don't retry a broken browser
            return ToolResult(tool=self.name, status=status,
                              capability=self.capability,
                              error=f"xss_proof unavailable: {message[:200]}")

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"proven": proven, "tested": tested, "nonce": nonce,
                     "executed": bool(proven)})

    def _drive(self, candidates: List[str], nonce: str,
               timeout: int) -> tuple:
        sync_playwright = self._playwright()
        proven: List[Dict[str, Any]] = []
        tested = 0

        with sync_playwright() as driver:
            browser = driver.chromium.launch(args=["--no-sandbox"])
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                dialogs: List[str] = []
                console: List[str] = []
                page.on("dialog", lambda d: (dialogs.append(d.message),
                                             d.dismiss()))
                page.on("console", lambda m: console.append(m.text))

                for url in candidates:
                    tested += 1
                    dialogs.clear()
                    console.clear()
                    try:
                        page.goto(url, timeout=timeout * 1000,
                                  wait_until="domcontentloaded")
                        page.wait_for_timeout(250)
                        marker = page.evaluate(
                            "() => window.__cyberswarm_proof || null")
                    except Exception:  # noqa: BLE001 - a dead URL is not a failure
                        continue

                    how = None
                    if marker == nonce:
                        how = "script executed and set the proof variable"
                    elif any(nonce in d for d in dialogs):
                        how = "payload triggered a JavaScript dialog"
                    elif any(nonce in c for c in console):
                        how = "payload executed and wrote to the console"

                    if how:
                        proven.append({"url": url, "evidence": how,
                                       "nonce": nonce})
                        # One proof per parameter is enough; more adds noise.
                        break

                    # Reset so a marker cannot leak into the next candidate.
                    try:
                        page.evaluate("() => { window.__cyberswarm_proof = null; }")
                    except Exception:  # noqa: BLE001
                        pass
            finally:
                browser.close()
        return proven, tested
