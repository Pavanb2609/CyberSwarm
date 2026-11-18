"""
Searchsploit wrapper for EXPLOIT_SEARCH capability.

Given a technology name (and optionally version), queries the local
Exploit-DB mirror via searchsploit and returns matched exploit metadata.

Install: apt install exploitdb   (provides /usr/bin/searchsploit)
"""

import json
import re
from typing import Any, Dict, List

from tools.base import Tool


class SearchsploitTool(Tool):
    name = "searchsploit"
    capability = "EXPLOIT_SEARCH"
    binary = "searchsploit"

    # Cached: the pip clone (`pip install searchsploit`, lands in ~/.local/bin)
    # is a minimal reimplementation that rejects the long options the real
    # exploitdb build accepts. The meesho run hit exactly this -- the pip clone
    # errored on `--json`/`--exclude`. Detect the flavour once and adapt.
    _long_opts: bool | None = None

    def _supports_long_opts(self) -> bool:
        cls = type(self)
        if cls._long_opts is None:
            cls._long_opts = self._probe_long_opts()
        return cls._long_opts

    def _probe_long_opts(self) -> bool:
        import shutil
        import subprocess

        path = shutil.which(self.binary)
        if not path:
            return True   # will fail validate() anyway; assume the real one
        try:
            proc = subprocess.run([path, "--help"], capture_output=True,
                                  text=True, timeout=15)
        except Exception:  # noqa: BLE001
            return False
        help_text = (proc.stdout or "") + (proc.stderr or "")
        # The real exploitdb build documents --json in its help; the pip clone
        # does not.
        return "--json" in help_text or "-j, --json" in help_text

    def build_command(self, target: str, **kwargs) -> List[str]:
        """
        target here is a technology string, e.g. "WordPress 5.8" or "nginx 1.18".
        The caller (run_agent_loop.py) passes each technology in evidence
        as a separate EXPLOIT_SEARCH call rather than one bulk query.
        """
        if self._supports_long_opts():
            return [self.binary, "--json",
                    "--exclude", "dos",   # skip DoS modules — not useful for pentest
                    target]
        # pip clone: JSON via -j, no --exclude. DoS filtering moves to parse().
        return [self.binary, "-j", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # The pip clone emits invalid JSON on some rows (a known double-quote
            # bug: `"Exploit":"title""`). Repair the common case, then retry once.
            repaired = re.sub(r'""(\s*[,}])', r'"\1', stdout)
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                return {"exploit_candidates": [], "count": 0}

        exploits = (data.get("RESULTS_EXPLOIT")
                    or data.get("RESULTS")          # pip clone uses a flat key
                    or []) + (data.get("RESULTS_SHELLCODE") or [])
        # When --exclude was unavailable (pip clone), drop DoS results here.
        exploits = [e for e in exploits
                    if "/dos/" not in str(e.get("Path", "")).lower()
                    and "denial of service" not in str(e.get("Title",
                                                             e.get("Exploit", ""))).lower()]

        candidates = []
        for ex in exploits[:20]:    # cap — don't flood evidence with hundreds of matches
            title = ex.get("Title") or ex.get("Exploit") or ""
            edb_id = ex.get("EDB-ID", "")
            path = ex.get("Path", "")
            etype = ex.get("Type", "")
            platform = ex.get("Platform", "")

            # Extract CVE from title if present
            cve = re.findall(r"CVE-\d{4}-\d+", title)

            candidates.append({
                "edb_id":    edb_id,
                "title":     title[:200],
                "type":      etype,
                "platform":  platform,
                "path":      path,
                "cve":       cve[:2],
                "url":       f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "",
            })

        return {
            "exploit_candidates": candidates,
            "count": len(candidates),
        }
