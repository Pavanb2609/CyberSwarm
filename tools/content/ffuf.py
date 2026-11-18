import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.base import Tool
from tools.wordlists import find_wordlist


def _find_default_wordlist() -> Optional[str]:
    return find_wordlist()


# Request cap: ffuf over a full ~4.6k-entry wordlist hammered testphp.vulnweb.com
# hard enough that the host went dark mid-scan (IP-level block). Cap the number
# of wordlist entries actually sent — the first N entries of common.txt cover
# the paths that matter — with an env/kwargs override for bigger sweeps.
DEFAULT_MAX_WORDS = 500


class FFUFTool(Tool):
    name = "ffuf"
    capability = "CONTENT_DISCOVERY"
    binary = "ffuf"

    def __init__(self):
        self._json_path = Path(tempfile.mktemp(suffix=".json"))
        self._wordlist_note: Optional[str] = None

    @staticmethod
    def _resolve_max_words(kwargs: dict) -> int:
        """Request cap: explicit max_words kwarg > $FFUF_MAX_WORDS > 500. 0/negative disables."""
        v = kwargs.get("max_words")
        if v is None:
            v = os.environ.get("FFUF_MAX_WORDS", DEFAULT_MAX_WORDS)
        try:
            cap = int(v)
        except (TypeError, ValueError):
            cap = DEFAULT_MAX_WORDS
        return cap

    def _trim_wordlist(self, wordlist: str, cap: int) -> str:
        """Return the wordlist path unchanged when it fits the cap; otherwise
        write a temp wordlist with the first `cap` entries and use that."""
        lines = [ln for ln in Path(wordlist).read_text(encoding="utf-8",
                                                       errors="ignore").splitlines()
                 if ln.strip()]
        if len(lines) <= cap:
            self._wordlist_note = None
            return wordlist
        trimmed = Path(tempfile.mktemp(suffix=".txt"))
        trimmed.write_text("\n".join(lines[:cap]) + "\n", encoding="utf-8")
        self._wordlist_note = (f"wordlist capped at {cap} of {len(lines)} entries "
                               f"(request cap; set max_words/$FFUF_MAX_WORDS to change)")
        return str(trimmed)

    def validate(self):
        problem = super().validate()
        if problem:
            return problem
        if not _find_default_wordlist():
            return ("No wordlist found in common locations or $FFUF_WORDLIST. "
                    "Find one with: dpkg -L dirb | grep common.txt  (or: find / -iname 'common.txt' 2>/dev/null), "
                    "then either `export FFUF_WORDLIST=/path/to/common.txt` or pass wordlist=<path> explicitly.")
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        if kwargs.get("full_url"):
            url = kwargs["full_url"]
        elif target.startswith("http"):
            url = target
        else:
            # default to https -- many sites (this one included) redirect
            # every single http:// path to the same https:// page, which
            # makes ffuf "discover" every wordlist entry as a false positive
            url = kwargs.get("base_url") or f"https://{target}"
        wordlist = kwargs.get("wordlist") or _find_default_wordlist()
        if wordlist and not Path(wordlist).exists():
            # validate() can't catch this: it's called with no kwargs (a
            # deliberate, project-wide Tool interface choice), so it only
            # ever sees the fallback candidates, never a caller-supplied
            # path. Raising here reaches Tool.run()'s existing
            # FileNotFoundError handler, turning what would otherwise be
            # ffuf's own cryptic "stat ...: no such file or directory"
            # subprocess failure into a clear, actionable ToolResult.
            raise FileNotFoundError(
                f"wordlist '{wordlist}' does not exist. If that was meant to be relative to "
                "a system wordlist package, use an absolute path, or set $FFUF_WORDLIST, or "
                "install one: sudo apt install dirb  (or seclists)")
        if wordlist:
            cap = self._resolve_max_words(kwargs)
            if cap > 0:
                wordlist = self._trim_wordlist(wordlist, cap)
        return [
            self.binary, "-u", f"{url}/FUZZ", "-w", wordlist,
            "-o", str(self._json_path), "-of", "json", "-s",
            "-ac",  # auto-calibrate: filters out pages that respond identically regardless of path
        ]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._json_path.exists():
            return {"discovered_paths": [], "count": 0}

        data = json.loads(self._json_path.read_text(encoding="utf-8"))
        self._json_path.unlink(missing_ok=True)

        raw_results = data.get("results", [])

        # Belt-and-suspenders: if almost every result shares the exact same
        # (status, length), it's a soft-404/redirect-everything pattern that
        # slipped past -ac, not real findings. Detect and drop it rather than
        # flooding evidence with thousands of false positives.
        from collections import Counter
        signature_counts = Counter((r.get("status"), r.get("length")) for r in raw_results)
        total = len(raw_results)
        if total > 20:
            most_common_sig, most_common_count = signature_counts.most_common(1)[0]
            if most_common_count / total > 0.9:
                filtered = [r for r in raw_results
                            if (r.get("status"), r.get("length")) != most_common_sig]
                dropped = total - len(filtered)
                raw_results = filtered
                note = (f"Dropped {dropped} results sharing identical status/length "
                        f"{most_common_sig} -- likely a redirect-everything false-positive pattern "
                        f"(e.g. HTTP->HTTPS redirect), not real findings.")
            else:
                note = None
        else:
            note = None

        paths = [{"url": r.get("url"), "status": r.get("status"), "length": r.get("length")}
                 for r in raw_results]

        # cap what actually gets stored in evidence -- real findings are rarely in the thousands
        MAX_STORED = 50
        truncated = len(paths) > MAX_STORED
        result = {"discovered_paths": paths[:MAX_STORED], "count": len(paths)}
        if truncated:
            result["note"] = f"{len(paths)} paths found, storing first {MAX_STORED} to keep evidence manageable."
        if self._wordlist_note:
            result["request_cap"] = self._wordlist_note
        if note:
            result["false_positive_filter"] = note

        return result
