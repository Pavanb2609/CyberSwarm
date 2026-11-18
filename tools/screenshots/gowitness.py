import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from tools.base import Tool

SCREENSHOTABLE_CODES = {200, 301, 302, 403}  # plus any >= 500


class GowitnessTool(Tool):
    """
    Wraps gowitness v3 (`scan file`) to take headless-Chrome screenshots
    of the target homepage plus all discovered paths with screenshotable
    HTTP status codes (200, 301, 302, 403, 500+).
    """

    name = "gowitness"
    capability = "SCREENSHOT_CAPTURE"
    binary = "gowitness"
    allow_nonzero_exit = True

    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

    def __init__(self):
        self._shot_dir = self.PROJECT_ROOT / "results" / "screenshots"
        self._shot_dir.mkdir(parents=True, exist_ok=True)
        self._jsonl_path = self.PROJECT_ROOT / "results" / "gowitness_tmp.jsonl"

    def _build_url_file(self, target: str, **kwargs) -> Path:
        """Write a newline-separated URL file for gowitness scan file."""
        url = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        urls = [url]

        for p in kwargs.get("discovered_paths", []):
            status = p.get("status_code") or p.get("status", 0)
            path_url = p.get("url", "")
            if not path_url:
                continue
            if status in SCREENSHOTABLE_CODES or status >= 500:
                if path_url not in urls:
                    urls.append(path_url)

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("\n".join(urls) + "\n", encoding="utf-8")
        return tmp

    def build_command(self, target: str, **kwargs) -> List[str]:
        url_file = self._build_url_file(target, **kwargs)
        self._url_file = url_file
        return [
            self.binary, "scan", "file", "--file", str(url_file),
            "--screenshot-path", str(self._shot_dir),
            "--write-jsonl", "--write-jsonl-file", str(self._jsonl_path),
            "--driver", "gorod", "--no-http",
        ]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        screenshots = []
        if self._jsonl_path.exists():
            for ln in self._jsonl_path.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    entry = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                final_url = entry.get("final_url") or entry.get("url") or ""
                screenshots.append({
                    "url": final_url,
                    "status_code": entry.get("response_code") or entry.get("status_code"),
                    "title": entry.get("title"),
                })
            self._jsonl_path.unlink(missing_ok=True)

        url_file = getattr(self, "_url_file", None)
        if url_file:
            url_file.unlink(missing_ok=True)

        # Match screenshots to files by URL components in filename
        shot_files = {p.name: p for p in self._shot_dir.glob("*") if p.is_file()}
        for s in screenshots:
            url = s.get("url", "")
            parsed = urlparse(url)
            domain_slug = f"{parsed.scheme}---{parsed.netloc}"
            path_part = parsed.path.rstrip("/").lstrip("/")
            for fname in shot_files:
                if not path_part:
                    # Homepage: match files like https---app.codacy.com-443.jpeg
                    suffix = fname[len(domain_slug):]
                    if re.match(r"^-\d+\.jpeg$", suffix):
                        s["path"] = str(shot_files[fname])
                        break
                else:
                    if domain_slug in fname and path_part in fname:
                        s["path"] = str(shot_files[fname])
                        break

        # Report only files THIS run actually captured (matched from the jsonl),
        # not stale screenshots left by previous engagements in the shared dir
        # (a past wolt.com screenshot was being reported as this run's result).
        captured = [s["path"] for s in screenshots if s.get("path")]

        all_paths = sorted(str(p) for p in self._shot_dir.glob("*") if p.is_file())

        return {
            "screenshot_captured": bool(captured),
            "screenshot_paths": captured,
            "screenshot_path": captured[0] if captured else None,
            "screenshots": screenshots,
            "screenshots_dir": str(self._shot_dir),
            "preexisting_files_in_dir": len(all_paths) - len(captured),
        }
