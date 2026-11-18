import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool, ToolResult


class WPScanTool(Tool):
    """
    Wraps wpscan for deeper WordPress assessment (version, plugins, themes,
    users, other interesting findings) once CMS_IDENTIFICATION has already
    flagged the target as WordPress. wpscan only makes sense for WordPress,
    so if the caller passes a `cms` hint that says otherwise, this skips
    running the binary entirely rather than wasting a scan on a non-match --
    same "evidence-gated" spirit as the planner's architecture-specific
    capability rules.
    """

    name = "wpscan"
    capability = "CMS_ASSESSMENT"
    binary = "wpscan"
    allow_nonzero_exit = True  # wpscan can exit non-zero on non-WP targets or when vulns are found

    def __init__(self):
        self._json_path = Path(tempfile.mktemp(suffix=".json"))

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        cms_hint = (kwargs.get("cms") or "").strip()
        if cms_hint and cms_hint.lower() != "wordpress":
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={
                    "cms_assessment_skipped": True,
                    "reason": f"CMS_IDENTIFICATION reported '{cms_hint}', not WordPress -- "
                              f"wpscan only assesses WordPress. Skipping rather than scanning blind.",
                },
            )
        return super().run(target, timeout=timeout, **kwargs)

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        return [
            self.binary, "--url", url, "--no-banner", "--random-user-agent",
            "--enumerate", "vp,vt,u",  # vulnerable plugins, vulnerable themes, users -- passive, no exploitation
            "-f", "json", "-o", str(self._json_path),
        ]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not self._json_path.exists():
            return {"cms_assessment": {}, "note": "wpscan produced no JSON output file"}

        data = json.loads(self._json_path.read_text(encoding="utf-8"))
        self._json_path.unlink(missing_ok=True)

        wp_version = ((data.get("version") or {}).get("number"))
        plugins = list((data.get("plugins") or {}).keys())
        themes = list((data.get("themes") or {}).keys())

        users_raw = data.get("users") or {}
        users = [details.get("username", uid) for uid, details in users_raw.items()] if isinstance(users_raw, dict) else []

        interesting = []
        for finding in data.get("interesting_findings", []) or []:
            desc = finding.get("to_s") or finding.get("type")
            if desc:
                interesting.append(desc)

        return {
            "cms_assessment": {
                "wordpress_version": wp_version,
                "plugins_found": plugins[:30],
                "themes_found": themes[:10],
                "users_found": users[:30],
                "interesting_findings": interesting[:20],
            }
        }
