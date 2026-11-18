import json
import re
from typing import Any, Dict, List

from tools.base import Tool

_URL_RE = re.compile(r"^https?://[^\s\"'<>]+$")


class KatanaTool(Tool):
    name = "katana"
    capability = "WEB_CRAWLING"
    binary = "katana"

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = kwargs.get("full_url") or (target if target.startswith("http") else f"http://{target}")
        depth = str(kwargs.get("depth", 2))
        return [self.binary, "-u", url, "-silent", "-jsonl", "-depth", depth]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        urls = []
        skipped = 0
        sample_skipped = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            url = None
            try:
                obj = json.loads(line)
                # newer katana nests the URL under request.endpoint; older
                # versions put it at the top level as "endpoint" or "url"
                candidate = (
                    obj.get("endpoint")
                    or obj.get("url")
                    or (obj.get("request") or {}).get("endpoint")
                    or (obj.get("request") or {}).get("url")
                )
                if candidate and _URL_RE.match(candidate):
                    url = candidate
                elif candidate is None:
                    pass  # valid JSON, just not a URL-bearing line (e.g. a finding/summary line) -- not an error
                else:
                    skipped += 1
                    if len(sample_skipped) < 3:
                        sample_skipped.append(line[:200])
            except json.JSONDecodeError:
                # katana without -jsonl prints plain URLs, one per line --
                # but only accept the line if it's actually a clean URL.
                # Malformed pages (e.g. a crawl target with broken HTML) can
                # make katana emit raw/binary error output instead; anything
                # that doesn't look like a real URL is dropped, not stored.
                if _URL_RE.match(line):
                    url = line
                else:
                    skipped += 1
                    if len(sample_skipped) < 3:
                        sample_skipped.append(line[:200])

            if url and url not in urls:
                urls.append(url)

        result = {"discovered_urls": urls, "count": len(urls)}
        if skipped:
            result["skipped_malformed_lines"] = skipped
            result["sample_skipped_lines"] = sample_skipped  # first few, for debugging what katana actually emits
        return result
