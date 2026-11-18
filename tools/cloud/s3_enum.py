"""
S3_ENUM -- list the contents of a publicly-listable S3 bucket over the REST API.

Read-only: a single `ListObjectsV2` GET (max-keys=1000), the same request any
anonymous browser could send. Only ever runs against buckets that recon has
already confirmed as publicly listable (status 200), so it adds concrete
evidence (object count + sample keys) without guessing. Pure Python (urllib).
"""

import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 60


class S3EnumTool(Tool):
    name = "s3_enum"
    capability = "S3_ENUM"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-urllib-s3-enum", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        buckets = [b for b in (kwargs.get("buckets") or []) if b]
        if not buckets:
            buckets = [target]
        assets = []
        for bucket in buckets:
            listing = self._list_bucket(bucket, timeout)
            if listing is not None:
                assets.append(listing)
        if not assets:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="No publicly listable buckets found (403/404 on all).")
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"s3_assets": assets, "target": target})

    def _list_bucket(self, bucket: str, timeout: int) -> Optional[Dict[str, Any]]:
        url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=1000"
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-s3-enum/1.0)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(2_000_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):  # exists-but-private, or does not exist
                return None
            return None
        except Exception:  # noqa: BLE001
            return None

        keys: List[str] = []
        is_truncated = False
        try:
            root = ET.fromstring(body)
            for elem in root.iter():
                tag = elem.tag.rsplit("}", 1)[-1]
                if tag == "Key" and elem.text:
                    keys.append(elem.text)
                elif tag == "IsTruncated" and elem.text and elem.text.strip().lower() == "true":
                    is_truncated = True
        except ET.ParseError:
            return None

        if not keys:
            return None

        downloads = self._check_downloads(bucket, keys[:2], timeout)

        return {
            "bucket": bucket,
            "list_url": url,
            "publicly_listable": True,
            "object_count": len(keys),
            "is_truncated": is_truncated,
            "sample_keys": keys[:25],
            "downloadable_objects": downloads,
            "public_downloads": sum(1 for d in downloads if d.get("status") == 200),
        }

    @staticmethod
    def _check_downloads(bucket: str, keys: List[str], timeout: int) -> List[Dict[str, Any]]:
        """Read-only HEAD of up to 2 sample keys to prove objects are actually
        downloadable by anonymous users (and reveal content type / size)."""
        out = []
        headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-s3-enum/1.0)"}
        for key in keys:
            url = f"https://{bucket}.s3.amazonaws.com/{urllib.parse.quote(key, safe='/')}"
            try:
                req = urllib.request.Request(url, method="HEAD", headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    out.append({"key": key, "url": url, "status": resp.status,
                                "content_type": resp.headers.get("Content-Type", ""),
                                "content_length": resp.headers.get("Content-Length", "")})
            except urllib.error.HTTPError as e:
                out.append({"key": key, "url": url, "status": e.code})
            except Exception:  # noqa: BLE001
                out.append({"key": key, "url": url, "status": 0})
        return out
