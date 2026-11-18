import re
from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

CLOUD_MARKERS = ("amazon web services", "aws", "azure", "google cloud", "gcp", "cloudfront")

# candidate bucket-name variants derived from the target's own name --
# the classic "does <company>-backups exist" recon technique
SUFFIXES = ["", "-prod", "-dev", "-staging", "-backup", "-backups", "-assets",
            "-static", "-media", "-data", "-files", "-uploads", "-www", "-logs"]

PROVIDERS = {
    "AWS_S3": "https://{bucket}.s3.amazonaws.com",
    "AZURE_BLOB": "https://{bucket}.blob.core.windows.net/{bucket}",
    "GCS": "https://storage.googleapis.com/{bucket}",
}


def _base_names(target: str) -> List[str]:
    host = target.split("://", 1)[-1].split("/", 1)[0]
    parts = host.split(".")
    # strip common subdomain prefixes and the TLD to get a company-ish root, e.g.
    # "app.codacy.com" -> "codacy"
    core = parts[-2] if len(parts) >= 2 else parts[0]
    names = {core}
    if len(parts) >= 3 and parts[0] not in ("www", "app"):
        names.add(parts[0])
    return [n for n in names if re.match(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", n)]


class CloudAssetDiscoveryTool(Tool):
    """
    Probes for exposed cloud storage buckets (S3 / Azure Blob / GCS) using
    bucket names derived from the target's own hostname. Pure Python via
    `requests`, no external binary. Gated: only runs if cloud-provider
    evidence already exists (technologies mentioning AWS/Azure/GCP) --
    matches the planner prompt's rule that this capability requires cloud
    evidence, not just plausibility. Passive: HEAD/GET only, no writes.
    """

    name = "cloud_enum"
    capability = "CLOUD_ASSET_DISCOVERY"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        technologies = [t.lower() for t in (kwargs.get("technologies") or [])]
        if technologies and not any(m in " ".join(technologies) for m in CLOUD_MARKERS):
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"cloud_assets_skipped": True,
                         "reason": "No cloud-provider evidence (AWS/Azure/GCP) in technologies -- "
                                   "skipping bucket enumeration rather than guessing blind."},
            )

        try:
            import requests
        except ImportError as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"'requests' package not available: {e}")

        import concurrent.futures
        headers = {"User-Agent": "CyberSwarm-Recon/1.0"}
        per_request_timeout = kwargs.get("per_request_timeout", 3)

        candidates = [f"{base}{suffix}" for base in _base_names(target) for suffix in SUFFIXES]
        found: List[Dict[str, Any]] = []

        def _probe(pair):
            provider, bucket = pair
            url = PROVIDERS[provider].format(bucket=bucket)
            try:
                resp = requests.head(url, timeout=per_request_timeout,
                                     headers=headers, allow_redirects=True)
                if resp.status_code == 405:  # some providers reject HEAD, retry GET
                    resp = requests.get(url, timeout=per_request_timeout, headers=headers)
            except requests.exceptions.RequestException:
                return None
            # 200 = public/listable, 403 = exists but access denied (still a real finding)
            if resp.status_code in (200, 403):
                return {"provider": provider, "bucket": bucket, "url": url,
                        "status": resp.status_code,
                        "publicly_listable": resp.status_code == 200}
            return None

        jobs = [(provider, bucket) for provider in PROVIDERS for bucket in candidates]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for res in ex.map(_probe, jobs):
                if res:
                    found.append(res)

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"cloud_assets_found": found, "count": len(found),
                     "candidates_checked": len(jobs)},
        )
