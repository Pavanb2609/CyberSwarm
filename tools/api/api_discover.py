from typing import Any, Dict, List
from urllib.parse import urljoin

from tools.base import Tool, ToolResult

# Common API surface signatures: spec files, docs UIs, and version-prefixed
# base paths. Kept intentionally small and high-signal rather than a huge
# wordlist -- this is meant to *classify* (REST/GraphQL/SOAP presence) not
# to replace CONTENT_DISCOVERY's broader ffuf sweep.
CANDIDATE_PATHS = [
    # OpenAPI / Swagger spec + UI
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/v1/swagger.json", "/v2/api-docs",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/api/docs",
    "/api/swagger.json", "/.well-known/openapi.json",
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    # SOAP / WSDL
    "/service?wsdl", "/api?wsdl",
    # Generic versioned API roots
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/v1",
]

# response bytes that strongly indicate a given API architecture, so the
# planner can classify REST_API / GRAPHQL_API / SOAP_API from evidence
# rather than guessing from path names alone.
SIGNATURES = {
    "REST_API": ('"openapi"', '"swagger"', "swagger-ui"),
    "GRAPHQL_API": ('"__schema"', "graphiql", "graphql"),
    "SOAP_API": ("<wsdl:definitions", "soap:envelope", "wsdl"),
}


def _parse_openapi_spec(session, spec_url: str,
                        per_request_timeout: int) -> Dict[str, Any]:
    """Fetch + parse an OpenAPI/Swagger spec into discoverable endpoints.

    Returns {"urls": [...], "params": [...]}: urls are endpoint URLs (query
    params appended when the spec declares them); params is a list of
    {"url", "name", "in": "query|path|body|header", "method"} dicts.
    """
    out: Dict[str, Any] = {"urls": [], "params": []}
    try:
        resp = session.get(spec_url, timeout=per_request_timeout)
        if resp.status_code != 200:
            return out
        try:
            spec = resp.json()
        except Exception:
            return out
        paths = spec.get("paths") or {}
        servers = [s.get("url", "").rstrip("/") for s in (spec.get("servers") or [])]
        base = servers[0] if servers else spec_url.rsplit("/", 1)[0]
        schemas = dict((spec.get("definitions") or {}))
        schemas.update((spec.get("components") or {}).get("schemas") or {})

        for path, ops in paths.items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method not in ("get", "post", "put", "delete", "patch"):
                    continue
                params = op.get("parameters") or []
                body_fields: List[str] = []
                body_schema = ((op.get("requestBody") or {})
                               .get("content", {}).get("application/json", {})
                               .get("schema", {}))
                ref = body_schema.get("$ref", "")
                body_schema = schemas.get(ref.rsplit("/", 1)[-1]) or body_schema
                for field in list((body_schema.get("properties") or {}).keys()):
                    body_fields.append(field)
                url = f"{base}{path}" if base.startswith("http") else f"https://{base}{path}"
                query_pairs = []
                for p in params:
                    pname = p.get("name", "")
                    where = p.get("in", "query")
                    if not pname:
                        continue
                    if where == "query":
                        query_pairs.append(f"{pname}=x")
                        out["params"].append({"url": url, "name": pname,
                                              "in": "query", "method": method})
                    elif where in ("path", "body", "header"):
                        out["params"].append({"url": url, "name": pname,
                                              "in": where, "method": method})
                for f in body_fields:
                    out["params"].append({"url": url, "name": f,
                                          "in": "body", "method": method})
                full = f"{url}?{'&'.join(query_pairs)}" if query_pairs else url
                if full not in out["urls"]:
                    out["urls"].append(full)
        return out
    except Exception:
        return out


class APIDiscoverTool(Tool):
    """
    Probes a curated set of common API spec/doc/base paths over HTTP(S) and
    classifies which API architecture (if any) is present. Pure Python via
    `requests` -- no external binary, so it always works with zero installs,
    same rationale as dns_resolve.py.
    """

    name = "api_discover"
    capability = "API_ENDPOINT_DISCOVERY"
    binary = ""  # no external binary required

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []  # unused; run() is overridden below

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}  # unused; run() is overridden below

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        try:
            import requests
        except ImportError as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"'requests' package not available: {e}")

        base_url = kwargs.get("base_url") or kwargs.get("full_url")
        if not base_url:
            base_url = target if target.startswith("http") else f"https://{target}"
        base_url = base_url.rstrip("/")

        per_request_timeout = kwargs.get("per_request_timeout", 6)
        found: List[Dict[str, Any]] = []
        detected_types = set()

        session = requests.Session()
        session.headers.update({"User-Agent": "CyberSwarm-Recon/1.0"})

        for path in CANDIDATE_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                resp = session.get(url, timeout=per_request_timeout, allow_redirects=True,
                                    verify=True)
            except requests.exceptions.RequestException:
                continue

            if resp.status_code in (401, 403, 404, 405):
                # 401/403 on a known API path is still a meaningful signal
                # (endpoint exists, just gated) -- keep it, but skip generic 404s.
                if resp.status_code == 404:
                    continue

            body_sample = (resp.text or "")[:2000].lower()
            matched_types = [
                api_type for api_type, needles in SIGNATURES.items()
                if any(n.lower() in body_sample for n in needles)
            ]
            for t in matched_types:
                detected_types.add(t)

            # Only record paths that either matched a signature or returned
            # a non-404 status -- avoids flooding evidence with dead ends.
            if matched_types or resp.status_code < 400:
                found.append({
                    "url": url,
                    "status": resp.status_code,
                    "length": len(resp.content or b""),
                    "matched_signatures": matched_types,
                })

        result = {
            "discovered_endpoints": found,
            "count": len(found),
            "detected_api_types": sorted(detected_types),
        }

        # When a machine-readable API spec was found, parse it into real
        # endpoints + parameters so the SystemMap can carry an injectable
        # surface (incl. POST-body params) instead of a bare classification.
        for f in found:
            if "REST_API" not in (f.get("matched_signatures") or []):
                continue
            spec_url = f["url"]
            parsed = _parse_openapi_spec(session, spec_url, per_request_timeout)
            if parsed["urls"]:
                result["openapi_spec"] = spec_url
                result["discovered_urls"] = parsed["urls"][:60]
                result["discovered_parameters"] = parsed["params"][:80]
                break

        return ToolResult(tool=self.name, status="success", capability=self.capability, results=result)
