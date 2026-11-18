"""
GRAPHQL_INTROSPECTION -- passive GraphQL schema discovery.

Probes common GraphQL endpoints for introspection enabled.
Reports exposed types, sensitive fields, and mutation capabilities.
Pure Python + requests.
"""

import json
from typing import Any

import requests

from tools.base import Tool, ToolResult

SENSITIVE_KEYWORDS = [
    "password", "token", "secret", "key", "auth", "session", "credit", "card",
    "payment", "email", "phone", "ssn", "address", "user", "account", "admin",
    "order", "booking", "passenger", "pii", "personal", "private", "credential",
]

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/gql", "/gql/", "/graph", "/query",
    "/flights/graphql/", "/v1/graphql", "/v2/graphql",
]

INTROSPECTION_QUERY = """{ __schema {
  queryType { name }
  mutationType { name }
  types {
    name kind
    fields { name type { name kind } }
    inputFields { name type { name kind } }
  }
} }"""


class GraphQLIntrospectionTool(Tool):
    """Passive GraphQL introspection scanner."""

    name = "graphql_introspection"
    capability = "GRAPHQL_INTROSPECTION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-graphql-introspection", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 15, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        extra_paths = kwargs.get("endpoints", [])

        paths_to_try = extra_paths + GRAPHQL_PATHS
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
                    "Content-Type": "application/json"}

        endpoints_found = []

        for path in paths_to_try:
            url = base.rstrip("/") + "/" + path.lstrip("/")
            try:
                resp = requests.post(url, json={"query": INTROSPECTION_QUERY},
                                     timeout=timeout, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        schema = data["data"]["__schema"]
                        endpoint_info = self._analyze_schema(schema, url)
                        if endpoint_info:
                            endpoints_found.append(endpoint_info)
            except (requests.RequestException, json.JSONDecodeError, ValueError):
                continue

        if not endpoints_found:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"endpoints": [], "count": 0,
                                       "message": "No GraphQL introspection endpoints found"})

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={
                              "endpoints": endpoints_found,
                              "count": len(endpoints_found),
                              "total_types": sum(e["type_count"] for e in endpoints_found),
                          })

    @staticmethod
    def _analyze_schema(schema: dict, url: str) -> dict[str, Any] | None:
        types = schema.get("types", [])
        custom = [t for t in types if not t["name"].startswith("__")]

        if not custom:
            return None

        objects = [t for t in custom if t["kind"] == "OBJECT"]
        inputs = [t for t in custom if t["kind"] == "INPUT_OBJECT"]

        # Find sensitive types
        sensitive_types = []
        for t in custom:
            name_lower = t["name"].lower()
            if any(kw in name_lower for kw in SENSITIVE_KEYWORDS):
                fields = [f["name"] for f in (t.get("fields") or t.get("inputFields") or [])]
                sensitive_types.append({"name": t["name"], "kind": t["kind"], "fields": fields[:10]})

        # Get query fields
        query_type_name = (schema.get("queryType") or {}).get("name", "Query")
        query_fields = []
        mutation_fields = []
        for t in objects:
            if t["name"] == query_type_name:
                query_fields = [f["name"] for f in (t.get("fields") or [])]
            if t["name"] == "Mutation":
                mutation_fields = [f["name"] for f in (t.get("fields") or [])]

        return {
            "url": url,
            "type_count": len(custom),
            "object_count": len(objects),
            "input_count": len(inputs),
            "has_mutation": bool(mutation_fields),
            "query_fields": query_fields,
            "mutation_fields": mutation_fields,
            "sensitive_types": sensitive_types,
            "severity": "HIGH" if sensitive_types or mutation_fields else "MEDIUM",
        }
