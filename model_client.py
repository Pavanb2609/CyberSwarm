"""
Thin client for talking to a local model backend.

Supports two backends, chosen via CLI arg or config:

  1. "ollama"          -> POST {base_url}/api/chat
                          e.g. base_url=http://localhost:11434, model="qwen3:8b"

  2. "openai_compat"   -> POST {base_url}/v1/chat/completions
                          works with vLLM, LM Studio, text-generation-webui,
                          llama.cpp server, GPT-OSS served this way, etc.
                          e.g. base_url=http://localhost:8000, model="gpt-oss-20b"

No API key is sent by default; pass api_key= if your server requires one.
"""

import logging
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger("cyberswarm.model_client")


# ── model-backend host auto-detection ───────────────────────────────────────
# The configured base_url may point at a stale/rotating host IP (a laptop Ollama
# on DHCP, a lab box on a changing subnet, ...). When it won't answer, CyberSwarm
# probes the default port on localhost + every local interface IP and uses the
# first backend that responds, so the whole pipeline keeps running with zero
# config changes. Explicit remote hosts are preserved when nothing local answers.

_BACKEND_PORTS = {"ollama": 11434, "openai_compat": 8000}
_BACKEND_HEALTH = {"ollama": "/api/tags", "openai_compat": "/v1/models"}


def _local_ipv4s() -> list[str]:
    """IPv4 addresses actually assigned to this host (no loopback)."""
    ips: list[str] = []
    for name in (socket.gethostname(), "localhost"):
        try:
            for info in socket.getaddrinfo(name, None, family=socket.AF_INET):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            continue
    try:  # bind+check trick: UDP connect makes the kernel pick a real egress IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        egress = sock.getsockname()[0]
        sock.close()
        if egress not in ips:
            ips.append(egress)
    except OSError:
        pass
    return [ip for ip in ips if ip not in ("127.0.0.1", "0.0.0.0")]


def _gateway_ipv4s() -> list[str]:
    """Routers/NAT hosts the box talks through (default gw, docker0 bridge, etc.).

    Model servers frequently live on the VM host / adjacent bridge host
    (e.g. VirtualBox NAT gw at .2, docker0 at 172.x.0.1), so probing these
    covers backends that are not an own-interface address.
    """
    gws: list[str] = []
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True,
                             timeout=5).stdout or ""
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts and parts.index("via") + 1 < len(parts):
                gw = parts[parts.index("via") + 1]
                if gw not in gws:
                    gws.append(gw)
    except Exception:  # noqa: BLE001 (no iproute2 / no permission)
        pass
    return gws


def resolve_backend_url(base_url: Optional[str], backend: str = "ollama",
                        probe_timeout: float = 1.5) -> str:
    """Return a reachable model-backend URL for `backend`.

    The configured URL wins if it answers its health endpoint. Otherwise the
    backend's default port is probed on localhost, 127.0.0.1, and every local
    interface IP, and the first responder is returned. Falls back to the
    configured URL unchanged when nothing local answers so a deliberately
    remote host is never silently replaced.
    """
    if not base_url:
        base_url = f"http://localhost:{_BACKEND_PORTS.get(backend, 11434)}"
    health = _BACKEND_HEALTH.get(backend, "/api/tags")
    base = base_url.rstrip("/")
    try:
        requests.get(base + health, timeout=probe_timeout)
        return base
    except Exception:  # noqa: BLE001 — any connection/IP/TLS failure means "not here"
        pass

    from urllib.parse import urlsplit
    scheme = urlsplit(base_url).scheme or "http"
    port = urlsplit(base_url).port or _BACKEND_PORTS.get(backend, 11434)
    for host in ["localhost", "127.0.0.1"] + _local_ipv4s() + _gateway_ipv4s():
        cand = f"{scheme}://{host}:{port}"
        try:
            requests.get(cand + health, timeout=probe_timeout)
            return cand
        except Exception:  # noqa: BLE001
            continue
    return base


@dataclass
class ModelClient:
    backend: str = "ollama"          # "ollama" | "openai_compat"
    base_url: str = "http://localhost:11434"
    model: str = "qwen3:8b"
    api_key: Optional[str] = None
    timeout: int = 600
    max_retries: int = 1
    temperature: float = 0.0         # deterministic for benchmarking
    default_temp: float = 0.3        # used when temperature is None (reasoning agents)
    think: bool = False              # Qwen3/reasoning models: disable extended thinking for speed + clean JSON
    max_tokens: int = 2048           # cap generation (was 700 — too low for complex JSON from planner/critic)
    context_window: int = 32768      # model's context size, for context-load measurement

    # Rolling record of the last call's prompt size. Read by difficulty.py to
    # measure context load, which was previously unmeasured -- context
    # exhaustion is one of the largest single causes of agent failure and the
    # pipeline had no idea how close it was running to the limit.
    last_prompt_tokens: int = 0
    peak_prompt_tokens: int = 0

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token count without a tokenizer dependency.

        ~4 characters per token holds well enough for English prose and JSON to
        drive a threshold. It is an estimate, and callers should treat it as
        one -- but an approximate measurement beats the current situation of no
        measurement at all.
        """
        return max(0, len(str(text or "")) // 4)

    def context_load(self) -> float:
        """Fraction of the context window the last prompt consumed, 0-1."""
        if not self.context_window:
            return 0.0
        return min(1.0, self.last_prompt_tokens / float(self.context_window))

    def _record_prompt(self, system_prompt: str, user_prompt: str) -> None:
        total = self.estimate_tokens(system_prompt) + self.estimate_tokens(user_prompt)
        self.last_prompt_tokens = total
        self.peak_prompt_tokens = max(self.peak_prompt_tokens, total)
        if self.context_window and total > 0.9 * self.context_window:
            log.warning("Prompt is %d tokens, %.0f%% of the %d-token window — "
                        "the model will start forgetting earlier content.",
                        total, 100.0 * total / self.context_window, self.context_window)

    # Structured output (constrained decoding). When a caller passes
    # json_schema=, the backend is asked to only emit JSON matching it:
    #   * Ollama >= 0.5:      payload["format"] = <schema>
    #   * OpenAI-compatible:  payload["response_format"] = {"type": "json_schema", ...}
    #     (vLLM, LM Studio, llama.cpp server).
    # This removes the "model returned prose / half a JSON object" failure mode
    # that sank qwen3:30b's valid-JSON rate to 47% in the 2026-09-01 benchmark.
    # If a server rejects the field (HTTP 400/422), the client remembers that and
    # transparently retries without it, so older servers keep working.
    structured_output: bool = True
    _schema_unsupported: bool = False

    def chat(self, system_prompt: str, user_prompt: str, temperature=None,
             json_schema: Optional[dict] = None) -> str:
        self._record_prompt(system_prompt, user_prompt)
        if temperature is None:
            temperature = self.default_temp if self.temperature is None else self.temperature
        schema = json_schema if (self.structured_output and not self._schema_unsupported) else None
        last_err = None
        for attempt in range(self.max_retries + 1):
            try:
                if self.backend == "ollama":
                    return self._chat_ollama(system_prompt, user_prompt, temperature, schema)
                elif self.backend == "openai_compat":
                    return self._chat_openai_compat(system_prompt, user_prompt, temperature, schema)
                else:
                    raise ValueError(f"Unknown backend: {self.backend}")
            except _SchemaRejected as e:
                log.warning("Backend rejected structured output (%s); retrying without it.", e)
                self._schema_unsupported = True
                schema = None
                last_err = e
                continue
            except Exception as e:  # noqa: BLE001
                last_err = e
                log.warning("Model call attempt %d/%d failed: %s", attempt + 1, self.max_retries + 1, e)
                time.sleep(1.5 * (attempt + 1))
        if schema is None and isinstance(last_err, _SchemaRejected):
            # The rejection consumed the last attempt; make one plain call.
            if self.backend == "ollama":
                return self._chat_ollama(system_prompt, user_prompt, temperature, None)
            return self._chat_openai_compat(system_prompt, user_prompt, temperature, None)
        raise RuntimeError(f"Model call failed after {self.max_retries + 1} attempts: {last_err}")

    @staticmethod
    def _raise_for_status(resp, used_schema: bool) -> None:
        if used_schema and resp.status_code in (400, 422):
            raise _SchemaRejected(f"HTTP {resp.status_code}: {resp.text[:200]}")
        resp.raise_for_status()

    def _chat_ollama(self, system_prompt: str, user_prompt: str, temperature=None,
                     json_schema: Optional[dict] = None) -> str:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "think": self.think,
            "options": {"temperature": temperature or 0.0,
                        "num_predict": self.max_tokens,
                        # Without an explicit num_ctx, Ollama silently runs at
                        # its 4096-token default and truncates long prompts
                        # (system maps, evidence, critic debates) invisibly.
                        "num_ctx": self.context_window},
        }
        if json_schema:
            payload["format"] = json_schema
        resp = requests.post(url, json=payload, timeout=self.timeout)
        self._raise_for_status(resp, bool(json_schema))
        data = resp.json()
        return data["message"]["content"]

    def _chat_openai_compat(self, system_prompt: str, user_prompt: str, temperature=None,
                            json_schema: Optional[dict] = None) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature or 0.0,
        }
        if json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "cyberswarm_decision", "schema": json_schema},
            }
        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        self._raise_for_status(resp, bool(json_schema))
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class _SchemaRejected(Exception):
    """The backend refused the structured-output field."""


def chat_structured(client, system_prompt: str, user_prompt: str,
                    json_schema: Optional[dict] = None, temperature=None) -> str:
    """Call client.chat with a JSON schema when the client supports it.

    Test doubles and older client objects only accept
    (system_prompt, user_prompt, temperature); fall back to that signature
    instead of crashing.
    """
    if json_schema is not None:
        try:
            return client.chat(system_prompt, user_prompt, temperature=temperature,
                               json_schema=json_schema)
        except TypeError as exc:
            if "json_schema" not in str(exc):
                raise
    return client.chat(system_prompt, user_prompt, temperature=temperature)

