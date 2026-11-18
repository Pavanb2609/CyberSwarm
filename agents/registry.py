"""Agent registry — maps agent names to classes for the orchestrator."""

from typing import Type

from agents.base_agent import BaseAgent

AGENT_REGISTRY: dict[str, str] = {
    "web_attack": "agents.web_attack_agent.WebAttackAgent",
    "network": "agents.specialists.NetworkAgent",
    "api": "agents.specialists.APIAgent",
    "auth": "agents.specialists.AuthAgent",
    "infra": "agents.specialists.InfraAgent",
    "cloud": "agents.specialists.CloudAgent",
    "exploitation": "agents.exploitation_agent.ExploitationAgent",
    "privesc": "agents.exploitation_agent.PrivilegeEscalationAgent",
    "pivot": "agents.exploitation_agent.PivotAgent",
    "intelligence": "agents.intelligence_agent.IntelligenceAgent",
    "web_fuzz": "agents.attack_specialists.WebFuzzAgent",
    "headers_attack": "agents.attack_specialists.HeadersAttackAgent",
    "subdomain_takeover": "agents.attack_specialists.SubdomainTakeoverAgent",
    "waf_bypass": "agents.attack_specialists.WafBypassAgent",
    "jwt": "agents.attack_specialists.JWTAnalystAgent",
    "xxe": "agents.attack_specialists.XXEAgent",
    "csrf": "agents.attack_specialists.CSRFScanAgent",
    "deserialization": "agents.attack_specialists.DeserializationAgent",
    "session_hijack": "agents.attack_specialists.SessionHijackAgent",
    "ssti_exploit": "agents.attack_specialists.SSTIExploitAgent",
    "lfi_exploit": "agents.attack_specialists.LFIExploitAgent",
    "ssrf_exploit": "agents.attack_specialists.SSRFExploitAgent",
    "jwt_exploit": "agents.attack_specialists.JWTExploitAgent",
    "insecure_design": "agents.attack_specialists.InsecureDesignAgent",
    "payload": "agents.payload_agent.PayloadAgent",
    "burp": "agents.burp_agent.BurpAgent",
    "ad": "agents.ad_agent.ADAgent",
    "xss_exploit": "agents.xss_agent.XSSExploitAgent",
}


def load_agent(agent_name: str, model_client) -> BaseAgent:
    if agent_name not in AGENT_REGISTRY:
        raise ValueError(f"Unknown agent: {agent_name}")
    import importlib
    module_path, class_name = AGENT_REGISTRY[agent_name].rsplit(".", 1)
    mod = importlib.import_module(module_path)
    cls: Type[BaseAgent] = getattr(mod, class_name)
    return cls(model_client)
