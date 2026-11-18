"""
Maps Phase 2 attack actions to tool wrappers.
Mirrors tools/registry.py exactly — same load_tool / get_tools_for pattern.

Adding a new attack tool = write a wrapper + add one line here. Nothing else changes.
"""

import importlib
from typing import Dict, List, Optional

from tools.base import Tool

# attack_action -> ordered list of tool names to try (first available wins)
ATTACK_TOOL_MAP: Dict[str, List[str]] = {
    "VULN_SCAN":             ["nuclei", "nmap_nse"],
    "WEB_VULN_SCAN":         ["nikto"],
    "SERVICE_VULN_SCAN":     ["nmap_nse"],
    "EXPLOIT_SEARCH":        ["searchsploit"],
    "TLS_VULN_SCAN":         ["testssl", "sslyze"],
    "XSS_SCAN":              ["dalfox", "nuclei_xss"],
    "SQLI_SCAN":             ["sqlmap", "nuclei_sqli"],
    "CONTENT_DISCOVERY":     ["feroxbuster", "ffuf"],
    "CORS_SCAN":             ["corsy"],
    "AUTH_PROBE":            ["auth_probe"],
    "API_PROBE":             ["api_probe"],
    "SSRF_SCAN":             ["nuclei_ssrf"],
    "LFI_SCAN":              ["nuclei_lfi"],
    "SSTI_SCAN":             ["nuclei_ssti"],
    "OPEN_REDIRECT_SCAN":    ["nuclei_redirect"],
    "CMD_INJECTION_SCAN":    ["nuclei_cmdi", "commix"],
    "EXPOSED_PANELS_SCAN":   ["nuclei_panels"],
    "DEFAULT_CRED_SCAN":     ["nuclei_defaultlogin"],
    "MISCONFIG_SCAN":        ["nuclei_misconfig"],
    "SUBDOMAIN_TAKEOVER_SCAN": ["nuclei_takeover", "subjack"],
    "HOST_HEADER_ATTACK":    ["nuclei_hostheader", "host_header"],
    "CLICKJACKING_TEST":     ["clickjack", "nuclei_clickjack"],
    "SECRETS_SCAN":          ["nuclei_exposure"],
    "WAF_DETECT":            ["wafw00f", "nuclei_wafdetect"],
    "JWT_ANALYSIS":          ["jwt_tool"],
    "HTTP_METHOD_TEST":      ["http_methods"],
    "XXE_SCAN":              ["xxe", "nuclei_xxe"],
    "CRLF_INJECTION_SCAN":   ["crlf", "nuclei_crlf"],
    "CSRF_SCAN":             ["csrf"],
    "FILE_UPLOAD_SCAN":      ["file_upload"],
    "DESERIALIZATION_SCAN":  ["deserialization", "nuclei_deserialization"],
    "WAF_BYPASS_TEST":       ["waf_bypass_payloads"],
    "SESSION_FIXATION":      ["session_fixation"],
    "SESSION_HIJACK":        ["session_hijack"],
    # --- credentialed testing (engagement context) ---
    "LOGIN_FILL":           ["login_fill"],
    "LOGIN_BRUTE":          ["login_brute"],
    "DEFAULT_CRED_CHECK":   ["default_creds_check", "nuclei_defaultlogin"],
    "IDOR_TEST":            ["idor_test"],
    "SSTI_EXPLOIT":          ["ssti_exploit"],
    "LFI_EXPLOIT":           ["lfi_exploit"],
    "SSRF_EXPLOIT":          ["ssrf_exploit"],
    "JWT_EXPLOIT":           ["jwt_exploit"],
    # --- Burp Suite Professional active scanner (REST API) ---
    "BURP_SCAN":             ["burp_scan"],
    "ACTIVE_SCAN":           ["zap_scan"],
    "XSS_PROOF":             ["xss_proof"],
    # --- PayloadAgent: generation + delivery with recorded proof ---
    "PAYLOAD_GENERATION":    ["payload_gen"],
    "PAYLOAD_PROBE":         ["payload_probe"],
    # --- OWASP Top-10 exploitation coverage ---
    "NOSQL_INJECTION_SCAN":  ["nosql_inj"],
    "LDAP_INJECTION_SCAN":   ["ldap_inj"],
    # --- Active Directory exploitation (OWASP A02/A07-adjacent) ---
    "AD_ASREP_ROAST":        ["asrep_roast"],
    "AD_KERBEROAST":         ["kerberoast"],
    "SMB_NULL_SESSION":      ["smb_nullsess"],
}

ATTACK_TOOL_MODULES: Dict[str, tuple] = {
    "nuclei":           ("tools.attack.nuclei",        "NucleiTool"),
    "nikto":            ("tools.attack.nikto",          "NiktoTool"),
    "nmap_nse":         ("tools.attack.nmap_nse",       "NmapNSETool"),
    "searchsploit":     ("tools.attack.searchsploit",   "SearchsploitTool"),
    "testssl":          ("tools.tls.testssl",           "TestSSLTool"),
    "dalfox":           ("tools.attack.dalfox",         "DalfoxTool"),
    "sqlmap":           ("tools.attack.sqlmap",         "SqlmapTool"),
    "feroxbuster":      ("tools.attack.feroxbuster",    "FeroxbusterTool"),
    "corsy":            ("tools.attack.corsy",          "CorsyTool"),
    "auth_probe":       ("tools.attack.auth_probe",     "AuthProbeTool"),
    "api_probe":        ("tools.attack.api_probe",      "ApiProbeTool"),
    # --- expanded attack surface (Phase: capabilities) ---
    "nuclei_ssrf":       ("tools.attack.nuclei_tags",    "SSRFScanTool"),
    "nuclei_lfi":        ("tools.attack.nuclei_tags",    "LFIScanTool"),
    "nuclei_ssti":       ("tools.attack.nuclei_tags",    "SSTIScanTool"),
    "nuclei_redirect":   ("tools.attack.nuclei_tags",    "OpenRedirectScanTool"),
    "nuclei_cmdi":       ("tools.attack.nuclei_tags",    "CmdInjectionScanTool"),
    "nuclei_xss":        ("tools.attack.nuclei_tags",    "XSSScanTool"),
    "nuclei_sqli":       ("tools.attack.nuclei_tags",    "SQLiScanTool"),
    "nuclei_panels":     ("tools.attack.nuclei_tags",    "ExposedPanelsScanTool"),
    "nuclei_defaultlogin": ("tools.attack.nuclei_tags",  "DefaultCredScanTool"),
    "nuclei_misconfig":  ("tools.attack.nuclei_tags",    "MisconfigScanTool"),
    "nuclei_takeover":   ("tools.attack.nuclei_tags",    "SubdomainTakeoverScanTool"),
    "nuclei_hostheader": ("tools.attack.nuclei_tags",    "HostHeaderScanTool"),
    "nuclei_clickjack":  ("tools.attack.nuclei_tags",    "ClickjackingScanTool"),
    "nuclei_exposure":   ("tools.attack.nuclei_tags",    "SecretsScanTool"),
    "nuclei_wafdetect":  ("tools.attack.nuclei_tags",    "WafDetectScanTool"),
    "sslyze":            ("tools.attack.sslyze",         "SSLyzeTool"),
    "ffuf":              ("tools.content.ffuf",          "FFUFTool"),
    "wafw00f":           ("tools.attack.wafw00f",        "Wafw00fTool"),
    "subjack":           ("tools.attack.subjack",        "SubjackTool"),
    "jwt_tool":          ("tools.attack.jwt_tool",       "JwtTool"),
    "commix":            ("tools.attack.commix",         "CommixTool"),
    "http_methods":      ("tools.attack.http_methods",   "HttpMethodTestTool"),
    "clickjack":         ("tools.attack.clickjacking",   "ClickjackingTool"),
    "host_header":       ("tools.attack.host_header",    "HostHeaderAttackTool"),
    "xxe":               ("tools.attack.xxe",            "XXEScanTool"),
    "nuclei_xxe":        ("tools.attack.nuclei_tags",    "XXEScanNucleiTag"),
    "crlf":              ("tools.attack.crlf",           "CRLFInjectionTool"),
    "nuclei_crlf":       ("tools.attack.nuclei_tags",    "CRLFInjectionNucleiTag"),
    "csrf":              ("tools.attack.csrf",           "CSRFScanTool"),
    "file_upload":       ("tools.attack.file_upload",    "FileUploadScanTool"),
    "deserialization":   ("tools.attack.deserialization","DeserializationScanTool"),
    "nuclei_deserialization": ("tools.attack.nuclei_tags", "DeserializationNucleiTag"),
    "waf_bypass_payloads": ("tools.attack.waf_bypass_payloads", "WafBypassTool"),
    "session_fixation":    ("tools.attack.session_fixation", "SessionFixationTool"),
    "session_hijack":      ("tools.attack.session_hijack", "SessionHijackTool"),
    "login_fill":          ("tools.attack.login_fill", "LoginFillTool"),
    "login_brute":         ("tools.attack.login_brute", "LoginBruteTool"),
    "default_creds_check": ("tools.attack.default_creds_check", "DefaultCredsCheckTool"),
    "idor_test":           ("tools.attack.idor_test", "IDORTestTool"),
    "ssti_exploit":        ("tools.attack.ssti", "SSTIExploitTool"),
    "lfi_exploit":         ("tools.attack.lfi", "LFIExploitTool"),
    "ssrf_exploit":        ("tools.attack.ssrf", "SSRFExploitTool"),
    "jwt_exploit":         ("tools.attack.jwt_exploit", "JWTExploitTool"),
    "burp_scan":           ("tools.attack.burp_scan",   "BurpScanTool"),
    "zap_scan":            ("tools.attack.zap_scan",    "ZAPScanTool"),
    "xss_proof":           ("tools.attack.xss_proof",   "XSSProofTool"),
    "payload_gen":         ("tools.attack.payload_gen", "PayloadGenTool"),
    "payload_probe":       ("tools.attack.payload_probe", "PayloadProbeTool"),
    "nosql_inj":           ("tools.attack.nosql_inj",   "NoSQLInjectionTool"),
    "ldap_inj":            ("tools.attack.ldap_inj",    "LDAPInjectionTool"),
    "asrep_roast":         ("tools.directory.ad_exploit", "ASRepRoastTool"),
    "kerberoast":          ("tools.directory.ad_exploit", "KerberoastTool"),
    "smb_nullsess":        ("tools.directory.ad_exploit", "SMBNullSessionTool"),
}


def load_attack_tool(tool_name: str) -> Tool:
    if tool_name not in ATTACK_TOOL_MODULES:
        raise ValueError(f"Unknown attack tool: {tool_name}")
    module_path, class_name = ATTACK_TOOL_MODULES[tool_name]
    module = importlib.import_module(module_path)
    return getattr(module, class_name)()


def get_tools_for_action(action: str) -> List[Tool]:
    tool_names = ATTACK_TOOL_MAP.get(action, [])
    tools = []
    for name in tool_names:
        try:
            tools.append(load_attack_tool(name))
        except Exception as e:
            print(f"[attack_registry] Could not load {name}: {e}")
    return tools


def supported_actions() -> List[str]:
    return sorted(ATTACK_TOOL_MAP.keys())


def preferred_tool_for(action: str) -> Optional[str]:
    tools = ATTACK_TOOL_MAP.get(action, [])
    return tools[0] if tools else None
