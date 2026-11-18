"""
Maps planner capabilities (e.g. "PORT_DISCOVERY") to the tool wrapper(s)
that can fulfill them, in preference order. The planner never sees tool
names -- it only ever emits a capability, and this registry resolves which
tool actually runs.

Adding a new tool = write a wrapper + add one line here. Nothing else
in the pipeline needs to change.
"""

import importlib

from tools.base import Tool

# capability -> ordered list of tool names to try (first available wins)
CAPABILITY_TOOL_MAP: dict[str, list[str]] = {
    "SUBDOMAIN_DISCOVERY": ["subfinder", "amass"],
    "PASSIVE_ASSET_DISCOVERY": ["amass", "subfinder"],
    "DNS_RESOLUTION": ["dns_resolve"],
    "DNS_ENUMERATION": ["dns_enum"],
    "HOST_DISCOVERY": ["nmap_host_discovery"],
    "PORT_DISCOVERY": ["naabu", "nmap"],
    "SERVICE_DETECTION": ["nmap"],
    "OPERATING_SYSTEM_IDENTIFICATION": ["nmap_os_detect"],
    "WEB_PROBING": ["httpx"],
    "WEB_TECHNOLOGY_DISCOVERY": ["whatweb"],
    "WEB_CRAWLING": ["katana"],
    "CONTENT_DISCOVERY": ["ffuf"],
    "SENSITIVE_ENDPOINT_DETECTION": ["sensitive_endpoint_detect"],
    "PARAMETER_DISCOVERY": ["arjun"],
    "JAVASCRIPT_ANALYSIS": ["linkfinder"],
    "HISTORICAL_URL_DISCOVERY": ["gau", "waybackurls"],
    "API_ENDPOINT_DISCOVERY": ["api_discover"],
    "CMS_IDENTIFICATION": ["cms_identify"],
    "CMS_ASSESSMENT": ["wpscan"],
    "SCREENSHOT_CAPTURE": ["gowitness"],
    "DIRECTORY_SERVICE_ENUMERATION": ["ldap_enum"],
    "WINDOWS_SERVICE_ENUMERATION": ["smb_enum"],
    "CLOUD_ASSET_DISCOVERY": ["cloud_enum"],
    "S3_LIST": ["s3_enum"],
    "CONTAINER_DISCOVERY": ["container_probe"],
    "IOT_SERVICE_IDENTIFICATION": ["iot_probe"],
    "TLS_ANALYSIS": ["testssl", "tls_analysis"],
    "HEADER_ANALYSIS": ["header_analysis"],
    "DESERIALIZATION_DETECTION": ["deserialization_detect"],
    "UPLOAD_FORM_DETECTION": ["upload_form_detect"],
    "CSRF_SURFACE_DETECTION": ["csrf_surface_detect"],
    "COOKIE_ANALYSIS": ["cookie_analyzer"],
    "GRAPHQL_INTROSPECTION": ["graphql_introspection"],
    "ROBOTS_TXT_ANALYSIS": ["robots_txt"],
    "CERT_INFO": ["cert_info"],
    "SENSITIVE_ENDPOINT_DETECTION": ["sensitive_endpoint_detect"],
    "SESSION_ANALYSIS": ["session_analyzer"],
    "AUTH_FLOW_ANALYSIS": ["auth_flow_analysis"],
}

# tool name -> (module path, class name)
TOOL_MODULES: dict[str, tuple] = {
    "subfinder": ("tools.passive.subfinder", "SubfinderTool"),
    "amass": ("tools.passive.amass", "AmassTool"),
    "dns_resolve": ("tools.dns.dns_resolve", "DNSResolutionTool"),
    "dns_enum": ("tools.dns.dns_enum", "DNSEnumTool"),
    "nmap_host_discovery": ("tools.portscan.host_discovery", "HostDiscoveryTool"),
    "naabu": ("tools.portscan.naabu", "NaabuTool"),
    "nmap": ("tools.portscan.nmap", "NmapTool"),
    "nmap_os_detect": ("tools.portscan.os_identify", "OSIdentificationTool"),
    "httpx": ("tools.web.httpx", "HttpxTool"),
    "whatweb": ("tools.web.whatweb", "WhatWebTool"),
    "katana": ("tools.web.katana", "KatanaTool"),
    "ffuf": ("tools.content.ffuf", "FFUFTool"),
    "arjun": ("tools.params.arjun", "ArjunTool"),
    "linkfinder": ("tools.javascript.linkfinder", "LinkFinderTool"),
    "gau": ("tools.web.gau", "GauTool"),
    "waybackurls": ("tools.web.waybackurls", "WaybackURLsTool"),
    "api_discover": ("tools.api.api_discover", "APIDiscoverTool"),
    "cms_identify": ("tools.cms.cms_identify", "CMSIdentifyTool"),
    "wpscan": ("tools.cms.wpscan", "WPScanTool"),
    "gowitness": ("tools.screenshots.gowitness", "GowitnessTool"),
    "ldap_enum": ("tools.directory.ldap_enum", "DirectoryServiceEnumerationTool"),
    "smb_enum": ("tools.directory.smb_enum", "WindowsServiceEnumerationTool"),
    "cloud_enum": ("tools.cloud.cloud_enum", "CloudAssetDiscoveryTool"),
    "s3_enum": ("tools.cloud.s3_enum", "S3EnumTool"),
    "container_probe": ("tools.container.container_probe", "ContainerDiscoveryTool"),
    "iot_probe": ("tools.iot.iot_probe", "IoTServiceIdentificationTool"),
    "testssl": ("tools.tls.testssl", "TestSSLTool"),
    "tls_analysis": ("tools.tls.tls_analysis", "TLSAnalysisTool"),
    "header_analysis": ("tools.web.header_analysis", "HeaderAnalysisTool"),
    "deserialization_detect": ("tools.recon.deserialization_detect", "DeserializationDetectionTool"),
    "upload_form_detect": ("tools.recon.upload_form_detect", "UploadFormDetectionTool"),
    "csrf_surface_detect": ("tools.recon.csrf_surface_detect", "CSRFSurfaceDetectionTool"),
    "cookie_analyzer": ("tools.recon.cookie_analyzer", "CookieAnalyzerTool"),
    "graphql_introspection": ("tools.recon.graphql_introspection", "GraphQLIntrospectionTool"),
    "robots_txt": ("tools.recon.robots_txt_parser", "RobotsTxtParserTool"),
    "cert_info": ("tools.recon.cert_info", "CertInfoTool"),
    "sensitive_endpoint_detect": ("tools.recon.sensitive_endpoint_detect", "SensitiveEndpointDetectTool"),
    "session_analyzer": ("tools.recon.session_analyzer", "SessionAnalyzerTool"),
    "auth_flow_analysis": ("tools.recon.auth_flow_analysis", "AuthFlowAnalysisTool"),
}


def load_tool(tool_name: str) -> Tool:
    if tool_name not in TOOL_MODULES:
        raise ValueError(f"Unknown tool: {tool_name}")
    module_path, class_name = TOOL_MODULES[tool_name]
    module = importlib.import_module(module_path)
    tool_class = getattr(module, class_name)
    return tool_class()


def get_tools_for_capability(capability: str) -> list[Tool]:
    tool_names = CAPABILITY_TOOL_MAP.get(capability, [])
    return [load_tool(name) for name in tool_names]


def supported_capabilities() -> list[str]:
    return sorted(CAPABILITY_TOOL_MAP.keys())


def preferred_tool_for(capability: str) -> str | None:
    """Return the first tool name registered for a capability, or None."""
    tools = CAPABILITY_TOOL_MAP.get(capability, [])
    return tools[0] if tools else None
