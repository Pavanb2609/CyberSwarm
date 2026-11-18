"""
Nuclei tag-driven attack wrappers.

Each new attack capability maps to a thin subclass of NucleiTool that pins a
capability name and a default -tags set. This gives us broad, template-driven
coverage (SSRF/LFI/SSTI/redirect/panels/default-logins/takeover/misconfig/...)
without any new binaries or parsing code.

Adding a capability = one subclass + one line in attack_registry.py.
"""

from typing import Any, Dict, List

from tools.attack.nuclei import NucleiTool


class _NucleiTag(NucleiTool):
    """Base: inject a default tag set unless the caller overrides it."""
    default_tags: str = ""
    name: str = "nuclei_tag"
    capability: str = "VULN_SCAN"

    def build_command(self, target: str, **kwargs) -> List[str]:
        kwargs.setdefault("tags", self.default_tags)
        return super().build_command(target, **kwargs)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        data = super().parse(stdout, stderr)
        data["capability"] = self.capability
        return data


class SSRFScanTool(_NucleiTag):
    name = "nuclei_ssrf"
    capability = "SSRF_SCAN"
    default_tags = "ssrf"
    binary = "nuclei"


class LFIScanTool(_NucleiTag):
    name = "nuclei_lfi"
    capability = "LFI_SCAN"
    default_tags = "lfi"
    binary = "nuclei"


class SSTIScanTool(_NucleiTag):
    name = "nuclei_ssti"
    capability = "SSTI_SCAN"
    default_tags = "ssti"
    binary = "nuclei"


class OpenRedirectScanTool(_NucleiTag):
    name = "nuclei_redirect"
    capability = "OPEN_REDIRECT_SCAN"
    default_tags = "redirect"
    binary = "nuclei"


class CmdInjectionScanTool(_NucleiTag):
    name = "nuclei_cmdi"
    capability = "CMD_INJECTION_SCAN"
    default_tags = "command-injection"
    binary = "nuclei"


class XSSScanTool(_NucleiTag):
    name = "nuclei_xss"
    capability = "XSS_SCAN"
    default_tags = "xss"
    binary = "nuclei"


class SQLiScanTool(_NucleiTag):
    name = "nuclei_sqli"
    capability = "SQLI_SCAN"
    default_tags = "sqli"
    binary = "nuclei"


class ExposedPanelsScanTool(_NucleiTag):
    name = "nuclei_panels"
    capability = "EXPOSED_PANELS_SCAN"
    default_tags = "exposed-panels"
    binary = "nuclei"


class DefaultCredScanTool(_NucleiTag):
    name = "nuclei_defaultlogin"
    capability = "DEFAULT_CRED_SCAN"
    default_tags = "default-login"
    binary = "nuclei"


class MisconfigScanTool(_NucleiTag):
    name = "nuclei_misconfig"
    capability = "MISCONFIG_SCAN"
    default_tags = "misconfig"
    binary = "nuclei"


class SubdomainTakeoverScanTool(_NucleiTag):
    name = "nuclei_takeover"
    capability = "SUBDOMAIN_TAKEOVER_SCAN"
    default_tags = "takeover"
    binary = "nuclei"


class HostHeaderScanTool(_NucleiTag):
    name = "nuclei_hostheader"
    capability = "HOST_HEADER_ATTACK"
    default_tags = "host-header"
    binary = "nuclei"


class ClickjackingScanTool(_NucleiTag):
    name = "nuclei_clickjack"
    capability = "CLICKJACKING_TEST"
    default_tags = "clickjacking"
    binary = "nuclei"


class SecretsScanTool(_NucleiTag):
    name = "nuclei_exposure"
    capability = "SECRETS_SCAN"
    default_tags = "exposure,secrets"
    binary = "nuclei"


class WafDetectScanTool(_NucleiTag):
    name = "nuclei_wafdetect"
    capability = "WAF_DETECT"
    default_tags = "waf-detect"
    binary = "nuclei"


class XXEScanNucleiTag(_NucleiTag):
    name = "nuclei_xxe"
    capability = "XXE_SCAN"
    default_tags = "xxe"
    binary = "nuclei"


class CRLFInjectionNucleiTag(_NucleiTag):
    name = "nuclei_crlf"
    capability = "CRLF_INJECTION_SCAN"
    default_tags = "crlf"
    binary = "nuclei"


class DeserializationNucleiTag(_NucleiTag):
    name = "nuclei_deserialization"
    capability = "DESERIALIZATION_SCAN"
    default_tags = "deserialization"
    binary = "nuclei"
