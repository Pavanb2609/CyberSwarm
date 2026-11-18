"""Registry tests — every attack tool must load and validate."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.attack_registry as ar


def test_supported_actions_include_new_tools():
    actions = set(ar.supported_actions())
    assert {"XSS_SCAN", "SQLI_SCAN", "CONTENT_DISCOVERY", "CORS_SCAN"} <= actions


def test_all_registered_tools_load():
    for name in ar.ATTACK_TOOL_MODULES:
        t = ar.load_attack_tool(name)
        assert t.name == name
        assert t.capability


def test_get_tools_for_action_returns_tool_instances():
    tools = ar.get_tools_for_action("VULN_SCAN")
    assert tools
    assert tools[0].capability == "VULN_SCAN"
