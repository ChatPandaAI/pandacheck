from pathlib import Path

from pandacheck.config import load_config
from pandacheck.scanner import scan_config

FIXTURES = Path(__file__).parent / "fixtures"


def findings(name: str):
    return scan_config(load_config(FIXTURES / name))


def ids(name: str) -> list[str]:
    return [finding.rule_id for finding in findings(name)]


def test_safe_config_has_no_findings():
    assert ids("safe.json5") == []


def test_local_to_cloud_fallback():
    assert ids("cloud_fallback.json5") == ["PC001"]


def test_unsandboxed_dangerous_tools():
    assert ids("unsandboxed_exec.json5") == ["PC002"]


def test_shared_scope():
    assert ids("shared_scope.json5") == ["PC003"]


def test_writable_workspace():
    assert ids("writable_workspace.json5") == ["PC004"]


def test_wildcard_tools():
    assert ids("wildcard_tools.json5") == ["PC005"]


def test_embedded_secret_redacts_value():
    result = findings("embedded_secret.json5")
    assert [item.rule_id for item in result] == ["PC006"]
    assert result[0].evidence == {"paths": ["gateway.auth.token"]}
    assert "synthetic-not-a-real-secret" not in str(result[0].to_dict())


def test_network_gateway():
    assert ids("network_gateway.json5") == ["PC007"]


def test_wildcard_delegation():
    assert ids("wildcard_delegation.json5") == ["PC008"]
