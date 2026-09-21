from pathlib import Path

from pandacheck.config import load_config
from pandacheck.scanner import scan_config

FIXTURES = Path(__file__).parent / "fixtures"


def ids(name: str) -> list[str]:
    return [finding.rule_id for finding in scan_config(load_config(FIXTURES / name))]


def test_safe_config_has_no_findings():
    assert ids("safe.json5") == []


def test_local_to_cloud_fallback():
    assert ids("cloud_fallback.json5") == ["PC001"]


def test_unsandboxed_dangerous_tools():
    assert ids("unsandboxed_exec.json5") == ["PC002"]


def test_shared_scope():
    assert ids("shared_scope.json5") == ["PC003"]
