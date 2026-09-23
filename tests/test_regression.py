from pathlib import Path

from pandacheck.config import load_config
from pandacheck.regression import diff_findings
from pandacheck.scanner import scan_config

FIXTURES = Path(__file__).parent / "fixtures"


def scan(name: str):
    return scan_config(load_config(FIXTURES / name))


def test_diff_detects_introduced_findings():
    result = diff_findings(scan("safe.json5"), scan("realistic_overbroad.json5"))
    ids = {item.rule_id for item in result.introduced}
    assert ids == {"PC001", "PC003", "PC004", "PC005", "PC006", "PC007", "PC008"}
    assert result.resolved == ()
    assert result.unchanged == ()


def test_diff_detects_resolved_findings():
    result = diff_findings(scan("realistic_overbroad.json5"), scan("safe.json5"))
    ids = {item.rule_id for item in result.resolved}
    assert ids == {"PC001", "PC003", "PC004", "PC005", "PC006", "PC007", "PC008"}
    assert result.introduced == ()
