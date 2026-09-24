from pathlib import Path

from pandacheck.config import load_config
from pandacheck.regression import diff_findings
from pandacheck.scanner import scan_config

ROOT = Path(__file__).parents[1]
DEMO = ROOT / "examples" / "demo"


def test_public_demo_introduces_expected_drift():
    baseline = scan_config(load_config(DEMO / "baseline.openclaw.json5"))
    candidate = scan_config(load_config(DEMO / "candidate.openclaw.json5"))
    result = diff_findings(baseline, candidate)

    assert baseline == []
    assert {item.rule_id for item in result.introduced} == {"PC001", "PC005"}
    assert result.resolved == ()
