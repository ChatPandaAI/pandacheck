from pathlib import Path

import pytest

from pandacheck.config import load_config
from pandacheck.policy import PolicyError, apply_policy, load_policy
from pandacheck.scanner import scan_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_policy_loads_explicit_exception():
    policy = load_policy(FIXTURES / "policy_accept_cloud.json5")
    assert policy.adapter == "openclaw"
    assert policy.fail_on == "high"
    assert policy.exceptions[0].rule_id == "PC001"


def test_policy_exception_requires_reason():
    with pytest.raises(PolicyError, match="reason"):
        load_policy(FIXTURES / "policy_bad_exception.json5")


def test_policy_suppression_remains_auditable():
    policy = load_policy(FIXTURES / "policy_accept_cloud.json5")
    findings = scan_config(load_config(FIXTURES / "cloud_fallback.json5"))
    active, suppressed = apply_policy(findings, policy)
    assert active == []
    assert len(suppressed) == 1
    assert suppressed[0].finding.rule_id == "PC001"
    assert "Approved availability fallback" in suppressed[0].reason
