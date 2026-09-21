from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pandacheck.models import Finding
from pandacheck.rules import OPENCLAW_RULES


def scan_config(config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in OPENCLAW_RULES:
        findings.extend(rule(config))
    return sorted(findings, key=lambda item: (-int(item.severity), item.rule_id))


def serialize_findings(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in findings]
