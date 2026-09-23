from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pandacheck.adapters import ADAPTERS
from pandacheck.models import Finding


class AdapterError(ValueError):
    pass


def scan_config(config: dict[str, Any], adapter_name: str = "openclaw") -> list[Finding]:
    try:
        adapter = ADAPTERS[adapter_name]
    except KeyError as exc:
        raise AdapterError(f"Unknown adapter: {adapter_name}") from exc

    findings = adapter.scan(config)
    return sorted(findings, key=lambda item: (-int(item.severity), item.rule_id))


def serialize_findings(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in findings]
