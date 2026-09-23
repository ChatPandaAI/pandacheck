from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import json5

from pandacheck.models import Finding


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyException:
    rule_id: str
    reason: str


@dataclass(frozen=True)
class Policy:
    version: int = 1
    adapter: str | None = None
    fail_on: str | None = None
    exceptions: tuple[PolicyException, ...] = ()


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "reason": self.reason,
        }


def load_policy(path: str | Path) -> Policy:
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError(f"Policy file not found: {policy_path}")

    try:
        raw = json5.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"Could not parse {policy_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("Top-level policy must be an object")

    version = raw.get("version", 1)
    if version != 1:
        raise PolicyError(f"Unsupported policy version: {version}")

    adapter = raw.get("adapter")
    if adapter is not None and not isinstance(adapter, str):
        raise PolicyError("policy.adapter must be a string")

    fail_on = raw.get("fail_on")
    if fail_on is not None and fail_on not in {"info", "warning", "high", "never"}:
        raise PolicyError("policy.fail_on must be one of: info, warning, high, never")

    raw_exceptions = raw.get("exceptions", [])
    if not isinstance(raw_exceptions, list):
        raise PolicyError("policy.exceptions must be a list")

    exceptions: list[PolicyException] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_exceptions):
        if not isinstance(item, dict):
            raise PolicyError(f"policy.exceptions[{index}] must be an object")
        rule_id = item.get("rule")
        reason = item.get("reason")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise PolicyError(f"policy.exceptions[{index}].rule must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"policy.exceptions[{index}].reason must be a non-empty string")
        if rule_id in seen:
            raise PolicyError(f"Duplicate policy exception for rule: {rule_id}")
        seen.add(rule_id)
        exceptions.append(PolicyException(rule_id=rule_id, reason=reason.strip()))

    return Policy(
        version=version,
        adapter=adapter,
        fail_on=fail_on,
        exceptions=tuple(exceptions),
    )


def apply_policy(
    findings: Iterable[Finding],
    policy: Policy | None,
) -> tuple[list[Finding], list[SuppressedFinding]]:
    if policy is None or not policy.exceptions:
        return list(findings), []

    exception_map = {item.rule_id: item.reason for item in policy.exceptions}
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []

    for finding in findings:
        reason = exception_map.get(finding.rule_id)
        if reason is None:
            active.append(finding)
        else:
            suppressed.append(SuppressedFinding(finding=finding, reason=reason))

    return active, suppressed
