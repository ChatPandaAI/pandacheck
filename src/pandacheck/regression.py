from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from pandacheck.models import Finding


def finding_key(finding: Finding) -> tuple[str, str]:
    evidence = json.dumps(finding.evidence, sort_keys=True, separators=(",", ":"))
    return finding.rule_id, evidence


@dataclass(frozen=True)
class FindingDiff:
    introduced: tuple[Finding, ...]
    resolved: tuple[Finding, ...]
    unchanged: tuple[Finding, ...]

    def to_dict(self) -> dict:
        return {
            "introduced": [item.to_dict() for item in self.introduced],
            "resolved": [item.to_dict() for item in self.resolved],
            "unchanged": [item.to_dict() for item in self.unchanged],
        }


def diff_findings(
    baseline: Iterable[Finding],
    candidate: Iterable[Finding],
) -> FindingDiff:
    baseline_map = {finding_key(item): item for item in baseline}
    candidate_map = {finding_key(item): item for item in candidate}

    baseline_keys = set(baseline_map)
    candidate_keys = set(candidate_map)

    introduced = tuple(
        sorted(
            (candidate_map[key] for key in candidate_keys - baseline_keys),
            key=lambda item: (-int(item.severity), item.rule_id, finding_key(item)[1]),
        )
    )
    resolved = tuple(
        sorted(
            (baseline_map[key] for key in baseline_keys - candidate_keys),
            key=lambda item: (-int(item.severity), item.rule_id, finding_key(item)[1]),
        )
    )
    unchanged = tuple(
        sorted(
            (candidate_map[key] for key in candidate_keys & baseline_keys),
            key=lambda item: (-int(item.severity), item.rule_id, finding_key(item)[1]),
        )
    )

    return FindingDiff(
        introduced=introduced,
        resolved=resolved,
        unchanged=unchanged,
    )
