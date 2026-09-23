from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pandacheck.models import Finding

Rule = Callable[[dict[str, Any]], list[Finding]]


@dataclass(frozen=True)
class Adapter:
    name: str
    rules: tuple[Rule, ...]
    description: str

    def scan(self, config: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule(config))
        return findings
