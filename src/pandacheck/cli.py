from __future__ import annotations

import argparse
import json
import sys

from pandacheck import __version__
from pandacheck.config import ConfigError, load_config
from pandacheck.models import Severity
from pandacheck.scanner import scan_config, serialize_findings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pandacheck",
        description="Scan AI-agent configs for risky boundaries.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan an OpenClaw-style JSON5 config")
    scan.add_argument("path", help="Path to openclaw.json or another JSON5 config")
    scan.add_argument("--format", choices=("human", "json"), default="human")
    return parser


def _print_human(findings) -> None:
    if not findings:
        print("✓ No PandaCheck findings.")
        return

    for finding in findings:
        print(f"[{finding.severity.label.upper():7}] {finding.rule_id}  {finding.title}")
        print(f"          {finding.message}")
        print(f"          Evidence: {json.dumps(finding.evidence, sort_keys=True)}")
        print(f"          Fix: {finding.remediation}")
        print()

    high = sum(1 for item in findings if item.severity >= Severity.HIGH)
    warning = sum(1 for item in findings if item.severity == Severity.WARNING)
    info = sum(1 for item in findings if item.severity == Severity.INFO)
    print(f"PandaCheck: {len(findings)} finding(s) — {high} high, {warning} warning, {info} info")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command != "scan":
        return 2

    try:
        config = load_config(args.path)
    except ConfigError as exc:
        print(f"pandacheck: {exc}", file=sys.stderr)
        return 2

    findings = scan_config(config)
    if args.format == "json":
        print(json.dumps({"version": __version__, "findings": serialize_findings(findings)}, indent=2))
    else:
        _print_human(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
