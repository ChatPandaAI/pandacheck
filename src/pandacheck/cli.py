from __future__ import annotations

import argparse
import json
import sys

from pathlib import Path

from pandacheck import __version__
from pandacheck.adapters import ADAPTERS
from pandacheck.config import ConfigError, load_config
from pandacheck.models import Severity
from pandacheck.policy import Policy, PolicyError, SuppressedFinding, apply_policy, load_policy
from pandacheck.regression import FindingDiff, diff_findings
from pandacheck.scanner import scan_config, serialize_findings
from pandacheck.starter import DEFAULT_POLICY_PATH, InitError, write_policy

SCHEMA_VERSION = "1"

FAIL_THRESHOLDS = {
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "high": Severity.HIGH,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pandacheck",
        description="Portable policy checks for AI-agent configuration.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a starter PandaCheck policy file")
    init.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_POLICY_PATH,
        help=f"Policy path to create (default: {DEFAULT_POLICY_PATH}).",
    )
    init.add_argument(
        "--adapter",
        choices=tuple(sorted(ADAPTERS)),
        default="openclaw",
        help="Adapter to record in the starter policy (default: openclaw).",
    )
    init.add_argument(
        "--fail-on",
        choices=("info", "warning", "high", "never"),
        default="high",
        help="CI threshold to record in the starter policy (default: high).",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing policy file.",
    )

    scan = subparsers.add_parser("scan", help="Scan one agent configuration")
    scan.add_argument("path", help="Path to an adapter-supported configuration file")
    _add_common_scan_args(scan)

    diff = subparsers.add_parser(
        "diff",
        help="Compare baseline and candidate configs and report newly introduced findings",
    )
    diff.add_argument("baseline", help="Baseline configuration")
    diff.add_argument("candidate", help="Candidate configuration")
    _add_common_scan_args(diff)

    return parser


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--adapter",
        choices=tuple(sorted(ADAPTERS)),
        default=None,
        help="Configuration adapter. Policy adapter is used when omitted; otherwise defaults to openclaw.",
    )
    parser.add_argument(
        "--policy",
        default=None,
        help="Optional PandaCheck JSON5 policy file.",
    )
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument(
        "--fail-on",
        choices=("info", "warning", "high", "never"),
        default=None,
        help="CI failure threshold. Overrides policy; default is info.",
    )


def _load_policy(path: str | None) -> Policy | None:
    if path is None:
        return None
    return load_policy(path)


def _resolve_options(
    cli_adapter: str | None,
    cli_fail_on: str | None,
    policy: Policy | None,
) -> tuple[str, str]:
    if cli_adapter and policy and policy.adapter and cli_adapter != policy.adapter:
        raise PolicyError(
            f"CLI adapter '{cli_adapter}' conflicts with policy adapter '{policy.adapter}'"
        )
    adapter = cli_adapter or (policy.adapter if policy else None) or "openclaw"
    fail_on = cli_fail_on or (policy.fail_on if policy else None) or "info"
    return adapter, fail_on


def _should_fail(findings, threshold: str) -> bool:
    if threshold == "never":
        return False
    minimum = FAIL_THRESHOLDS[threshold]
    return any(item.severity >= minimum for item in findings)


def _print_findings(findings) -> None:
    for finding in findings:
        print(f"[{finding.severity.label.upper():7}] {finding.rule_id}  {finding.title}")
        print(f"          {finding.message}")
        print(f"          Evidence: {json.dumps(finding.evidence, sort_keys=True)}")
        print(f"          Fix: {finding.remediation}")
        print()


def _print_suppressed(suppressed: list[SuppressedFinding]) -> None:
    if not suppressed:
        return
    print(f"Accepted by policy: {len(suppressed)}")
    for item in suppressed:
        print(f"[ACCEPTED] {item.finding.rule_id}  {item.finding.title}")
        print(f"           Reason: {item.reason}")
    print()


def _print_scan_human(findings, suppressed, adapter_name: str, fail_on: str) -> None:
    print(f"PandaCheck adapter: {adapter_name}")
    print(f"CI threshold: {fail_on}")
    if findings:
        _print_findings(findings)
    else:
        print("✓ No active PandaCheck findings.")
    _print_suppressed(suppressed)

    high = sum(1 for item in findings if item.severity >= Severity.HIGH)
    warning = sum(1 for item in findings if item.severity == Severity.WARNING)
    info = sum(1 for item in findings if item.severity == Severity.INFO)
    print(
        f"PandaCheck: {len(findings)} active finding(s) — "
        f"{high} high, {warning} warning, {info} info; "
        f"{len(suppressed)} accepted by policy"
    )


def _scan_payload(adapter: str, fail_on: str, findings, suppressed) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "pandacheck_version": __version__,
        "mode": "scan",
        "adapter": adapter,
        "fail_on": fail_on,
        "findings": serialize_findings(findings),
        "suppressed_findings": [item.to_dict() for item in suppressed],
    }


def _diff_payload(
    adapter: str,
    fail_on: str,
    result: FindingDiff,
    baseline_suppressed,
    candidate_suppressed,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "pandacheck_version": __version__,
        "mode": "diff",
        "adapter": adapter,
        "fail_on": fail_on,
        **result.to_dict(),
        "baseline_suppressed_findings": [item.to_dict() for item in baseline_suppressed],
        "candidate_suppressed_findings": [item.to_dict() for item in candidate_suppressed],
    }


def _run_scan(args, policy: Policy | None, adapter: str, fail_on: str) -> int:
    config = load_config(args.path)
    raw_findings = scan_config(config, adapter_name=adapter)
    findings, suppressed = apply_policy(raw_findings, policy)

    if args.format == "json":
        print(json.dumps(_scan_payload(adapter, fail_on, findings, suppressed), indent=2))
    else:
        _print_scan_human(findings, suppressed, adapter, fail_on)

    return 1 if _should_fail(findings, fail_on) else 0


def _run_diff(args, policy: Policy | None, adapter: str, fail_on: str) -> int:
    baseline_config = load_config(args.baseline)
    candidate_config = load_config(args.candidate)

    baseline_raw = scan_config(baseline_config, adapter_name=adapter)
    candidate_raw = scan_config(candidate_config, adapter_name=adapter)
    baseline_findings, baseline_suppressed = apply_policy(baseline_raw, policy)
    candidate_findings, candidate_suppressed = apply_policy(candidate_raw, policy)

    result = diff_findings(baseline_findings, candidate_findings)

    if args.format == "json":
        print(
            json.dumps(
                _diff_payload(
                    adapter,
                    fail_on,
                    result,
                    baseline_suppressed,
                    candidate_suppressed,
                ),
                indent=2,
            )
        )
    else:
        print(f"PandaCheck adapter: {adapter}")
        print(f"CI threshold: {fail_on}")
        if result.introduced:
            print(f"Introduced findings: {len(result.introduced)}")
            _print_findings(result.introduced)
        else:
            print("✓ No new active findings introduced.")
        if result.resolved:
            print(f"Resolved findings: {len(result.resolved)}")
            for finding in result.resolved:
                print(f"[RESOLVED] {finding.rule_id}  {finding.title}")
            print()
        print(f"Unchanged findings: {len(result.unchanged)}")
        _print_suppressed(candidate_suppressed)

    return 1 if _should_fail(result.introduced, fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "init":
        try:
            output = write_policy(
                args.path,
                adapter=args.adapter,
                fail_on=args.fail_on,
                force=args.force,
            )
        except (InitError, OSError) as exc:
            print(f"pandacheck: {exc}", file=sys.stderr)
            return 2
        print(f"Created PandaCheck policy: {output}")
        print(f"Next: pandacheck scan YOUR_CONFIG --policy {output}")
        return 0

    try:
        policy = _load_policy(args.policy)
        adapter, fail_on = _resolve_options(args.adapter, args.fail_on, policy)
        if args.command == "scan":
            return _run_scan(args, policy, adapter, fail_on)
        if args.command == "diff":
            return _run_diff(args, policy, adapter, fail_on)
        return 2
    except (ConfigError, PolicyError) as exc:
        print(f"pandacheck: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
