# Changelog

All notable changes to PandaCheck will be documented here.

## [Unreleased]

### Added

- `pandacheck init` starter policy generator with overwrite protection;
- synthetic 60-second regression demo;
- copyable GitHub Actions pull-request workflow;
- adapter request issue form.

### Changed

- README rewritten around install, policy initialization, regression, and CI adoption.

## [0.2.0] - 2026-09-23

### Added

- adapter registry and explicit adapter metadata;
- versioned JSON output schema;
- configurable CI severity thresholds via `--fail-on`;
- JSON5 project policy files with reason-required exceptions;
- auditable suppressed findings instead of silent ignores;
- regression `diff` mode that classifies introduced, resolved, and unchanged findings;
- regression CI failure based on newly introduced findings only.

## [0.1.0] - 2026-09-21

First public pre-alpha milestone.

### Added

- local-first JSON5 configuration scanner and `pandacheck scan` CLI;
- human-readable and JSON output;
- deterministic exit codes for CI use;
- eight initial OpenClaw-oriented checks:
  - PC001 local primary with non-local fallback;
  - PC002 dangerous tools explicitly allowed while sandboxing is off;
  - PC003 shared sandbox scope;
  - PC004 writable sandbox workspace;
  - PC005 wildcard tool allow-list;
  - PC006 possible inline secret values, with value redaction;
  - PC007 gateway binding broader than loopback;
  - PC008 wildcard agent delegation;
- synthetic fixtures and realistic bounded/over-broad dogfood configurations;
- tests protecting credential redaction;
- Python 3.11/3.12 GitHub Actions CI;
- rule reference, contribution guidelines, and security/privacy policy.

### Notes

PandaCheck 0.1.0 is pre-alpha. Findings identify configuration patterns, not compromise or non-compliance. A clean scan is not a security certification.
