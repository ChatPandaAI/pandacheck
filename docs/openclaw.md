# PandaCheck and OpenClaw's native security audit

OpenClaw has a first-party security audit:

```bash
openclaw security audit
openclaw security audit --deep
openclaw security audit --fix
openclaw security audit --json
```

Its native audit is the right first tool for OpenClaw-specific runtime security. It understands OpenClaw internals and currently covers a much broader surface than PandaCheck v0.1.0, including filesystem permissions, gateway/auth exposure, channel policy, tool/exec policy, plugins and skills, cross-agent visibility, model hygiene, and optional deep runtime probes.

Official references:

- https://docs.openclaw.ai/gateway/security/running-the-audit
- https://docs.openclaw.ai/gateway/security/audit-checks

## Why keep PandaCheck?

PandaCheck is moving toward a different layer: **portable policy-as-code around agent configuration**.

The intended distinction is:

| OpenClaw native audit | PandaCheck direction |
| --- | --- |
| first-party OpenClaw runtime knowledge | cross-runtime policy layer |
| OpenClaw-specific security checks | organization/project governance checks |
| can probe live OpenClaw state | static/pre-deploy CI by default |
| OpenClaw check IDs and fixes | stable portable finding/policy schema |
| built into OpenClaw | external tool that can compare different agent stacks |

A future PandaCheck policy might express expectations such as:

- this project must remain local-model-only;
- no agent may gain wildcard tool access;
- these agents must have separate execution boundaries;
- cloud fallback requires an explicit exception;
- config changes must not increase a declared capability baseline.

Those are governance policies rather than claims that OpenClaw itself failed to audit a security issue.

## v0.1.0

The eight v0.1.0 OpenClaw-oriented checks remain useful as a small external/static baseline and as fixtures for developing the adapter architecture. They should not be presented as a replacement for `openclaw security audit`.

## Principle

When a framework's native security tooling is stronger for framework-specific checks, PandaCheck should say so and integrate or complement it rather than pretending otherwise.
