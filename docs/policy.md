# Project policy files

PandaCheck v0.2 supports JSON5 project policy files.

Example:

```json5
{
  version: 1,
  adapter: "openclaw",
  fail_on: "high",
  exceptions: [
    {
      rule: "PC001",
      reason: "Approved remote fallback for this project's availability requirement."
    }
  ]
}
```

Use it with:

```bash
pandacheck scan openclaw.json --policy pandacheck.policy.json5
```

## Principles

Policy exceptions are **accepted risk, not hidden risk**.

Every exception requires:

- an exact rule ID;
- a non-empty human-readable reason.

A suppressed finding remains in machine-readable output under `suppressed_findings`, together with its reason.

The command line may override `fail_on`. An explicit CLI adapter must agree with the policy adapter.

## CI threshold

`fail_on` may be `info`, `warning`, `high`, or `never`.

Example: a project may allow existing warnings but fail CI for active high-severity findings.

## Versioning

Policy schema version 1 is intentionally small. Future schema changes must remain explicit rather than silently changing policy meaning.
