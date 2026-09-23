# Regression mode

PandaCheck regression mode answers:

> Did this candidate configuration introduce a new active finding compared with the baseline?

```bash
pandacheck diff baseline.json5 candidate.json5 --fail-on high
```

With a project policy:

```bash
pandacheck diff baseline.json5 candidate.json5 \
  --policy pandacheck.policy.json5 \
  --format json
```

## What is compared

Findings are identified by:

- rule ID; and
- canonicalized **safe finding evidence**.

PandaCheck does not diff or print the raw configuration as part of regression classification.

Results are grouped as:

- `introduced`
- `resolved`
- `unchanged`

Policy-accepted findings are tracked separately and remain visible.

## CI behavior

Regression mode applies the failure threshold to **introduced active findings only**.

This is deliberate. A team can start using PandaCheck on a project with known existing findings and immediately prevent new high-severity drift without first fixing every historical warning.

## Privacy

The same reporting boundary applies as normal scans: rules must not place raw credentials into evidence. PC006, for example, reports credential-like configuration paths rather than values.
