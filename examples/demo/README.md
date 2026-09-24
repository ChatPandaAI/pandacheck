# PandaCheck 60-second demo

All files here are synthetic.

From the repository root:

```bash
python -m pip install -e .
pandacheck init /tmp/pandacheck.policy.json5
pandacheck diff \
  examples/demo/baseline.openclaw.json5 \
  examples/demo/candidate.openclaw.json5 \
  --policy /tmp/pandacheck.policy.json5
```

The candidate deliberately introduces two configuration changes:

- a remote fallback behind a local primary model;
- wildcard tool access.

With the starter policy's default `fail_on: "high"`, PandaCheck reports both changes but CI fails because the wildcard tool finding is high severity.

The point is not that this synthetic configuration represents every agent runtime. The point is that PandaCheck can establish a baseline and block newly introduced policy drift without forcing a team to erase every historical warning first.
