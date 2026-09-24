# GitHub Actions

PandaCheck can gate pull requests without uploading agent configuration to PandaCheck or a hosted scanning service. The scan runs inside the repository's GitHub Actions runner.

## 1. Create a policy

After installing PandaCheck:

```bash
pandacheck init
```

Commit `pandacheck.policy.json5` after reviewing its threshold and any explicit exceptions.

## 2. Add the workflow

Copy [the example workflow](../examples/github-actions/pandacheck.yml) to:

```text
.github/workflows/pandacheck.yml
```

The example assumes the agent configuration is committed as `openclaw.json`. Change that path if your project stores it elsewhere.

## 3. What the pull-request gate does

The workflow checks out enough Git history to read the base branch's configuration, then runs:

```bash
pandacheck diff BASELINE CANDIDATE --policy pandacheck.policy.json5 --fail-on high
```

Known baseline findings remain visible but do not fail the pull request. Newly introduced active findings at or above the threshold do.

## First-time configuration files

If the base branch does not yet contain the configuration path, the example workflow will fail while loading its baseline. For that first PR, run a normal scan instead:

```bash
pandacheck scan openclaw.json --policy pandacheck.policy.json5 --fail-on high
```

Once the config exists on the base branch, switch to regression mode.

## Privacy

PandaCheck itself has no telemetry in the core scanner. Remember that GitHub Actions logs are still part of your GitHub environment. PandaCheck rules should emit safe evidence, and credentials should not be committed to repository configuration in the first place.
