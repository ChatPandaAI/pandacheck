# Quickstart

## Install the current release

Python 3.11+:

```bash
python -m pip install https://github.com/ChatPandaAI/pandacheck/archive/refs/tags/v0.2.0.tar.gz
```

PandaCheck is distributed through GitHub Releases, not PyPI.

## Current release: scan and diff

```bash
pandacheck scan openclaw.json --fail-on high
```

```bash
pandacheck diff baseline.json5 candidate.json5 --fail-on high
```

## Next patch / source checkout: initialize policy

The source tree includes `pandacheck init`, which will ship in the next patch release:

```bash
pandacheck init
```

It creates `pandacheck.policy.json5` and refuses to overwrite an existing file unless `--force` is supplied.

Until that patch is tagged, you can copy [the example policy](../examples/pandacheck.policy.json5).

## GitHub Actions

See [GitHub Actions](github-actions.md) for a pull-request regression gate.
