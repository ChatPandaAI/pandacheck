# Quickstart

## Install the current release

Python 3.11+:

```bash
python -m pip install https://github.com/ChatPandaAI/pandacheck/archive/refs/tags/v0.2.1.tar.gz
```

PandaCheck is distributed through GitHub Releases, not PyPI.

## Scan and diff

```bash
pandacheck scan openclaw.json --fail-on high
```

```bash
pandacheck diff baseline.json5 candidate.json5 --fail-on high
```

## Initialize project policy

```bash
pandacheck init
```

It creates `pandacheck.policy.json5` and refuses to overwrite an existing file unless `--force` is supplied.

## GitHub Actions

See [GitHub Actions](github-actions.md) for a pull-request regression gate.
