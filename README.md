# 🐼 PandaCheck

**Portable policy checks for AI-agent configuration. Local-first, deterministic, and CI-friendly.**

PandaCheck turns agent-governance expectations into repeatable checks that can run before a risky configuration change reaches a live agent.

> Current release: **v0.2.0 pre-alpha**. The core scanner has no telemetry. A quiet scan is not a security certification.

## Why use it?

A framework-native audit can tell you whether a configuration looks unsafe **today**. PandaCheck adds a project-policy layer:

- fail CI only when a finding crosses your chosen severity threshold;
- record explicit, reason-required exceptions instead of silently hiding them;
- compare a baseline with a candidate and block **newly introduced** drift;
- keep the same policy/output shape as more runtime adapters are added.

OpenClaw is the first adapter. For OpenClaw-specific runtime security, use `openclaw security audit` first; PandaCheck is meant to complement it, not replace it.

## Install

Python 3.11+:

```bash
python -m pip install https://github.com/ChatPandaAI/pandacheck/archive/refs/tags/v0.2.0.tar.gz
```

PandaCheck is currently distributed through **GitHub Releases, not PyPI**.

## 60-second demo

The repository includes a synthetic baseline and a candidate that deliberately adds wildcard tool access and a remote model fallback.

```bash
git clone https://github.com/ChatPandaAI/pandacheck.git
cd pandacheck
python -m pip install -e .

pandacheck init
pandacheck diff \
  examples/demo/baseline.openclaw.json5 \
  examples/demo/candidate.openclaw.json5 \
  --policy pandacheck.policy.json5
```

Expected shape:

```text
Introduced findings: 2
[HIGH   ] PC005  Tool allow-list contains a wildcard
[WARNING] PC001  Local model can fall back to a remote provider
```

The starter policy defaults to `fail_on: "high"`, so the warning remains visible while the high-severity regression fails CI.

## Use it on a project

Create a starter policy:

```bash
pandacheck init
```

Review and commit `pandacheck.policy.json5`, then scan:

```bash
pandacheck scan openclaw.json --policy pandacheck.policy.json5
```

Compare a proposed change with a known baseline:

```bash
pandacheck diff baseline.json5 candidate.json5 \
  --policy pandacheck.policy.json5
```

Machine-readable output is available with `--format json`.

See:

- [Project policy files](docs/policy.md)
- [Regression mode](docs/regression.md)
- [GitHub Actions](docs/github-actions.md)
- [OpenClaw overlap and positioning](docs/openclaw.md)
- [Rule reference](docs/rules.md)

## GitHub Actions

A copyable pull-request workflow lives at [`examples/github-actions/pandacheck.yml`](examples/github-actions/pandacheck.yml).

It reads the base branch's configuration and blocks only newly introduced active findings at or above the configured threshold.

## Current OpenClaw rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `PC001` | warning | local primary model with a non-local fallback |
| `PC002` | high | dangerous tools explicitly allowed while default sandboxing is off |
| `PC003` | warning | shared sandbox scope across agents |
| `PC004` | warning | writable sandbox workspace |
| `PC005` | high | wildcard tool allow-list |
| `PC006` | high | possible inline secret values, without printing the value |
| `PC007` | warning | gateway binding broader than loopback |
| `PC008` | warning | wildcard agent delegation |

Rules are intentionally narrow and deterministic. PandaCheck prefers a small number of defensible findings over a large number of guesses.

## Privacy boundary

PandaCheck's public examples and fixtures are synthetic.

The core scanner does not upload configuration or use analytics. Finding evidence must be safe to print; for example, `PC006` reports credential-like **paths**, not secret values.

Do **not** paste real credentials, personal archives, customer data, or unredacted private production configuration into public issues.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Want another runtime?

Open an **adapter request** with:

- the runtime/project name;
- a link to its public configuration documentation;
- the policy drift you want PandaCheck to detect;
- whether the runtime already has native security/audit tooling.

Demand will determine the next adapter rather than expanding support speculatively.

## Development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

## Product principles

1. Deterministic checks before LLM interpretation.
2. Accepted risk stays visible and requires a reason.
3. Regression mode should let teams prevent new risk without erasing all historical debt first.
4. Framework-native security tooling should be recommended when it is stronger.
5. Public fixtures stay synthetic.
6. The open-source core should remain useful; future paid value, if any, should come from maintained convenience, integrations, workflow, and support.

## License

Apache-2.0. See `LICENSE`.

---

Built under the **ChatPandaAI** project. Red Panda is the ChatGPT-side collaborator; PandaClaw is the local autonomous runtime used in related experiments.
