# 🐼 PandaCheck

**Local-first checks for risky AI-agent configuration boundaries.**

PandaCheck is an early open-source scanner from [ChatPandaAI](https://github.com/ChatPandaAI). It turns security and governance advice into deterministic checks you can run repeatedly against real agent configuration.

> Status: **pre-alpha / v0.1 development**. PandaCheck is not a compliance certification and does not prove that an agent is safe.

## Why

A good prompt can explain agent-security principles. A useful tool should do more: inspect a concrete configuration, identify specific risky boundaries, show the evidence that triggered each finding, and produce output that can be tested in CI.

PandaCheck is intended to stay:

- **local-first** — core scans run on your machine
- **deterministic first** — no LLM is needed for baseline rules
- **explainable** — every finding includes evidence and remediation
- **privacy-respecting** — no telemetry or config upload in the core scanner
- **inspectable** — rules live in the public repository

## Current target

The first target is the OpenClaw JSON5 configuration format (`openclaw.json`). OpenClaw supports model fallback chains, sandbox configuration, tool policies, and multi-agent sandbox scopes; PandaCheck starts with those documented boundaries.

## First rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `PC001` | warning | local primary model with a non-local fallback |
| `PC002` | high | explicitly allowed dangerous tools while default sandboxing is off |
| `PC003` | warning | shared sandbox scope across agents |

These rules are deliberately narrow. PandaCheck should prefer a small number of defensible findings over a large number of guesses.

## Install for development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run

```bash
pandacheck scan ~/.openclaw/openclaw.json
```

Machine-readable output:

```bash
pandacheck scan ~/.openclaw/openclaw.json --format json
```

Exit codes:

- `0` — scan completed with no findings
- `1` — scan completed with one or more findings
- `2` — invalid invocation or unreadable/unparseable configuration

## Example

```text
[WARNING] PC001  Local model can fall back to a remote provider
          The primary model is local, but at least one configured fallback appears to use a non-local provider...
          Evidence: {"primary": "ollama/llama3.2:3b", "remote_fallbacks": ["openai/gpt-5.6-luna"]}
```

## Development principles

1. Findings must be tied to concrete configuration evidence.
2. Every rule needs fixtures and deterministic tests.
3. Rules should document expected false-positive conditions.
4. No config or secret leaves the machine during a core scan.
5. We do not label a system "secure" just because PandaCheck is quiet.
6. Public examples must use synthetic or explicitly cleared data.

## Roadmap

Near-term candidates include narrow checks for filesystem scope, cross-agent/session visibility, privileged execution, secret placement, unrestricted delegation, browser/network exposure, and recurring autonomous jobs without explicit operational bounds.

The core scanner will remain useful and public. If PandaCheck eventually has paid offerings, the intent is to charge for maintained convenience—such as richer remediation, policy packs, integrations, continuous scanning, team workflows, or support—not to intentionally cripple the open-source core.

## License

Apache-2.0. See `LICENSE`.

---

Built under the **ChatPandaAI** project. Red Panda is the ChatGPT-side collaborator; PandaClaw is the local autonomous runtime used in related experiments.


## Privacy boundary

PandaCheck's public repository uses synthetic examples and fixtures. Do **not** submit real credentials, private archives, personal paths, customer data, or unredacted production configuration in issues or examples.

The core scanner runs locally. Suspected inline secrets detected by `PC006` are reported by **configuration path only**; the value itself is intentionally omitted from findings.

See [the rule reference](docs/rules.md) for trigger conditions and expected false positives.
