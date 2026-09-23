# 🐼 PandaCheck

**Portable policy checks for AI-agent configuration. Local-first, deterministic, and CI-friendly.**

PandaCheck is an early open-source project from [ChatPandaAI](https://github.com/ChatPandaAI). It turns agent-governance expectations into checks that can run repeatedly against configuration before risky changes reach a live agent.

> Current release: **v0.1.0 pre-alpha**. `main` is now **v0.2.0.dev0**. PandaCheck is not a compliance certification and does not prove that an agent is safe.

## What PandaCheck is becoming

PandaCheck started as an OpenClaw configuration scanner. OpenClaw now ships a comprehensive native `openclaw security audit`, so PandaCheck is **not** trying to replace it.

For OpenClaw runtime security, use the native audit first.

PandaCheck's direction is broader:

- portable **policy-as-code** for agent configurations;
- deterministic checks that can run in CI before deployment;
- project/team policy packs;
- config-change regression checks;
- consistent findings across multiple agent runtimes;
- local-only operation for the core scanner.

OpenClaw remains the first adapter because it gives us a real, documented configuration surface to test against.

See [OpenClaw positioning and overlap](docs/openclaw.md).

## Why

A good prompt can explain agent-security principles. A useful tool should do more: inspect concrete configuration, identify specific policy drift, show safe evidence, and return deterministic output that automation can act on.

PandaCheck is intended to stay:

- **local-first** — core scans run on your machine
- **deterministic first** — no LLM required for baseline checks
- **explainable** — findings include evidence and remediation
- **privacy-respecting** — no telemetry or config upload in the core scanner
- **inspectable** — baseline rules live in the public repository
- **portable** — policy should not be trapped inside one agent runtime

## Try v0.1.0

Python 3.11+:

```bash
python -m pip install https://github.com/ChatPandaAI/pandacheck/archive/refs/tags/v0.1.0.tar.gz
pandacheck --version
```

Scan an OpenClaw-style JSON5 config:

```bash
pandacheck scan ~/.openclaw/openclaw.json
```

Machine-readable output:

```bash
pandacheck scan ~/.openclaw/openclaw.json --format json
```

Exit codes in v0.1.0:

- `0` — scan completed with no findings
- `1` — scan completed with one or more findings
- `2` — invalid invocation or unreadable/unparseable configuration

## v0.2 development on `main`

The development branch now adds:

- explicit adapter metadata (`--adapter openclaw`);
- versioned JSON output schema;
- configurable CI thresholds;
- project policy files with reviewable, reason-required exceptions;
- regression mode that fails only on newly introduced findings.

Example CI gate:

```bash
pandacheck scan openclaw.json --fail-on high
```

Project policy:

```bash
pandacheck scan openclaw.json --policy examples/pandacheck.policy.json5
```

Regression gate:

```bash
pandacheck diff baseline.json5 candidate.json5 --fail-on high
```

The diff command can tolerate known historical findings while blocking newly introduced high-severity drift. See [project policy](docs/policy.md) and [regression mode](docs/regression.md).

## v0.1 baseline rules

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

These checks are deliberately narrow. PandaCheck should prefer a small number of defensible findings over a large number of guesses.

See [the rule reference](docs/rules.md) for trigger conditions and legitimate-use/false-positive notes.

## Example

```text
[WARNING] PC001  Local model can fall back to a remote provider
          The primary model is local, but a configured fallback appears non-local...
          Evidence: {"primary": "ollama/llama3.2:3b", "remote_fallbacks": ["openai/gpt-5.6-luna"]}
```

## Development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

## Development principles

1. Findings must be tied to concrete configuration evidence.
2. Every baseline rule needs deterministic tests.
3. Expected false positives must be documented.
4. No config or secret leaves the machine during a core scan.
5. A quiet scan must never be described as proof that a system is secure.
6. Public examples must use synthetic or explicitly cleared data.
7. Framework-native security tooling should be recommended when it is stronger for that framework.

## Roadmap

The v0.2 milestone moves from an OpenClaw-specific scanner toward portable policy-as-code:

- ✅ configurable CI severity thresholds;
- ✅ project policy files with explicit exceptions;
- ✅ adapter architecture for multiple agent runtimes;
- ✅ config-diff regression checks;
- reusable policy packs;
- ✅ stable machine-readable finding schema.

If PandaCheck eventually has paid offerings, the intent is to charge for maintained convenience — richer remediation, maintained policy packs, integrations, continuous scanning, team workflows, or support — not to intentionally cripple the open-source core.

## Privacy boundary

PandaCheck's public repository uses synthetic examples and fixtures. Do **not** submit real credentials, private archives, personal paths, customer data, or unredacted production configuration in issues or examples.

The core scanner runs locally. Suspected inline secrets detected by `PC006` are reported by **configuration path only**; the value itself is intentionally omitted from findings.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See `LICENSE`.

---

Built under the **ChatPandaAI** project. Red Panda is the ChatGPT-side collaborator; PandaClaw is the local autonomous runtime used in related experiments.
