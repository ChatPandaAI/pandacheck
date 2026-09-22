# Contributing to PandaCheck

Thanks for helping improve PandaCheck.

## Before proposing a rule

A baseline rule should be deterministic and tied to a concrete configuration behavior. Please include:

- the exact configuration path or pattern;
- why the pattern can matter;
- evidence that is safe to print;
- a remediation that acknowledges legitimate use cases;
- a positive synthetic fixture;
- a negative/clean case;
- expected false positives.

## Privacy

Never commit or paste:

- real API keys, tokens, passwords, or credentials;
- private user or customer configuration;
- personal archives or memory exports;
- confidential client material;
- proprietary material you do not have permission to publish.

Use synthetic fixtures.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

All baseline rules should have deterministic tests.
