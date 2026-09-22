# PandaCheck rule reference

PandaCheck findings are intentionally narrow. A finding means the documented configuration pattern was observed; it does **not** mean the deployment is compromised or non-compliant.

| ID | Severity | Trigger | Common legitimate case |
|---|---|---|---|
| PC001 | warning | local primary model plus non-local fallback | intentionally permitted emergency cloud fallback |
| PC002 | high | dangerous tools explicitly allowed while default sandbox is off | tightly controlled host agent that deliberately requires host access |
| PC003 | warning | sandbox scope is `shared` | agents intentionally cooperating in one shared environment |
| PC004 | warning | sandbox workspace access is writable | coding/build agent intentionally modifying its own workspace |
| PC005 | high | tool allow-list contains `*` or `all` | short-lived isolated test environment |
| PC006 | high | credential-like key contains an inline string | synthetic fixture or non-secret value with an unfortunately secret-looking key |
| PC007 | warning | gateway bind appears broader than loopback | authenticated service intentionally exposed on a trusted network |
| PC008 | warning | delegation allow-list contains `*` | controlled lab where every registered agent is intentionally reachable |

## Evidence safety

PC006 reports **paths only**, never the suspected secret value. Rule implementations should avoid including credential material in evidence, error output, fixtures, or test snapshots.

## Rule acceptance bar

Before a rule enters the baseline set it should have:

1. a concrete configuration path or documented behavior;
2. a clear risk statement;
3. evidence that explains why it fired;
4. remediation that does not pretend there is one universally correct architecture;
5. at least one positive fixture;
6. a reasonable clean/negative case;
7. documented false-positive conditions.
