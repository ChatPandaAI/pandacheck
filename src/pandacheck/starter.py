from __future__ import annotations

from pathlib import Path

DEFAULT_POLICY_PATH = "pandacheck.policy.json5"


class InitError(ValueError):
    pass


def render_policy(adapter: str = "openclaw", fail_on: str = "high") -> str:
    return f'''{{
  // PandaCheck project policy, schema version 1.
  version: 1,

  // Adapter used when --adapter is not supplied.
  adapter: "{adapter}",

  // CI fails only for active findings at or above this severity.
  fail_on: "{fail_on}",

  // Accepted findings stay visible in reports and require a reason.
  exceptions: [
    // {{
    //   rule: "PC001",
    //   reason: "Approved remote fallback for this project's availability requirement."
    // }}
  ]
}}
'''


def write_policy(
    path: str | Path = DEFAULT_POLICY_PATH,
    *,
    adapter: str = "openclaw",
    fail_on: str = "high",
    force: bool = False,
) -> Path:
    output = Path(path)
    if output.exists() and not force:
        raise InitError(f"Refusing to overwrite existing file: {output}")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_policy(adapter=adapter, fail_on=fail_on), encoding="utf-8")
    return output
