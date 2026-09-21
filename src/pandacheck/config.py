from __future__ import annotations

from pathlib import Path
from typing import Any

import json5


class ConfigError(ValueError):
    pass


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        data = json5.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # parser errors vary by json5 version
        raise ConfigError(f"Could not parse {config_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError("Top-level config must be an object")

    return data
