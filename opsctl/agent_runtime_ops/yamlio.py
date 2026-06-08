from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: Path, *, default: Any | None = None) -> Any:
    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return {} if data is None else data


def dump_yaml(data: Any) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)

