"""Config persistence."""

import json
from pathlib import Path

CONFIG_PATH = Path.home() / ".agentcanary" / "config.json"


def load() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            pass
    return {}


def save(data: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2))


def get_api_key() -> str:
    return load().get("api_key", "")


def set_api_key(key: str):
    cfg = load()
    cfg["api_key"] = key
    save(cfg)
