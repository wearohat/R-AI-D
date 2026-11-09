import json
import os

from ai.providers import PROVIDERS, ProviderConfig, default_config
from config.settings import OUTPUT_DIR

SETTINGS_FILE = OUTPUT_DIR / "gui_settings.json"

INTEL_KEY_ENV = {
    "shodan": "SHODAN_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
}


def load_settings():
    settings = {"provider": "ollama", "remember_keys": False, "timeout": 300, "providers": {}, "intel_keys": {}}
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r") as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                settings.update({k: v for k, v in stored.items() if k in settings})
        except (OSError, ValueError):
            pass
    for name in PROVIDERS:
        base = default_config(name)
        stored = settings["providers"].get(name) or {}
        settings["providers"][name] = {
            "model": stored.get("model") or base.model,
            "base_url": stored.get("base_url") or base.base_url,
            "api_key": stored.get("api_key") or base.api_key,
        }
    stored_keys = settings.get("intel_keys") or {}
    settings["intel_keys"] = {
        name: stored_keys.get(name) or os.getenv(env, "").strip() for name, env in INTEL_KEY_ENV.items()
    }
    if settings["provider"] not in PROVIDERS:
        settings["provider"] = "ollama"
    return settings


def save_settings(settings):
    data = json.loads(json.dumps(settings))
    if not data.get("remember_keys"):
        for provider in data["providers"].values():
            provider["api_key"] = ""
        data["intel_keys"] = {name: "" for name in data.get("intel_keys") or {}}
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=4)


def config_from_settings(settings, provider=None):
    name = provider or settings["provider"]
    values = settings["providers"][name]
    return ProviderConfig(
        provider=name,
        model=values["model"].strip(),
        base_url=values["base_url"].strip(),
        api_key=values["api_key"].strip(),
        timeout=int(settings.get("timeout") or 300),
    )
