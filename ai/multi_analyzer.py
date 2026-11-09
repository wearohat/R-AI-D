import json
import re

from ai.prompt_builder import build_prompt
from ai.providers import LLMError, ProviderConfig, ask
from config.settings import PRIORITIZED_TARGETS_FILE
from utils.logger import logger

MAX_CONSECUTIVE_FAILURES = 3


def parse_response(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*", "", text).rstrip("`").strip()
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start:end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _score(value):
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0
    score = max(0.0, min(score, 10.0))
    return int(score) if score.is_integer() else round(score, 1)


def _suggestions(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None and str(v).strip()]
    return [str(value)]


def normalize(parsed, raw, subdomain, config):
    if parsed is None:
        result = {"score": 0, "reason": raw, "suggestions": [], "parse_error": True}
    else:
        result = dict(parsed)
        result["score"] = _score(parsed.get("score"))
        result["reason"] = str(parsed.get("reason") or "")
        result["suggestions"] = _suggestions(parsed.get("suggestions"))
    result["subdomain"] = subdomain
    result["provider"] = config.provider
    result["model"] = config.model
    return result


def analyze_subdomains(items, config: ProviderConfig, progress=None, should_cancel=None):
    results = []
    failed = []
    aborted = None
    consecutive_failures = 0
    total = len(items)

    for index, (subdomain, evidence) in enumerate(items.items(), start=1):
        if should_cancel and should_cancel():
            aborted = "cancelled"
            break
        if progress:
            progress(index, total, subdomain)

        try:
            raw = ask(config, build_prompt(subdomain, evidence))
        except LLMError as e:
            logger.error(f"[AI] {subdomain}: {e}")
            failed.append({"subdomain": subdomain, "error": str(e)})
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                aborted = str(e)
                logger.error(f"[AI] Stopping after {consecutive_failures} failed calls in a row: {e}")
                break
            continue

        consecutive_failures = 0
        results.append(normalize(parse_response(raw), raw, subdomain, config))
        logger.info(f"[AI] Analyzed {subdomain} with {config.label}")

    results.sort(key=lambda r: r.get("score", 0), reverse=True)
    PRIORITIZED_TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PRIORITIZED_TARGETS_FILE, "w") as f:
        json.dump(results, f, indent=4)
    logger.info(f"Saved {len(results)} prioritized results to {PRIORITIZED_TARGETS_FILE}")

    return {"results": results, "failed": failed, "aborted": aborted, "model": config.label}
