import json

from ai.prompt_builder import build_prompt
from ai.llm_client import ask_llm

from config.settings import (
    EVIDENCE_DIR,
    PRIORITIZED_TARGETS_FILE
)

from utils.logger import logger

def analyze_all():
    results = []

    for file in EVIDENCE_DIR.glob("*.json"):

        subdomain = file.stem.replace("_", ".")

        try:
            with open(file, "r") as f:
                evidence = json.load(f)

            prompt = build_prompt(subdomain, evidence)

            response = ask_llm(prompt)

            if not response:
                continue

            try:
                parsed = json.loads(response)

            except:
                parsed = {
                    "score": 0,
                    "reason": response,
                    "suggestions": []
                }

            parsed["subdomain"] = subdomain

            results.append(parsed)

            logger.info(f"[AI] Analyzed {subdomain}")

        except Exception as e:
            logger.error(f"[AI] Failed analyzing {file}: {e}")

    results = sorted(
        results,
        key=lambda x: x.get("score", 0),
        reverse=True
    )

    with open(PRIORITIZED_TARGETS_FILE, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Saved prioritized results")

