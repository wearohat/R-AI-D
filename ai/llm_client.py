import requests

from config.settings import OLLAMA_URL, OLLAMA_MODEL
from utils.logger import logger

def ask_llm(prompt):
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        data = response.json()

        return data.get("response", "")

    except Exception as e:
        logger.error(f"[LLM] Error: {e}")
        return None

