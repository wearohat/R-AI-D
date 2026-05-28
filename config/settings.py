import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "output"
EVIDENCE_DIR = OUTPUT_DIR / "evidence"

ALL_SUBDOMAINS_FILE = OUTPUT_DIR / "all_subdomains.txt"
PRIORITIZED_TARGETS_FILE = OUTPUT_DIR / "prioritized_targets.json"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:3b"
)
REQUEST_TIMEOUT = 15

