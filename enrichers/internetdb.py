import json
import requests

from config.settings import EVIDENCE_DIR
from utils.logger import logger
from utils.helpers import sanitize_filename

def fetch(ip, subdomain):
    url = f"https://internetdb.shodan.io/{ip}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            logger.warning(f"[InternetDB] No data for {subdomain}")
            return None

        data = response.json()

        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

        filename = sanitize_filename(subdomain) + ".json"

        filepath = EVIDENCE_DIR / filename

        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)

        logger.info(f"[InternetDB] Saved evidence for {subdomain}")

        return data

    except Exception as e:
        logger.error(f"[InternetDB] Error for {subdomain}: {e}")
        return None

