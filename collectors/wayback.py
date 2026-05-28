import requests
import re

from utils.logger import logger

def fetch(domain):
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"

    try:
        response = requests.get(url, timeout=15)

        data = response.json()

        subs = set()

        for row in data[1:]:
            if len(row) > 2:
                value = row[2]

                matches = re.findall(
                    rf"([a-zA-Z0-9._-]+\.{re.escape(domain)})",
                    value
                )

                subs.update(matches)

        logger.info(f"[Wayback] Found {len(subs)} subdomains")

        return subs

    except Exception as e:
        logger.error(f"[Wayback] Error: {e}")
        return set()

