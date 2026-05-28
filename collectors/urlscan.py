import requests
from utils.logger import logger
from utils.helpers import is_valid_subdomain

def fetch(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"

    try:
        response = requests.get(url, timeout=15)
        data = response.json()

        subs = set()

        for result in data.get("results", []):
            page = result.get("page", {})
            hostname = page.get("domain")

            if hostname and is_valid_subdomain(hostname, domain):
                subs.add(hostname)

        logger.info(f"[URLScan] Found {len(subs)} subdomains")

        return subs

    except Exception as e:
        logger.error(f"[URLScan] Error: {e}")
        return set()
