import requests
from utils.logger import logger
from utils.helpers import is_valid_subdomain

def fetch(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns"

    try:
        response = requests.get(url, timeout=15)
        data = response.json()

        subs = set()

        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")

            if hostname and is_valid_subdomain(hostname, domain):
                subs.add(hostname)

        logger.info(f"[AlienVault] Found {len(subs)} subdomains")

        return subs

    except Exception as e:
        logger.error(f"[AlienVault] Error: {e}")
        return set()

