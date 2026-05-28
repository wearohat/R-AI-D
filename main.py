import sys

from collectors.alienvault import fetch as alienvault_fetch
from collectors.urlscan import fetch as urlscan_fetch
from collectors.wayback import fetch as wayback_fetch

from collectors.aggregator import save_subdomains

from enrichers.resolver import resolve
from enrichers.internetdb import fetch as internetdb_fetch

from ai.analyzer import analyze_all

from utils.logger import logger

def main(domain):
    logger.info(f"Starting enumeration for: {domain}")

    all_subdomains = set()

    all_subdomains.update(alienvault_fetch(domain))
    all_subdomains.update(urlscan_fetch(domain))
    all_subdomains.update(wayback_fetch(domain))

    subdomains = save_subdomains(all_subdomains)

    for subdomain in subdomains:
        ip = resolve(subdomain)

        if not ip:
            continue

        internetdb_fetch(ip, subdomain)

    analyze_all()

    logger.info("Pipeline completed successfully")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py example.com")
        sys.exit(1)

    domain = sys.argv[1]

    main(domain)

