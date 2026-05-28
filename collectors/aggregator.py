from config.settings import ALL_SUBDOMAINS_FILE
from utils.logger import logger

def save_subdomains(subdomains):
    unique_subs = sorted(set(subdomains))

    ALL_SUBDOMAINS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(ALL_SUBDOMAINS_FILE, "w") as f:
        for sub in unique_subs:
            f.write(sub + "\n")

    logger.info(f"Saved {len(unique_subs)} subdomains to {ALL_SUBDOMAINS_FILE}")

    return unique_subs

