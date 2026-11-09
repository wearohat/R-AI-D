import os
import time

import requests

from enrichers.intel_store import IntelError, http_error
from utils.logger import logger

URL = "https://www.virustotal.com/api/v3/domains/{domain}"
REQUESTS_PER_MINUTE = int(os.getenv("VIRUSTOTAL_REQUESTS_PER_MINUTE", "4"))

_last_call = 0.0


def _wait_for_quota():
    global _last_call
    if REQUESTS_PER_MINUTE > 0:
        delay = 60.0 / REQUESTS_PER_MINUTE - (time.monotonic() - _last_call)
        if delay > 0:
            time.sleep(delay)
    _last_call = time.monotonic()


def summarize(data):
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    flagged = sorted(v for v, r in results.items() if r.get("category") in ("malicious", "suspicious"))
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "vendors_total": sum(v for v in stats.values() if isinstance(v, int)),
        "flagged_by": flagged,
        "reputation": attributes.get("reputation"),
        "categories": sorted(set((attributes.get("categories") or {}).values())),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "note": "Zero detections means no vendor flags it, not that it is safe.",
    }


def fetch(domain, api_key):
    _wait_for_quota()
    try:
        response = requests.get(URL.format(domain=domain), headers={"x-apikey": api_key}, timeout=20)
    except requests.exceptions.RequestException as e:
        raise IntelError(f"VirusTotal: {e}")
    if response.status_code == 404:
        logger.info(f"[VirusTotal] No report for {domain}")
        return None
    if response.status_code != 200:
        raise http_error("VirusTotal", response)
    result = summarize(response.json())
    logger.info(f"[VirusTotal] {domain}: {result['malicious']} malicious, {result['suspicious']} suspicious "
                f"of {result['vendors_total']} vendors")
    return result
