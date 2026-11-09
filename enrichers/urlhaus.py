import requests

from enrichers.intel_store import IntelError, http_error
from utils.logger import logger

URL = "https://urlhaus-api.abuse.ch/v1/host/"


def summarize(data):
    urls = data.get("urls") or []
    return {
        "listed": bool(urls),
        "url_count": len(urls),
        "online": sum(1 for u in urls if u.get("url_status") == "online"),
        "threats": sorted({u.get("threat") for u in urls if u.get("threat")}),
        "urls": [
            {
                "url": u.get("url"),
                "status": u.get("url_status"),
                "threat": u.get("threat"),
                "tags": u.get("tags") or [],
                "date_added": u.get("date_added"),
            }
            for u in urls[:20]
        ],
        "blacklists": data.get("blacklists") or {},
    }


def fetch(host, api_key):
    try:
        response = requests.post(URL, data={"host": host}, headers={"Auth-Key": api_key}, timeout=20)
    except requests.exceptions.RequestException as e:
        raise IntelError(f"URLhaus: {e}")
    if response.status_code != 200:
        raise http_error("URLhaus", response)
    data = response.json()
    status = data.get("query_status")
    if status == "no_results":
        logger.info(f"[URLhaus] {host}: not listed")
        return summarize({})
    if status != "ok":
        raise IntelError(f"URLhaus: {status}")
    result = summarize(data)
    logger.info(f"[URLhaus] {host}: {result['url_count']} malware URL(s), {result['online']} online")
    return result
