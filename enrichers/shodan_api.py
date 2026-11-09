import requests

from enrichers.intel_store import IntelError, http_error
from utils.logger import logger

URL = "https://api.shodan.io/shodan/host/{ip}"


def summarize(data):
    services = []
    vulns = set(data.get("vulns") or [])
    cpes = set()
    for banner in data.get("data") or []:
        services.append({
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "product": banner.get("product"),
            "version": banner.get("version"),
            "module": (banner.get("_shodan") or {}).get("module"),
        })
        if isinstance(banner.get("vulns"), dict):
            vulns.update(banner["vulns"].keys())
        cpes.update(banner.get("cpe") or [])
    return {
        "ip": data.get("ip_str"),
        "ports": sorted(set(data.get("ports") or [])),
        "hostnames": data.get("hostnames") or [],
        "org": data.get("org"),
        "isp": data.get("isp"),
        "os": data.get("os"),
        "country": data.get("country_name"),
        "last_update": data.get("last_update"),
        "services": services,
        "cpes": sorted(cpes),
        "vulns": sorted(vulns),
        "tags": data.get("tags") or [],
    }


def fetch(ip, api_key):
    try:
        response = requests.get(URL.format(ip=ip), params={"key": api_key}, timeout=20)
    except requests.exceptions.RequestException as e:
        raise IntelError(f"Shodan: {e}")
    if response.status_code == 404:
        logger.info(f"[Shodan] No data for {ip}")
        return None
    if response.status_code != 200:
        raise http_error("Shodan", response)
    result = summarize(response.json())
    logger.info(f"[Shodan] {ip}: {len(result['services'])} services, {len(result['vulns'])} CVEs")
    return result
