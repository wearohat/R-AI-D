import json
from collections import Counter
from dataclasses import dataclass, field

from config.settings import EVIDENCE_DIR, PRIORITIZED_TARGETS_FILE
from enrichers.intel_store import load_all
from gui.pipeline import current_subdomains, load_summary

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2082: "cPanel", 2083: "cPanel",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9200: "Elasticsearch", 10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
}


@dataclass
class ScanData:
    summary: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    results: list = field(default_factory=list)


def load_results():
    if not PRIORITIZED_TARGETS_FILE.exists():
        return []
    try:
        with open(PRIORITIZED_TARGETS_FILE, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return [r for r in data if isinstance(r, dict) and r.get("subdomain")] if isinstance(data, list) else []


def load_scan_data():
    subdomains = current_subdomains()
    if not subdomains and EVIDENCE_DIR.exists():
        subdomains_for_evidence = [path.stem.replace("_", ".") for path in sorted(EVIDENCE_DIR.glob("*.json"))]
    else:
        subdomains_for_evidence = subdomains
    evidence = {s: r for s in subdomains_for_evidence if (r := load_all(s))}
    known = set(subdomains) or set(evidence)
    results = [r for r in load_results() if r["subdomain"] in known]
    return ScanData(summary=load_summary(), subdomains=subdomains, evidence=evidence, results=results)


def score_of(result):
    try:
        return float(result.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def top_results(data, limit=10):
    return sorted(data.results, key=lambda r: (-score_of(r), r["subdomain"]))[:limit]


def score_distribution(data):
    counts = Counter(int(round(score_of(r))) for r in data.results if not r.get("parse_error"))
    return [(score, counts.get(score, 0)) for score in range(0, 11)]


def _merged(record, key):
    values = set()
    for source in ("internetdb", "shodan"):
        values.update((record.get(source) or {}).get(key) or [])
    return values


def _ip(record, subdomain):
    for source in ("internetdb", "shodan"):
        ip = (record.get(source) or {}).get("ip")
        if ip:
            return ip
    return subdomain


def _hosts(data):
    hosts = {}
    for subdomain, record in data.evidence.items():
        host = hosts.setdefault(_ip(record, subdomain), {"ports": set(), "cpes": set()})
        host["ports"].update(_merged(record, "ports"))
        host["cpes"].update(_merged(record, "cpes"))
    return hosts


def port_exposure(data, limit=12):
    counts = Counter()
    for host in _hosts(data).values():
        for port in host["ports"]:
            counts[port] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [(f"{p} ({WELL_KNOWN_PORTS[p]})" if p in WELL_KNOWN_PORTS else str(p), n) for p, n in ranked]


def vulnerable_subdomains(data, limit=10):
    rows = [(s, len(_merged(r, "vulns"))) for s, r in data.evidence.items()]
    rows = [r for r in rows if r[1] > 0]
    return sorted(rows, key=lambda item: (-item[1], item[0]))[:limit]


def _technology(cpe):
    parts = cpe.replace("cpe:2.3:", "cpe:/").split(":")
    if len(parts) >= 4:
        return parts[3].replace("_", " ")
    return cpe


def technologies(data, limit=10):
    counts = Counter()
    for host in _hosts(data).values():
        for tech in {_technology(c) for c in host["cpes"]}:
            counts[tech] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def vt_detections(record):
    vt = record.get("virustotal") or {}
    return (vt.get("malicious") or 0) + (vt.get("suspicious") or 0)


def urlhaus_urls(record):
    return (record.get("urlhaus") or {}).get("url_count") or 0


def virustotal_flagged(data, limit=10):
    rows = [(s, vt_detections(r)) for s, r in data.evidence.items() if vt_detections(r)]
    return sorted(rows, key=lambda item: (-item[1], item[0]))[:limit]


def urlhaus_listed(data, limit=10):
    rows = [(s, urlhaus_urls(r)) for s, r in data.evidence.items() if urlhaus_urls(r)]
    return sorted(rows, key=lambda item: (-item[1], item[0]))[:limit]


def mitre_rows(data):
    return [(f"{t['id']} {t['name']}", t["records"]) for t in data.summary.get("mitre") or []]


def coverage(data):
    summary = data.summary
    found = summary.get("found", len(data.subdomains))
    rows = [("Subdomains found", found)]
    if "resolved" in summary:
        rows.append(("Resolved to an IP", summary["resolved"]))
    rows.append(("With host or threat data", len(data.evidence)))
    rows.append(("Analysed by AI", len(data.results)))
    return rows
