import json
import re
from datetime import datetime, timezone

from ai.multi_analyzer import analyze_subdomains
from collectors.aggregator import save_subdomains
from collectors.alienvault import fetch as alienvault_fetch
from collectors.urlscan import fetch as urlscan_fetch
from collectors.wayback import fetch as wayback_fetch
from config.settings import ALL_SUBDOMAINS_FILE, OUTPUT_DIR
from enrichers import intel_store, shodan_api, urlhaus, virustotal
from enrichers.internetdb import fetch as internetdb_fetch
from enrichers.intel_store import IntelError
from enrichers.resolver import resolve
from mitre.attack import SOURCE_ACTIVITY, summarize, techniques_for_sources
from utils.logger import logger

SCAN_SUMMARY_FILE = OUTPUT_DIR / "last_scan.json"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

COLLECTORS = [
    ("AlienVault OTX", alienvault_fetch),
    ("URLScan.io", urlscan_fetch),
    ("Wayback Machine", wayback_fetch),
]

INTEL_SOURCES = [
    ("shodan", lambda sub, ip, key: shodan_api.fetch(ip, key)),
    ("virustotal", lambda sub, ip, key: virustotal.fetch(sub, key)),
    ("urlhaus", lambda sub, ip, key: urlhaus.fetch(sub, key)),
]


def normalize_domain(domain):
    return (domain or "").strip().lower().rstrip(".")


def is_valid_domain(domain):
    return bool(DOMAIN_RE.match(normalize_domain(domain)))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_summary():
    if not SCAN_SUMMARY_FILE.exists():
        return {}
    try:
        with open(SCAN_SUMMARY_FILE, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_summary(summary):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(SCAN_SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=4)


def current_subdomains():
    if not ALL_SUBDOMAINS_FILE.exists():
        return []
    with open(ALL_SUBDOMAINS_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]


def is_flagged(record):
    vt = record.get("virustotal") or {}
    return bool((vt.get("malicious") or 0) + (vt.get("suspicious") or 0) or (record.get("urlhaus") or {}).get("listed"))


def ai_evidence(record):
    evidence = dict(record)
    evidence["mitre_attack_techniques_used"] = [
        f"{t['id']} {t['name']}" for t in techniques_for_sources(record)
    ]
    return evidence


def _analysis_fields(summary, analysis):
    summary["analysed"] = len(analysis["results"])
    summary["failed"] = len(analysis["failed"])
    summary["aborted"] = analysis["aborted"]
    summary["model"] = analysis["model"]


def _mitre(summary):
    counts = dict(summary.get("collectors") or {})
    counts["DNS resolution"] = summary.get("resolved", 0)
    for source, activity in SOURCE_ACTIVITY.items():
        counts[activity] = (summary.get("sources") or {}).get(source, 0)
    summary["mitre"] = summarize(counts)


def _enrich(subdomain, ip, keys, disabled, counts, errors):
    record = {}
    data = internetdb_fetch(ip, subdomain)
    if data:
        record["internetdb"] = data
        counts["internetdb"] += 1
    for source, fetch in INTEL_SOURCES:
        key = keys.get(source)
        if not key or source in disabled:
            continue
        try:
            result = fetch(subdomain, ip, key)
        except IntelError as e:
            errors[source] = str(e)
            logger.error(str(e))
            if e.fatal:
                disabled.add(source)
                logger.error(f"{source} disabled for the rest of this scan")
            continue
        if result is not None:
            intel_store.save(source, subdomain, result)
            record[source] = result
            counts[source] += 1
    return record


def run_scan(domain, config=None, keys=None, progress=None, should_cancel=None):
    domain = normalize_domain(domain)
    if not is_valid_domain(domain):
        raise ValueError(f"'{domain}' is not a valid domain name")

    keys = {k: v for k, v in (keys or {}).items() if v}
    cancelled = should_cancel or (lambda: False)
    emit = progress or (lambda stage, done, total, text: None)
    summary = {"domain": domain, "started": _now(), "status": "running", "collectors": {},
               "intel_enabled": sorted(keys)}
    logger.info(f"Starting enumeration for: {domain}")

    found = set()
    for index, (name, fetch) in enumerate(COLLECTORS, start=1):
        if cancelled():
            break
        emit("collect", index, len(COLLECTORS), name)
        subs = fetch(domain)
        summary["collectors"][name] = len(subs)
        found.update(subs)

    subdomains = save_subdomains(found)
    summary["found"] = len(subdomains)

    evidence = {}
    resolved = 0
    counts = {"internetdb": 0, "shodan": 0, "virustotal": 0, "urlhaus": 0}
    errors = {}
    disabled = set()
    for index, subdomain in enumerate(subdomains, start=1):
        if cancelled():
            break
        emit("enrich", index, len(subdomains), subdomain)
        ip = resolve(subdomain)
        if not ip:
            continue
        resolved += 1
        record = _enrich(subdomain, ip, keys, disabled, counts, errors)
        if record:
            evidence[subdomain] = ai_evidence(record)
    summary["resolved"] = resolved
    summary["with_evidence"] = len(evidence)
    summary["sources"] = counts
    summary["intel_errors"] = errors
    summary["flagged"] = sum(1 for r in evidence.values() if is_flagged(r))
    _mitre(summary)

    if config is not None and evidence and not cancelled():
        analysis = analyze_subdomains(
            evidence,
            config,
            progress=lambda done, total, sub: emit("analyse", done, total, sub),
            should_cancel=cancelled,
        )
        _analysis_fields(summary, analysis)
    else:
        summary["analysed"] = 0
        summary["failed"] = 0
        summary["aborted"] = None if config is not None else "AI analysis skipped"
        summary["model"] = config.label if config is not None else None

    summary["status"] = "cancelled" if cancelled() else "completed"
    summary["finished"] = _now()
    save_summary(summary)
    logger.info("Pipeline completed successfully" if summary["status"] == "completed" else "Pipeline cancelled")
    return summary


def reanalyze(config, progress=None, should_cancel=None):
    summary = load_summary()
    subdomains = current_subdomains()
    evidence = {s: ai_evidence(r) for s in subdomains if (r := intel_store.load_all(s))}
    if not evidence:
        raise ValueError("No evidence found for the current target. Run a scan first.")

    emit = progress or (lambda stage, done, total, text: None)
    analysis = analyze_subdomains(
        evidence,
        config,
        progress=lambda done, total, sub: emit("analyse", done, total, sub),
        should_cancel=should_cancel,
    )
    summary.setdefault("domain", None)
    summary["with_evidence"] = len(evidence)
    summary.setdefault("found", len(subdomains))
    _analysis_fields(summary, analysis)
    summary["reanalysed"] = _now()
    save_summary(summary)
    return summary
