TACTIC = "Reconnaissance (TA0043)"

TECHNIQUES = {
    "T1593": "Search Open Websites/Domains",
    "T1596.001": "Search Open Technical Databases: DNS/Passive DNS",
    "T1596.005": "Search Open Technical Databases: Scan Databases",
    "T1590.002": "Gather Victim Network Information: DNS",
    "T1590.005": "Gather Victim Network Information: IP Addresses",
    "T1592.002": "Gather Victim Host Information: Software",
    "T1597.001": "Search Closed Sources: Threat Intel Vendors",
}

ACTIVITIES = {
    "AlienVault OTX": ["T1596.001"],
    "URLScan.io": ["T1596.005"],
    "Wayback Machine": ["T1593"],
    "DNS resolution": ["T1590.002", "T1590.005"],
    "InternetDB": ["T1596.005", "T1592.002"],
    "Shodan API": ["T1596.005", "T1592.002"],
    "VirusTotal": ["T1597.001"],
    "URLhaus": ["T1597.001"],
}

SOURCE_ACTIVITY = {
    "internetdb": "InternetDB",
    "shodan": "Shodan API",
    "virustotal": "VirusTotal",
    "urlhaus": "URLhaus",
}


def technique(technique_id):
    return {
        "id": technique_id,
        "name": TECHNIQUES[technique_id],
        "tactic": TACTIC,
        "url": "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/",
    }


def techniques_for(activity):
    return [technique(t) for t in ACTIVITIES.get(activity, [])]


def techniques_for_sources(sources):
    activities = ["DNS resolution"] + [SOURCE_ACTIVITY[s] for s in sources if s in SOURCE_ACTIVITY]
    seen = {}
    for activity in activities:
        for t in ACTIVITIES[activity]:
            seen.setdefault(t, technique(t))
    return list(seen.values())


def summarize(activity_counts):
    rows = {}
    for activity, count in activity_counts.items():
        if not count:
            continue
        for t in ACTIVITIES.get(activity, []):
            row = rows.setdefault(t, {**technique(t), "activities": [], "records": 0})
            row["activities"].append(activity)
            row["records"] += count
    return sorted(rows.values(), key=lambda r: (-r["records"], r["id"]))
