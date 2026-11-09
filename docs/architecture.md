# Architecture

The pipeline is divided into independent functional layers:

```text
Collectors
    ↓
Enrichers
    ↓
MITRE ATT&CK
    ↓
AI Analysis
    ↓
GUI / Reporting
```

---

# Layer Overview

## Collectors Layer

Responsible for passive subdomain enumeration.

Sources:

* AlienVault OTX
* URLScan
* Wayback Machine

Goal:

* discover subdomains
* aggregate results
* deduplicate entries

Output:

```text
output/all_subdomains.txt
```

---

## Enrichment Layer

Responsible for transforming raw subdomains into actionable intelligence.

Tasks:

* DNS resolution
* InternetDB querying
* Shodan API querying
* VirusTotal checks
* URLhaus checks
* evidence storage

Output:

```text
output/evidence/*.json
output/shodan/*.json
output/virustotal/*.json
output/urlhaus/*.json
```

---

## MITRE ATT&CK Layer

Responsible for:

* naming every recon activity
* standardized technique names and IDs

Output:

```text
output/last_scan.json
```

---

## AI Layer

Responsible for:

* reconnaissance reasoning
* CVE interpretation
* open-port analysis
* target prioritization
* investigation suggestions

Uses:

* Ollama 
* OpenRouter
* OrcaRouter

Output:

```text
output/prioritized_targets.json
```

---

## GUI / Reporting Layer

Responsible for:

* running scans
* results table
* charts
* structured JSON reports
