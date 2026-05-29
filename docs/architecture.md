# Architecture

The pipeline is divided into independent functional layers:

```text
Collectors
    ↓
Enrichers
    ↓
AI Analysis
    ↓
Reporting
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
* evidence storage

Output:

```text
output/evidence/*.json
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

* local LLMs through Ollama

Output:

```text
output/prioritized_targets.json
```

---

## Reporting Layer

Responsible for:

* human-readable terminal output
* structured JSON reports
* future dashboard integration

---

