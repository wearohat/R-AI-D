# Enrichers

The enrichers layer transforms raw subdomains into actionable intelligence.

---

# resolver.py

Responsible for:

* resolving subdomains into IP addresses

Uses:

* DNS resolution

Goal:

* prepare targets for InternetDB enrichment

---

# internetdb.py

Queries:

```text
https://internetdb.shodan.io/
```

Collects:

* open ports
* CVEs
* CPEs
* hostnames
* tags

Stores:

```text
output/evidence/
```

---

# Evidence Files

Each target receives an individual JSON evidence file.

Example:

```text
output/evidence/vpn_example_com.json
```

---

# Purpose

The enrichment layer provides:

* structured target intelligence
* service visibility
* vulnerability indicators

This becomes the evidence consumed by the AI layer.
