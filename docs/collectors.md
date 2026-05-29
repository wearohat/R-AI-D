# Collectors

The collectors layer is responsible for passive subdomain enumeration.

---

# alienvault.py

Queries:

```text
https://otx.alienvault.com/
```

Uses:

* passive DNS records

Goal:

* discover historical and observed subdomains

---

# urlscan.py

Queries:

```text
https://urlscan.io/
```

Uses:

* indexed scan results

Goal:

* identify publicly observed domains

---

# wayback.py

Queries:

```text
https://web.archive.org/
```

Uses:

* archived URLs

Goal:

* discover historical subdomains

---

# aggregator.py

Responsible for:

* combining results
* deduplication
* file storage

Output:

```text
output/all_subdomains.txt
```

---

# Design Philosophy

The collectors layer uses:

* passive reconnaissance only
* no active probing
* no intrusive scanning


