# MITRE ATT&CK

The MITRE layer is responsible for:

* categorizing recon activities
* standardized technique names
* standardized technique IDs

Tactic:

```text
Reconnaissance (TA0043)
```

---

# attack.py

Maps every activity to its technique:

* AlienVault OTX: T1596.001 DNS/Passive DNS
* URLScan.io: T1596.005 Scan Databases
* Wayback Machine: T1593 Search Open Websites/Domains
* DNS resolution: T1590.002 DNS, T1590.005 IP Addresses
* InternetDB / Shodan API: T1596.005 Scan Databases, T1592.002 Software
* VirusTotal / URLhaus: T1597.001 Threat Intel Vendors

Works offline.

---

# Shown In

* Results tab
* Charts tab
* AI prompt

Stores:

```text
output/last_scan.json
```

---

# Note

The techniques describe how R-AI-D collected the data.

They do NOT describe attacker activity.
