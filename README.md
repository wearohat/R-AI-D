# R-AI-D
 
AI-powered passive reconnaissance framework.
 
Everything is passive: the target is never scanned or probed.
 
## Features
 
- Subdomain enumeration: AlienVault OTX, URLScan.io, Wayback Machine
- Host enrichment: Shodan InternetDB, Shodan API
- Threat intelligence: VirusTotal, URLhaus
- MITRE ATT&CK technique names and IDs for every recon activity
- AI prioritisation with local or cloud solutions
- Desktop GUI with results and charts
 
---
 
## Setup
 
### Install dependencies
 
```bash
pip install -r requirements.txt
```
 
### AI provider
 
- **Ollama** (local, no key): install from https://ollama.com, then run `ollama pull llama3.2:3b`
- **OpenRouter**: API key from https://openrouter.ai
- **OrcaRouter**: API key from https://orcarouter.ai
 
### Optional API keys
 
- Shodan: https://account.shodan.io
- VirusTotal: https://www.virustotal.com
- URLhaus: https://auth.abuse.ch
 
Add them in the GUI's **Settings** tab. Sources without a key are skipped.
 
---
 
## Run
 
### GUI
 
```bash
python3 run_gui.py
```
