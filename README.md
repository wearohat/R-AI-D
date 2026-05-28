# R-AI-D

Automated subdomain discovery and AI-powered reconnaissance triage.

## Features

- AlienVault enumeration
- URLScan enumeration
- Wayback Machine enumeration
- InternetDB enrichment
- Local LLM analysis
- Automatic prioritization

---

## Install

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Ollama

https://ollama.com

### 4. Pull model

```bash
ollama pull MODEL NAME
```

Models for Low-end devices:

* llama3.2:3b
* phi3:mini

Model for Higher-end devices:

* mistral
* qwen2.5


---

## Run

```bash
python main.py example.com
```

---

## Outputs


```bash
cat output/prioritized_targets.json
```

---
