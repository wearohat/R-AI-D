# R-AI-D


Automated AI-powered passive reconnaissance tool.

## Features

- AlienVault enumeration
- URLScan enumeration
- Wayback Machine enumeration
- InternetDB enrichment
- Local LLM analysis
- Automatic prioritization

---

## Setup

###  Install dependencies

```bash
pip install -r requirements.txt
```

###  Install Ollama & Download Models

https://ollama.com

---

## Run

R-AI-D supports dynamic model switching through environment variables.
By default, the project uses: llama3.2:3b
You can swap models at runtime without changing the code.

### Deafult Run

```bash
python main.py example_target.com
```

### Model Swap Run

```bash
OLLAMA_MODEL=ENTER_MODEL_NAME_HERE python main.py example_target.com
```

---

## Outputs

```bash
cat output/prioritized_targets.json
```

---
