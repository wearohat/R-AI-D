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

R-AI-D supports dynamic model switching through environment variables.
By default, the project uses: llama3.2:3b
You can swap models at runtime without changing the code.

## Deafult Run

```bash
python main.py example_target.com
```

```bash
OLLAMA_MODEL=ENTER_MODEL_NAME_HERE python main.py example_target.com
```


---

## Outputs


```bash
cat output/prioritized_targets.json
```

---
