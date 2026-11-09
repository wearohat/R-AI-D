# Configurable Settings

## OLLAMA_URL

Defines:

* local AI endpoint

Default:

```python
OLLAMA_URL = "http://localhost:11434/api/generate"
```

---

## OLLAMA_MODEL

Defines:

* default local model

Example:

```python
OLLAMA_MODEL = "llama3.2:3b"
```

---

# Dynamic Model Switching

Models can be swapped at runtime


---

# API Keys

Set as environment variables or in the GUI Settings tab:

```bash
OPENROUTER_API_KEY=...
ORCAROUTER_API_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
URLHAUS_API_KEY=...
```

---

# GUI Settings

Stored in:

```text
output/gui_settings.json
```

API keys are saved only if "Remember API keys" is ticked.

---

# Output Paths

Configured:

* output directory
* evidence directory
* report locations
