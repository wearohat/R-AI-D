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

Models can be swapped at runtime:

```bash
OLLAMA_MODEL=deepseek-r1:14b python main.py example_target.com
```

---

# Output Paths

Configured:

* output directory
* evidence directory
* report locations

---

