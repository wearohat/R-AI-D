# AI Layer

The AI layer is responsible for:

* reasoning
* prioritization
* security interpretation
* investigation recommendations

---

# prompt_builder.py

Creates structured prompts for the local LLM.

The prompts instruct the AI to:

* analyze open ports
* interpret service exposure
* explain CVEs
* recommend investigation paths

---

# llm_client.py

Handles communication with:

* Ollama local API

Default endpoint:

```text
http://localhost:11434/api/generate
```

Used by:

* main.py

---

# analyzer.py

Coordinates:

* evidence loading
* prompt creation
* LLM querying
* result parsing
* prioritization

Used by:

* main.py

---

# providers.py

Handles communication with:

* Ollama (local, no API key)
* OpenRouter (cloud, API key)
* OrcaRouter (cloud, API key)

Also:

* lists available models
* tests the connection
* returns clear error messages

Default models:

```text
Ollama:      llama3.2:3b
OpenRouter:  openrouter/free
OrcaRouter:  orcarouter/auto
```

Used by:

* GUI

---

# multi_analyzer.py

Coordinates:

* prompt creation (reuses prompt_builder.py)
* querying the selected provider
* result parsing
* prioritization

Also:

* keeps scores between 0 and 10
* stops after 3 failed calls in a row

Used by:

* GUI

---

# AI Input

For each subdomain the AI receives:

* InternetDB data
* Shodan API data
* VirusTotal detections
* URLhaus results
* MITRE ATT&CK techniques used

---

# AI Role

The AI acts as:

* reconnaissance analyst
* triage assistant
* investigation planner

It does NOT directly perform exploitation.

Output:

```text
output/prioritized_targets.json
```
