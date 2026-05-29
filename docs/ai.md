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

---

# analyzer.py

Coordinates:

* evidence loading
* prompt creation
* LLM querying
* result parsing
* prioritization

---

# AI Role

The AI acts as:

* reconnaissance analyst
* triage assistant
* investigation planner

It does NOT directly perform exploitation.
