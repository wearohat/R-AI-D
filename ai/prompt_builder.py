import json

def build_prompt(subdomain, evidence):
    return f"""
You are a cybersecurity reconnaissance analyst.

Analyze the following InternetDB evidence for the subdomain:

Subdomain:
{subdomain}

Evidence:
{json.dumps(evidence, indent=2)}

Tasks:
1. Determine if this subdomain is interesting for further investigation.
2. Score it from 1-10.
3. Explain why.
4. Suggest possible manual investigation approaches.
5. Mention exposed technologies or risks.

Return JSON only in this format:

{{
  "score": 0,
  "reason": "",
  "suggestions": []
}}
"""

