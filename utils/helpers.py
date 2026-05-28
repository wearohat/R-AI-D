import re

def sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

def is_valid_subdomain(subdomain: str, domain: str) -> bool:
    pattern = rf"^[a-zA-Z0-9._-]+\.{re.escape(domain)}$"
    return re.match(pattern, subdomain) is not None
