import json

from config.settings import EVIDENCE_DIR, OUTPUT_DIR
from utils.helpers import sanitize_filename

SOURCES = ["shodan", "virustotal", "urlhaus"]


class IntelError(Exception):
    def __init__(self, message, fatal=False):
        super().__init__(message)
        self.fatal = fatal


def source_dir(source):
    return EVIDENCE_DIR if source == "internetdb" else OUTPUT_DIR / source


def _path(source, subdomain):
    return source_dir(source) / (sanitize_filename(subdomain) + ".json")


def save(source, subdomain, data):
    path = _path(source, subdomain)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def load(source, subdomain):
    path = _path(source, subdomain)
    if not path.exists():
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_all(subdomain):
    record = {}
    for source in ["internetdb"] + SOURCES:
        data = load(source, subdomain)
        if data is not None:
            record[source] = data
    return record


def http_error(source, response):
    if response.status_code in (401, 403):
        return IntelError(f"{source}: API key rejected or not allowed ({response.status_code})", fatal=True)
    if response.status_code == 429:
        return IntelError(f"{source}: rate limit or quota reached", fatal=True)
    return IntelError(f"{source}: HTTP {response.status_code}")
