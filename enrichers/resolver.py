import socket

from utils.logger import logger

def resolve(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip

    except Exception as e:
        logger.warning(f"[Resolver] Failed to resolve {subdomain}: {e}")
        return None
