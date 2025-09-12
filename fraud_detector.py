import os
import requests
import requests_cache
from datetime import timedelta

# Cache IP lookups for 1 day (avoid rate limits)
requests_cache.install_cache("ip_cache", expire_after=86400)

BASE_DIR = os.path.dirname(__file__)
DISPOSABLE_FILE = os.path.join(BASE_DIR, "data", "disposable_domains.txt")

# Load disposable domains into a set
with open(DISPOSABLE_FILE) as f:
    DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())

# Duplicate tracking (in-memory; replace with DB if needed)
SEEN_EMAILS = {}   # email -> last_timestamp
SEEN_DEVICES = {}  # device_id -> last_timestamp
DUPLICATE_WINDOW = timedelta(hours=24)

IPAPI_BASE = "https://ipapi.co/{ip}/json/"


# --- Core Checks ---
def is_disposable_email(email: str) -> bool:
    """Check if email domain is disposable."""
    try:
        domain = email.split("@")[-1].lower()
        return domain in DISPOSABLE_DOMAINS
    except Exception:
        return False


def ip_lookup(ip: str) -> dict:
    """Lookup IP info from ipapi.co (cached)."""
    try:
        resp = requests.get(IPAPI_BASE.format(ip=ip), timeout=5)
        return resp.json()
    except Exception:
        return {}


def check_entry(entry):
    """
    Run rule-based fraud checks.
    Returns: list of (message, severity).
    """
    flags = []

    # Duplicate Email → High
    if entry.get("duplicate_email", False):
        flags.append(("Duplicate email detected", "high"))

    # Disposable Email → Medium
    if is_disposable_email(entry.get("email", "")):
        flags.append(("Disposable email provider detected", "medium"))

    # Proxy/VPN/Hosting → Medium
    ip = entry.get("ip")
    if ip:
        try:
            response = ip_lookup(ip)
            if (
                response.get("proxy")
                or response.get("vpn")
                or "hosting" in str(response.get("org", "")).lower()
            ):
                flags.append(("IP from data center/cloud provider", "medium"))
        except Exception:
            flags.append(("IP check failed", "low"))

    # Bot-like behavior → High
    actions = entry.get("actions_per_minute", 0)
    if actions > 20:
        flags.append(("Bot-like behavior (very high actions/min)", "high"))

    return flags
