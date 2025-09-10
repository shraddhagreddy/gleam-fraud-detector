import json
import os
import re
from email_validator import validate_email, EmailNotValidError
import requests
import requests_cache
from datetime import datetime, timedelta

# cache IP lookups for 1 day (avoid rate limits)
requests_cache.install_cache('ip_cache', expire_after=86400)

BASE_DIR = os.path.dirname(__file__)
DISPOSABLE_FILE = os.path.join(BASE_DIR, "data", "disposable_domains.txt")

# load disposable domains into set
with open(DISPOSABLE_FILE) as f:
    DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())

# Simple duplicate tracking (in-memory; replace with DB in production)
SEEN_EMAILS = {}   # email -> last_timestamp
SEEN_DEVICES = {}  # device_id -> last_timestamp
DUPLICATE_WINDOW = timedelta(hours=24)  # consider duplicates within 24h

IPAPI_BASE = "https://ipapi.co/{ip}/json/"

def is_disposable_email(email: str) -> bool:
    try:
        domain = email.split("@")[-1].lower()
    except Exception:
        return False
    return domain in DISPOSABLE_DOMAINS

def ip_lookup(ip: str) -> dict:
    try:
        resp = requests.get(IPAPI_BASE.format(ip=ip), timeout=5)
        return resp.json()
    except Exception:
        return {}

def check_entry(entry):
    flags = []

    # Duplicate Email → High
    if entry.get("duplicate_email", False):
        flags.append(("Duplicate email detected", "high"))

    # Disposable Email → Medium
    domain = entry["email"].split("@")[-1]
    if domain in DISPOSABLE_DOMAINS:
        flags.append(("Disposable email provider detected", "medium"))

    # Proxy/VPN → Medium
    ip = entry["ip"]
    try:
        import requests
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        if response.get("proxy") or response.get("vpn") or "hosting" in str(response.get("org", "")).lower():
            flags.append(("IP from data center/cloud provider", "medium"))
    except:
        flags.append(("IP check failed", "low"))

    # Bot-like behavior → High
    if entry["actions_per_minute"] > 20:
        flags.append(("Bot-like behavior (very high actions/min)", "high"))

    return flags
