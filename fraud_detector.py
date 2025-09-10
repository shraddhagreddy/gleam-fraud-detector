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

def check_entry(entry: dict) -> dict:
    """
    Return a dict: { entry_id, flags:[...], severity: 'low|medium|high' }
    """
    flags = []
    severity_score = 0

    # 0. Basic required fields
    email = entry.get("email", "").strip().lower()
    ip = entry.get("ip", "")
    device = entry.get("device_id")
    ts = entry.get("timestamp")
    try:
        timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        timestamp = datetime.utcnow()

    # 1. Email valid?
    try:
        validate_email(email)
    except EmailNotValidError:
        flags.append("Invalid email format")
        severity_score += 1

    # 2. Disposable?
    if is_disposable_email(email):
        flags.append("Disposable email provider detected")
        severity_score += 2

    # 3. Duplicate email within window?
    last = SEEN_EMAILS.get(email)
    if last and (timestamp - last) < DUPLICATE_WINDOW:
        flags.append("Duplicate email entry (within 24h)")
        severity_score += 2
    SEEN_EMAILS[email] = timestamp

    # 4. Device duplicate
    if device:
        last_dev = SEEN_DEVICES.get(device)
        if last_dev and (timestamp - last_dev) < DUPLICATE_WINDOW:
            flags.append("Same device used for multiple entries")
            severity_score += 2
        SEEN_DEVICES[device] = timestamp

    # 5. Actions-per-minute => bot-like
    apm = entry.get("actions_per_minute", 0)
    if apm >= 20:
        flags.append("Bot-like behavior (very high actions/min)")
        severity_score += 2
    elif apm >= 10:
        flags.append("Suspiciously high actions/min")
        severity_score += 1

    # 6. IP lookup
    ip_info = ip_lookup(ip)
    if ip_info:
        # ipapi returns some fields; not all providers include proxy/vpn booleans
        # We'll rely on 'org', 'asn', 'ip' and 'country' as signals if proxy/vpn keys missing
        # if a provider returns 'proxy' or 'vpn' keys, use them
        if ip_info.get("proxy") or ip_info.get("vpn"):
            flags.append("Proxy/VPN connection suspected")
            severity_score += 2
        # suspicious org names (heuristic)
        org = ip_info.get("org", "") or ip_info.get("asn", "")
        if org and ("cloud" in org.lower() or "amazon" in org.lower() or "digitalocean" in org.lower() or "google" in org.lower()):
            flags.append(f"IP from data center/cloud provider: {org}")
            severity_score += 1

    else:
        flags.append("IP lookup failed")
        severity_score += 1

    severity = "low"
    if severity_score >= 4:
        severity = "high"
    elif severity_score >= 2:
        severity = "medium"

    return {
        "entry_id": entry.get("entry_id"),
        "email": email,
        "ip": ip,
        "flags": flags,
        "severity": severity,
        "raw_ip_info": ip_info
    }
