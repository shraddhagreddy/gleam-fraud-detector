from fraud_detector import check_entry
from datetime import datetime, timedelta

def test_disposable_email_flag():
    entry = {
        "entry_id": "t1",
        "email": "abc@mailinator.com",
        "ip": "8.8.8.8",
        "actions_per_minute": 1,
        "device_id": "dev1",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    res = check_entry(entry)
    assert any("Disposable email provider" in f or "Disposable email provider detected" in f for f in res["flags"])

def test_bot_behavior_flag():
    entry = {
        "entry_id": "t2",
        "email": "ok@gmail.com",
        "ip": "1.1.1.1",
        "actions_per_minute": 50,
        "device_id": "dev2",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    res = check_entry(entry)
    assert any("Bot-like" in f for f in res["flags"])
