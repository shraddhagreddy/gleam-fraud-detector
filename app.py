from flask import Flask, render_template, request, redirect, url_for
import json
from fraud_detector import check_entry

app = Flask(__name__)

DATA_FILE = "data/sample_entries.json"
APPEALS_FILE = "data/appeals.json"


def load_entries():
    with open(DATA_FILE) as f:
        return json.load(f)


def load_appeals():
    try:
        with open(APPEALS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save_appeals(appeals):
    with open(APPEALS_FILE, "w") as f:
        json.dump(appeals, f, indent=2)


def build_results(entries, appeals=None):
    # Use .get("status") to avoid KeyError
    appealed_lookup = {(a["email"], a["ip"]): a.get("status", "pending") for a in (appeals or [])}
    results = []

    for i, entry in enumerate(entries, start=1):
        flags = check_entry(entry)

        if not flags:
            results.append({
                "id": i,
                "email": entry["email"],
                "ip": entry["ip"],
                "flags": ["No issues detected ✅"],
                "severity": "low",
                "appealed": (entry["email"], entry["ip"]) in appealed_lookup,
                "appeal_status": appealed_lookup.get((entry["email"], entry["ip"]))
            })
            continue

        severity_levels = [f[1] for f in flags]
        if "high" in severity_levels:
            overall_severity = "high"
        elif "medium" in severity_levels:
            overall_severity = "medium"
        else:
            overall_severity = "low"

        results.append({
            "id": i,
            "email": entry["email"],
            "ip": entry["ip"],
            "flags": [f[0] for f in flags],
            "severity": overall_severity,
            "appealed": (entry["email"], entry["ip"]) in appealed_lookup,
            "appeal_status": appealed_lookup.get((entry["email"], entry["ip"]))
        })

    return results



# --- Fraud dashboard ---
@app.route("/")
def index():
    entries = load_entries()
    appeals = load_appeals()
    results = build_results(entries, appeals)
    return render_template("index.html", results=results)


@app.route("/appeal", methods=["POST"])
def appeal():
    email = request.form["email"]
    ip = request.form["ip"]
    message = request.form.get("message", "")

    appeals = load_appeals()
    appeals.append({
        "email": email,
        "ip": ip,
        "status": "pending",
        "message": message
    })
    save_appeals(appeals)

    entries = load_entries()
    results = build_results(entries, appeals)

    return render_template("index.html", results=results)


# --- Appeals dashboard ---
@app.route("/appeals")
def appeals_page():
    appeals = load_appeals()
    return render_template("appeals.html", appeals=appeals)


@app.route("/appeals/update", methods=["POST"])
def update_appeal():
    email = request.form["email"]
    ip = request.form["ip"]
    action = request.form["action"]

    appeals = load_appeals()
    for appeal in appeals:
        if appeal["email"] == email and appeal["ip"] == ip:
            appeal["status"] = "approved" if action == "approve" else "rejected"
            break

    save_appeals(appeals)
    return redirect(url_for("appeals_page"))


if __name__ == "__main__":
    app.run(debug=True)
