from flask import Flask, render_template
import json
from fraud_detector import check_entry

app = Flask(__name__)

DATA_FILE = "data/sample_entries.json"

def load_entries():
    """Load test entries from JSON file"""
    with open(DATA_FILE) as f:
        return json.load(f)

@app.route("/")
def index():
    # Load entries
    entries = load_entries()   # ✅ defined here
    results = []               # ✅ defined here

    for i, entry in enumerate(entries, start=1):
        flags = check_entry(entry)

        # If no issues found
        if not flags:
            results.append({
                "id": i,
                "email": entry["email"],
                "ip": entry["ip"],
                "flags": ["No issues detected ✅"],
                "severity": "low"
            })
            continue

        # Calculate overall severity
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
            "severity": overall_severity
        })

    return render_template("index.html", results=results)  # ✅ pass results to template

if __name__ == "__main__":
    app.run(debug=True)
