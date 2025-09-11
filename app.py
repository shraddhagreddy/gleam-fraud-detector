from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from fraud_detector import check_entry
import json

app = Flask(__name__)

# --- Database setup ---
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///fraud.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# --- Appeal Model ---
class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending")


with app.app_context():
    db.create_all()


# --- Load fraud entries from JSON ---
DATA_FILE = "data/sample_entries.json"

def load_entries():
    with open(DATA_FILE) as f:
        return json.load(f)


# --- Build fraud detection results ---
def build_results(entries):
    appeals = Appeal.query.all()
    appealed_lookup = {(a.email, a.ip): a.status for a in appeals}

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
                "appealed": (entry["email"], entry["ip"]) in appealed_lookup
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
            "appealed": (entry["email"], entry["ip"]) in appealed_lookup
        })

    return results


# --- Fraud dashboard ---
@app.route("/")
def index():
    entries = load_entries()
    results = build_results(entries)
    return render_template("index.html", results=results)


# --- Submit an appeal ---
@app.route("/appeal", methods=["POST"])
def appeal():
    email = request.form["email"]
    ip = request.form["ip"]
    message = request.form.get("message", "")

    appeal = Appeal(email=email, ip=ip, message=message, status="pending")
    db.session.add(appeal)
    db.session.commit()

    return redirect(url_for("index"))


# --- Appeals dashboard ---
@app.route("/appeals")
def appeals_page():
    appeals = Appeal.query.all()
    return render_template("appeals.html", appeals=appeals, debug=app.debug)


@app.route("/appeals/update", methods=["POST"])
def update_appeal():
    email = request.form["email"]
    ip = request.form["ip"]
    action = request.form["action"]

    appeal = Appeal.query.filter_by(email=email, ip=ip).first()
    if appeal:
        appeal.status = "approved" if action == "approve" else "rejected"
        db.session.commit()

    return redirect(url_for("appeals_page"))


# --- Debug route to print all appeals ---
@app.route("/debug/appeals")
def debug_appeals():
    appeals = Appeal.query.all()
    output = []
    for a in appeals:
        output.append(f"{a.email} | {a.ip} | {a.status} | {a.message}")
    return "<br>".join(output) if output else "No appeals in database."


# --- Reset route (⚠ Dangerous: clears DB) ---
@app.route("/debug/reset")
def reset_db():
    db.drop_all()
    db.create_all()
    return "✅ Database has been reset (all appeals deleted)."


if __name__ == "__main__":
    app.run(debug=True)
