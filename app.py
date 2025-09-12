from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from fraud_detector import check_entry
from collections import Counter
from datetime import datetime, timezone
import json
import joblib
import numpy as np
import os

app = Flask(__name__)

# --- Database setup ---
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///fraud.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Appeal Model ---
class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

with app.app_context():
    db.create_all()  # For first-time setup; migrations are preferred

# --- Load fraud entries from JSON ---
DATA_FILE = "data/sample_entries.json"

def load_entries():
    with open(DATA_FILE) as f:
        return json.load(f)

# --- Load ML Model ---
MODEL_PATH = "models/fraud_model.pkl"
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"⚠️ Could not load model: {e}")
    model = None

# --- Helper: Extract features for ML model ---
def extract_features(entry):
    """
    Convert entry into numeric features expected by model.
    Features: actions_per_minute, domain_type (0/1), ip_asn, duplicate_email
    """
    return np.array([[
        entry.get("actions_per_minute", 0),
        1 if entry.get("domain_type") == "disposable" else 0,
        int(entry.get("ip_asn", 0)),
        1 if entry.get("duplicate_email", False) else 0
    ]])

# --- Build fraud detection results ---
def build_results(entries):
    appeals = Appeal.query.all()
    appealed_lookup = {(a.email, a.ip): a.status for a in appeals}
    results = []

    for i, entry in enumerate(entries, start=1):
        flags = check_entry(entry)

        # ML confidence
        confidence = 0.0
        if model:
            features = extract_features(entry)
            prob = model.predict_proba(features)[0][1]  # Probability of fraud
            confidence = round(float(prob), 2)

        if not flags:
            results.append({
                "id": i,
                "email": entry["email"],
                "ip": entry["ip"],
                "flags": ["No issues detected ✅"],
                "severity": "low",
                "confidence": confidence,
                "appealed": (entry["email"], entry["ip"]) in appealed_lookup,
                "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat())
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
            "confidence": confidence,
            "appealed": (entry["email"], entry["ip"]) in appealed_lookup,
            "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat())
        })

    return results

# --- Fraud dashboard ---
@app.route("/")
def index():
    entries = load_entries()
    results = build_results(entries)
    return render_template("index.html", results=results)

# --- Chart Data API ---
@app.route("/api/chart-data")
def chart_data():
    entries = load_entries()
    results = build_results(entries)

    # Count severity
    severities = Counter([r["severity"] for r in results])

    # Timeline: group by date
    timeline = {}
    for r in results:
        date_str = r["timestamp"][:10]  # YYYY-MM-DD
        if date_str not in timeline:
            timeline[date_str] = {"low": 0, "medium": 0, "high": 0}
        timeline[date_str][r["severity"]] += 1

    timeline_list = [{"date": d, **counts} for d, counts in sorted(timeline.items())]

    return jsonify({
        "severity_counts": severities,
        "timeline": timeline_list
    })

# --- Submit an appeal (form) ---
@app.route("/appeal", methods=["POST"])
def appeal():
    email = request.form["email"]
    ip = request.form["ip"]
    message = request.form.get("message", "")
    appeal = Appeal(email=email, ip=ip, message=message, status="pending")
    db.session.add(appeal)
    db.session.commit()
    return redirect(url_for("index"))

# --- Appeals dashboard (web) ---
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
    output = [f"{a.email} | {a.ip} | {a.status} | {a.message}" for a in appeals]
    return "<br>".join(output) if output else "No appeals in database."

# --- Reset route (⚠ Dangerous: clears DB) ---
@app.route("/debug/reset")
def reset_db():
    db.drop_all()
    db.create_all()
    return "✅ Database has been reset (all appeals deleted)."

# --- API Endpoints ---
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json()
    if not data or "email" not in data or "ip" not in data:
        return jsonify({"error": "Missing email or ip"}), 400

    flags = check_entry(data)

    confidence = 0.0
    if model:
        features = extract_features(data)
        prob = model.predict_proba(features)[0][1]
        confidence = round(float(prob), 2)

    if not flags:
        result = {
            "email": data["email"],
            "ip": data["ip"],
            "flags": ["No issues detected ✅"],
            "severity": "low",
            "confidence": confidence
        }
    else:
        severity_levels = [f[1] for f in flags]
        if "high" in severity_levels:
            overall_severity = "high"
        elif "medium" in severity_levels:
            overall_severity = "medium"
        else:
            overall_severity = "low"
        result = {
            "email": data["email"],
            "ip": data["ip"],
            "flags": [f[0] for f in flags],
            "severity": overall_severity,
            "confidence": confidence
        }
    return jsonify(result), 200

@app.route("/api/results", methods=["GET"])
def api_results():
    entries = load_entries()
    results = build_results(entries)
    return jsonify(results), 200

@app.route("/api/appeal", methods=["POST"])
def api_appeal():
    data = request.get_json()
    if not data or "email" not in data or "ip" not in data:
        return jsonify({"error": "Missing email or ip"}), 400
    message = data.get("message", "")
    appeal = Appeal(email=data["email"], ip=data["ip"], message=message, status="pending")
    db.session.add(appeal)
    db.session.commit()
    return jsonify({"message": "Appeal submitted successfully", "status": "pending"}), 201

@app.route("/api/appeals", methods=["GET"])
def api_get_appeals():
    appeals = Appeal.query.all()
    return jsonify([{"email": a.email, "ip": a.ip, "message": a.message, "status": a.status} for a in appeals]), 200

@app.route("/api/appeals/update", methods=["POST"])
def api_update_appeal():
    data = request.get_json()
    if not data or "email" not in data or "ip" not in data or "action" not in data:
        return jsonify({"error": "Missing fields"}), 400
    appeal = Appeal.query.filter_by(email=data["email"], ip=data["ip"]).first()
    if appeal:
        appeal.status = "approved" if data["action"] == "approve" else "rejected"
        db.session.commit()
        return jsonify({"message": f"Appeal {appeal.status}"}), 200
    return jsonify({"error": "Appeal not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
