from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from fraud_detector import check_entry
from collections import Counter
from datetime import datetime, timezone
import json
import joblib
import numpy as np
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change in production

# --- Database setup ---
import os
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///fraud.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- User Model ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="reviewer")  # admin or reviewer

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Appeal Model ---
class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Create tables and seed default users (dev convenience)
with app.app_context():
    db.create_all()

    # --- Ensure default users exist ---
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        print("✅ Default admin created (username=admin, password=admin123)")

    if not User.query.filter_by(username="reviewer").first():
        reviewer = User(username="reviewer", role="reviewer")
        reviewer.set_password("review123")
        db.session.add(reviewer)
        print("✅ Default reviewer created (username=reviewer, password=review123)")

    db.session.commit()

# --- Login Manager ---
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Load fraud entries ---
DATA_FILE = "data/sample_entries.json"

def load_entries():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️ Missing data file: {DATA_FILE} — returning empty list")
        return []

# --- Load ML Model ---
MODEL_PATH = "models/fraud_model.pkl"
try:
    model = joblib.load(MODEL_PATH)
    print("✅ ML model loaded successfully.")
except Exception as e:
    print(f"⚠️ Could not load model: {e}")
    model = None

# --- Helper: Extract features ---
def extract_features(entry):
    """
    Convert entry into numeric features expected by model.
    Features: actions_per_minute, domain_type (disposable=1), ip_asn, duplicate_email
    """
    # safe conversions
    actions = int(entry.get("actions_per_minute", 0) or 0)
    domain_flag = 1 if entry.get("domain_type") == "disposable" else 0
    try:
        ip_asn = int(entry.get("ip_asn", 0) or 0)
    except Exception:
        ip_asn = 0
    duplicate = 1 if entry.get("duplicate_email", False) else 0

    return np.array([[actions, domain_flag, ip_asn, duplicate]])

# --- Build results helper (used by UI + APIs) ---
def build_results(entries):
    appeals = Appeal.query.all()
    appealed_lookup = {(a.email, a.ip): a.status for a in appeals}
    results = []

    for i, entry in enumerate(entries, start=1):
        flags = check_entry(entry) or []
        confidence = 0.0
        if model:
            try:
                features = extract_features(entry)
                prob = model.predict_proba(features)[0][1]
                confidence = round(float(prob), 2)
            except Exception as e:
                print(f"⚠️ Prediction failed: {e}")
                confidence = 0.0

        severity_levels = [f[1] for f in flags] if flags else []
        if "high" in severity_levels:
            overall_severity = "high"
        elif "medium" in severity_levels:
            overall_severity = "medium"
        else:
            overall_severity = "low"

        results.append({
            "id": i,
            "email": entry.get("email", ""),
            "ip": entry.get("ip", ""),
            "flags": [f[0] for f in flags] if flags else ["No issues detected ✅"],
            "severity": overall_severity,
            "confidence": confidence,
            "appealed": (entry.get("email", ""), entry.get("ip", "")) in appealed_lookup,
            "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat())
        })

    return results

# --- Routes ---
@app.route("/")
@login_required
def index():
    entries = load_entries()
    results = build_results(entries)
    return render_template("index.html", results=results, user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "reviewer")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
        else:
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("✅ Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# --- Chart Data API (fixed: returns JSON-friendly dicts) ---
@app.route("/api/chart-data")
def chart_data():
    entries = load_entries()
    results = build_results(entries)

    # Count severity -> return plain dict so jsonify() works
    severities = Counter([r.get("severity", "low") for r in results])
    severity_counts = {
        "low": int(severities.get("low", 0)),
        "medium": int(severities.get("medium", 0)),
        "high": int(severities.get("high", 0))
    }

    # Timeline: group by date -> ensure each item has numeric low/medium/high
    timeline = {}
    for r in results:
        ts = r.get("timestamp") or datetime.now(timezone.utc).isoformat()
        date_str = ts[:10]  # YYYY-MM-DD
        timeline.setdefault(date_str, {"low": 0, "medium": 0, "high": 0})
        sev = r.get("severity", "low")
        timeline[date_str][sev] = timeline[date_str].get(sev, 0) + 1

    timeline_list = [{"date": d, **counts} for d, counts in sorted(timeline.items())]

    return jsonify({
        "severity_counts": severity_counts,
        "timeline": timeline_list
    })

# --- Appeals dashboard ---
@app.route("/appeals")
@login_required
def appeals_page():
    appeals = Appeal.query.all()
    return render_template("appeals.html", appeals=appeals, user=current_user, debug=app.debug)

@app.route("/appeals/update", methods=["POST"])
@login_required
def update_appeal():
    if current_user.role != "admin":
        flash("❌ Only admins can update appeals.", "danger")
        return redirect(url_for("appeals_page"))

    email = request.form["email"]
    ip = request.form["ip"]
    action = request.form["action"]
    appeal = Appeal.query.filter_by(email=email, ip=ip).first()
    if appeal:
        appeal.status = "approved" if action == "approve" else "rejected"
        db.session.commit()
    return redirect(url_for("appeals_page"))

# --- Submit Appeal ---
@app.route("/appeal", methods=["POST"])
@login_required
def submit_appeal():
    email = request.form.get("email")
    ip = request.form.get("ip")
    message = request.form.get("message", "")

    # Check if appeal already exists
    existing = Appeal.query.filter_by(email=email, ip=ip).first()
    if existing:
        flash("⚠️ Appeal already submitted for this entry.", "warning")
    else:
        new_appeal = Appeal(email=email, ip=ip, message=message)
        db.session.add(new_appeal)
        db.session.commit()
        flash("✅ Appeal submitted successfully!", "success")

    return redirect(url_for("appeals_page"))

@app.route("/debug/reset")
@login_required
def reset_db():
    if current_user.role != "admin":
        flash("❌ Only admins can reset the DB.", "danger")
        return redirect(url_for("appeals_page"))

    # Delete all appeals
    Appeal.query.delete()
    db.session.commit()
    flash("✅ Appeals database reset.", "success")
    return redirect(url_for("appeals_page"))

if __name__ == "__main__":
    #app.run(debug=True)
    app.run(host="0.0.0.0", port=5000)
