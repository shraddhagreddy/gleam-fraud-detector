from flask import Flask, render_template_string, request, redirect, url_for
import json
from fraud_detector import check_entry

app = Flask(__name__)

DATA_FILE = "data/sample_entries.json"
APPEALS_FILE = "data/appeals.json"


def load_entries():
    with open(DATA_FILE) as f:
        return json.load(f)


def save_appeal(entry_id, email, reason):
    try:
        with open(APPEALS_FILE) as f:
            appeals = json.load(f)
    except FileNotFoundError:
        appeals = []

    appeals.append({
        "entry_id": entry_id,
        "email": email,
        "reason": reason
    })

    with open(APPEALS_FILE, "w") as f:
        json.dump(appeals, f, indent=2)


@app.route("/")
def index():
    entries = load_entries()
    results = []
    for i, entry in enumerate(entries, start=1):
        flags = check_entry(entry)
        severity = "low"
        if any("bot" in f.lower() or "duplicate" in f.lower() for f in flags):
            severity = "high"
        elif flags:
            severity = "medium"

        results.append({
            "id": i,
            "email": entry["email"],
            "ip": entry["ip"],
            "flags": flags if flags else ["No issues detected ✅"],
            "severity": severity
        })

    # HTML with color coding + appeal button
    html = """
    <h1>Fraud Detection Report (demo)</h1>
    <table border="1" cellpadding="10">
      <tr><th>Entry ID</th><th>Email</th><th>IP</th><th>Flags</th><th>Severity</th><th>Appeal</th></tr>
      {% for r in results %}
        <tr>
          <td>{{r.id}}</td>
          <td>{{r.email}}</td>
          <td>{{r.ip}}</td>
          <td>{{", ".join(r.flags)}}</td>
          <td style="color:
              {% if r.severity == 'high' %}red
              {% elif r.severity == 'medium' %}orange
              {% else %}green
              {% endif %}
          ">{{r.severity}}</td>
          <td><a href="{{ url_for('appeal', entry_id=r.id, email=r.email) }}">Appeal</a></td>
        </tr>
      {% endfor %}
    </table>
    """
    return render_template_string(html, results=results)


@app.route("/appeal/<int:entry_id>/<email>", methods=["GET", "POST"])
def appeal(entry_id, email):
    if request.method == "POST":
        reason = request.form["reason"]
        save_appeal(entry_id, email, reason)
        return redirect(url_for("index"))

    html = """
    <h1>Appeal Entry {{entry_id}}</h1>
    <p>Email: {{email}}</p>
    <form method="post">
      <label for="reason">Reason:</label><br>
      <textarea name="reason" rows="4" cols="40" required></textarea><br><br>
      <input type="submit" value="Submit Appeal">
    </form>
    <a href="{{ url_for('index') }}">Back</a>
    """
    return render_template_string(html, entry_id=entry_id, email=email)


if __name__ == "__main__":
    app.run(debug=True)
