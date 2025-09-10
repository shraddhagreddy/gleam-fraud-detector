# Gleam Fraud Detector (Prototype)

🚀 A simple proof-of-concept showing how **fraud detection + transparency** can improve Gleam campaigns.

## Features
- Detects:
  - Duplicate emails
  - Disposable email domains
  - Proxy/VPN connections (via IP check API)
  - Bot-like behavior (too many actions/minute)
- Provides **clear flags** instead of silent shadowbans.
- Includes a simple Flask app to demo results.

## Run Locally
```bash
git clone https://github.com/<your-username>/gleam-fraud-detector.git
cd gleam-fraud-detector
pip install -r requirements.txt
python app.py
