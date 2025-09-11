# Gleam Fraud Detector (Prototype)

![Python](https://img.shields.io/badge/python-3.10-blue)
![Flask](https://img.shields.io/badge/flask-2.3-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![GitHub issues](https://img.shields.io/github/issues/shraddhagreddy/gleam-fraud-detector)


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
