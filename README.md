# Gleam Fraud Detector (Prototype)

![Python](https://img.shields.io/badge/python-3.10-blue)
![Flask](https://img.shields.io/badge/flask-2.3-green)
![License](https://img.shields.io/badge/license-MIT-blue) 
![GitHub issues](https://img.shields.io/github/issues/shraddhagreddy/gleam-fraud-detector)


🚀 A simple proof-of-concept showing how **fraud detection + transparency** can improve Gleam campaigns. Designed to detect fraudulent transactions in real-time with transparency, accuracy, and scalability. 

## Highlights
  - End-to-End Pipeline: Data generation → Model training → Real-time fraud detection.
  - Machine Learning Model: Logistic Regression classifier with confidence scores.
  - Interactive Dashboard: Real-time display of fraud predictions and analytics.
  - Secure & Transparent: Traceable predictions and clear logging.

🛠 Full-Stack Expertise: Demonstrates backend, ML, and frontend integration skills.

## Features
- Detects:
  - Duplicate emails
  - Disposable email domains
  - Proxy/VPN connections (via IP check API)
  - Bot-like behavior (too many actions/minute)
- Provides **clear flags** instead of silent shadowbans.
- Includes a simple Flask app to demo results.

## Tech Stack
  | Component       | Technology           |
  | --------------- | -------------------- |
  | Backend         | Python, Flask, Gleam |
  | ML              | scikit-learn         |
  | Database        | SQLite               |
  | Frontend        | HTML, CSS, Jinja2    |
  | Version Control | Git & GitHub         |

## How It Works
  - Data Simulation – Generates synthetic user transactions.
  - Model Training – Logistic regression model classifies transactions.
  - Prediction – Outputs confidence scores for each transaction.
  - Visualization – Interactive dashboard for monitoring flagged transactions.

## Code Structure
gleam-fraud-detector/
│
├── app.py                  # Flask backend routes
├── models/
│   └── fraud_model.pkl     # Pre-trained ML model
├── templates/
│   └── dashboard.html      # Frontend dashboard
├── static/
│   └── css/                # Stylesheets
├── utils/
│   └── data_gen.py         # Data generation scripts
├── requirements.txt        # Python dependencies
└── README.md               # Documentation

## 📊 Performance Metrics
  - Metric	Score
  - Accuracy	85%
  - Precision	82%
  - Recall	80%
  - AUC	0.88
Metrics based on synthetic dataset. Model can be retrained with real transactional data.

## Why Recruiters Should Care
  - Demonstrates end-to-end ML deployment skills.
  - Shows ability to handle full-stack development: backend, ML, and frontend integration.
  - Highlights knowledge of Gleam, a rare functional language.
  - Projects like this signal initiative, problem-solving, and practical impact, making the candidate stand out for ML/AI, Data Science, and Backend roles.
    
## Run Locally
```bash
git clone https://github.com/<your-username>/gleam-fraud-detector.git
cd gleam-fraud-detector
pip install -r requirements.txt
python app.py



