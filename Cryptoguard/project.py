from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
from scipy.sparse import hstack
from collections import defaultdict
import os



app = Flask(__name__)

# Get the directory of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load model and vectorizer
model = joblib.load(os.path.join(BASE_DIR, 'best_model.pkl'))
tfidf = joblib.load(os.path.join(BASE_DIR, 'tfidf_vectorizer.pkl'))
print("Current working directory:", os.getcwd())


if not os.path.exists(os.path.join(BASE_DIR, 'best_model.pkl')):
    raise FileNotFoundError("best_model.pkl not found")
if not os.path.exists(os.path.join(BASE_DIR, 'tfidf_vectorizer.pkl')):
    raise FileNotFoundError("tfidf_vectorizer.pkl not found")

# Load model and vectorizer
# model = joblib.load('best_model.pkl')
# tfidf = joblib.load('tfidf_vectorizer.pkl')

# Vulnerability patterns
VULNERABILITY_PATTERNS = {
    'buffer_overflow': ['strcpy(', 'strcat(', 'gets(', 'sprintf('],
    'command_injection': ['system(', 'popen(', 'exec(', 'ShellExecute('],
    'memory_issues': ['malloc(', 'free(', 'realloc(', 'memset('],
    'format_string': ['printf(', 'fprintf(', 'sprintf(', 'snprintf(']
}

def predict_vulnerability(code_snippet):
    """Predict if a code snippet is vulnerable."""
    vulnerability_types = [
        vuln for vuln, patterns in VULNERABILITY_PATTERNS.items()
        if any(pattern in code_snippet for pattern in patterns)
    ]

    # Feature transformation
    text_features = tfidf.transform([code_snippet])
    num_features = np.array([[len(code_snippet)]])
    X = hstack([text_features, num_features])

    # Prediction
    proba = model.predict_proba(X)[0][1]
    is_unsafe = proba >= 0.5 or bool(vulnerability_types)

    return {
        "code_snippet": code_snippet[:100] + ("..." if len(code_snippet) > 100 else ""),
        "is_vulnerable": is_unsafe,
        "probability": round(float(proba), 4),
        "confidence": "HIGH" if proba > 0.7 else ("MEDIUM" if proba > 0.5 else "LOW"),
        "vulnerability_types": vulnerability_types if vulnerability_types else None
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    code_snippet = data.get('code', '')

    if not code_snippet:
        return jsonify({"error": "No code provided"}), 400

    result = predict_vulnerability(code_snippet)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
