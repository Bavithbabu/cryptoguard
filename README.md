🔐 CryptoGuard – ML-Powered Vulnerability Detection for C/C++ Code
CryptoGuard is a hybrid machine learning system that detects security vulnerabilities in C/C++ code snippets. It combines statistical ML models with rule-based pattern matching to identify risky code — making it a powerful tool for static analysis and secure coding.

🚀 Features
✅ ML-based vulnerability prediction using TF-IDF + code length

🧠 Rule-based detection for known dangerous functions (e.g., strcpy, system)

📊 Probability scores with confidence levels (HIGH, MEDIUM, LOW)

🌐 Flask API for easy integration

🖥️ Frontend interface for submitting code snippets


📁 Dataset
Used a curated dataset of C/C++ code snippets labeled as vulnerable or safe:

cleaned_vulnerabilities.csv

Preprocessed to remove duplicates, normalize labels, and extract features


🧠 Model Training
TF-IDF vectorization of code

Logistic Regression, Random Forest, and Gradient Boosting models tested

Final model selected based on F1-score and saved as best_model.pkl


🛠️ How It Works
User submits code snippet

Backend transforms code using TF-IDF + length

Model predicts vulnerability probability

Rule-based patterns checked

Final decision returned with confidence level


📦 Installation
bash
git clone https://github.com/Bavithbabu/cryptoguard.git
cd cryptoguard/Cryptoguard
pip install -r requirements.txt
python app.py


📬 API Usage
POST /predict

json
{
  "code": "char buffer[10]; strcpy(buffer, input);"
}


Response:

json
{
  "is_vulnerable": true,
  "probability": 0.82,
  "confidence": "HIGH",
  "vulnerability_types": ["buffer_overflow"]
}



💡 Future Improvements
Add SHAP explainability

Improve frontend UI

Expand dataset with real-world exploits

Add feedback loop for retraining


