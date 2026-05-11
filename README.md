# 🔐 CryptoGuard

> **ML-Powered Vulnerability Detection for C/C++ Code**

CryptoGuard is a static analysis tool that detects security vulnerabilities in C/C++ code snippets using a hybrid approach — combining a trained machine learning model with rule-based pattern matching. It exposes a simple Flask REST API and a frontend interface, making it easy to integrate into development workflows.

---

## 📌 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Vulnerability Categories](#vulnerability-categories)
- [Dataset](#dataset)
- [Model Training](#model-training)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Example Usage](#example-usage)
- [Future Improvements](#future-improvements)

---

## Overview

Security vulnerabilities in C/C++ code — like buffer overflows, command injection, and memory mismanagement — are among the most exploited bugs in production systems. CryptoGuard automates the detection of these patterns using:

- **TF-IDF vectorization** to capture statistical patterns from code tokens
- **A trained ML classifier** (Logistic Regression / Random Forest / Gradient Boosting) to predict vulnerability probability
- **Rule-based pattern matching** that flags known dangerous C/C++ functions

Both signals are combined to produce a final verdict with a confidence level.

---

## How It Works

```
User submits C/C++ code snippet
        │
        ▼
┌─────────────────────────────┐
│   TF-IDF Vectorization      │  ← Tokenizes code into a sparse feature matrix
│ + Code Length Feature       │  ← Appended as numeric feature via hstack
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   Trained ML Model          │  ← Predicts vulnerability probability (0.0 – 1.0)
│   (best_model.pkl)          │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   Rule-Based Pattern Check  │  ← Scans for dangerous function calls
│   (VULNERABILITY_PATTERNS)  │
└────────────┬────────────────┘
             │
             ▼
   is_vulnerable = (ML prob ≥ 0.5) OR (any rule matched)
   confidence    = HIGH (>0.7) | MEDIUM (>0.5) | LOW
```

---

## Vulnerability Categories

| Category | Dangerous Patterns Detected |
|---|---|
| **Buffer Overflow** | `strcpy()`, `strcat()`, `gets()`, `sprintf()` |
| **Command Injection** | `system()`, `popen()`, `exec()`, `ShellExecute()` |
| **Memory Issues** | `malloc()`, `free()`, `realloc()`, `memset()` |
| **Format String** | `printf()`, `fprintf()`, `sprintf()`, `snprintf()` |

---

## Dataset

- **Source:** `cleaned_vulnerabilities.csv` — a curated dataset of labeled C/C++ code snippets
- **Raw Data:** `all_c_cpp_release2.0.csv` (~56MB) — original corpus before preprocessing
- **Preprocessing:** Removed duplicates, normalized labels, extracted TF-IDF and length features

---

## Model Training

Training was done in `Ml_Project.ipynb`. Three classifiers were evaluated:

| Model | Notes |
|---|---|
| Logistic Regression | Fast, interpretable baseline |
| Random Forest | Handles non-linear patterns well |
| Gradient Boosting | Best overall F1-score |

- Features: **TF-IDF matrix** (code tokens) + **code length** (numeric) — combined via `scipy.sparse.hstack`
- Final model saved as `best_model.pkl`
- TF-IDF transformer saved as `tfidf_vectorizer.pkl`
- Selection criterion: **F1-score** (balances precision and recall for imbalanced security datasets)

---

## Project Structure

```
Cryptoguard/
├── project.py                  # Flask app — prediction logic + API routes
├── best_model.pkl              # Trained ML model (serialized via joblib)
├── tfidf_vectorizer.pkl        # Fitted TF-IDF vectorizer (serialized via joblib)
├── Ml_Project.ipynb            # Model training and evaluation notebook
├── cleaned_vulnerabilities.csv # Preprocessed labeled dataset
├── all_c_cpp_release2.0.csv    # Raw C/C++ code corpus
├── safe.c                      # Example: safe C code (uses strncpy, fgets)
├── test_local_file.c           # Example: unsafe C code (uses strcpy, gets, malloc)
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
git clone https://github.com/Bavithbabu/cryptoguard.git
cd cryptoguard/Cryptoguard
pip install flask scikit-learn joblib numpy scipy
```

### Run the Server

```bash
python project.py
```

The server starts at `http://localhost:5000`.

---

## API Reference

### `POST /predict`

Analyzes a C/C++ code snippet for vulnerabilities.

**Request Body:**

```json
{
  "code": "<your C/C++ code snippet here>"
}
```

**Response:**

```json
{
  "code_snippet": "char buffer[10]; strcpy(buffer, input);...",
  "is_vulnerable": true,
  "probability": 0.8200,
  "confidence": "HIGH",
  "vulnerability_types": ["buffer_overflow"]
}
```

**Response Fields:**

| Field | Type | Description |
|---|---|---|
| `code_snippet` | string | First 100 chars of submitted code |
| `is_vulnerable` | boolean | Final verdict (ML + rule-based) |
| `probability` | float | ML model's confidence score (0.0–1.0) |
| `confidence` | string | `HIGH` \| `MEDIUM` \| `LOW` |
| `vulnerability_types` | array / null | Rule-matched vulnerability categories |

**Error Response (400):**

```json
{
  "error": "No code provided"
}
```

---

## Example Usage

### Vulnerable Code

```c
void unsafe_function(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow risk
}
```

**Response:**
```json
{
  "is_vulnerable": true,
  "probability": 0.82,
  "confidence": "HIGH",
  "vulnerability_types": ["buffer_overflow"]
}
```

---

### Safe Code

```c
void safe_function(const char* input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);  // Bounded copy
    buffer[sizeof(buffer) - 1] = '\0';
}
```

**Response:**
```json
{
  "is_vulnerable": false,
  "probability": 0.12,
  "confidence": "LOW",
  "vulnerability_types": null
}
```

---

## Future Improvements

- [ ] **SHAP Explainability** — Show which tokens/patterns drove the prediction
- [ ] **Expand Vulnerability Categories** — Integer overflow, race conditions, use-after-free
- [ ] **Migrate to FastAPI** — Async support, auto-generated docs at `/docs`
- [ ] **Improve Frontend UI** — Better code editor with syntax highlighting
- [ ] **Feedback Loop** — Let users flag incorrect predictions to retrain the model
- [ ] **Expand Dataset** — Include real-world CVEs and exploit samples
- [ ] **File Upload Support** — Analyze entire `.c` / `.cpp` files, not just snippets

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | scikit-learn (Logistic Regression / Random Forest / Gradient Boosting) |
| Feature Engineering | TF-IDF (scikit-learn) + code length |
| Serialization | joblib |
| Backend | Flask |
| Numerical | NumPy, SciPy |

---

> Built by [Bavithbabu](https://github.com/Bavithbabu) — detecting what the eye misses, one snippet at a time.
