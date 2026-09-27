# RedFlag: Real-Time Malicious URL & Phishing Detection Platform

**RedFlag** is a specialized cybersecurity platform built to inspect, identify, and explain malicious URLs, phishing traps, typosquatting attacks, and deceptive links in real time.

---

## 🎨 Color Palette & Design
- **`#F5F5F5`**: Canvas & Background
- **`#DFF1F1`**: Soft Tint Cards & Sections
- **`#BBD5DA`**: Accent Borders & Separators
- **`#FF0000`**: RedFlag Brand Alert & Primary Actions

---

## 📁 Architecture Layout

```
Phishing detector/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── endpoints.py      # /api/v1/scan/url, /api/v1/scan/quick, /threats/known
│   │   │   └── __init__.py       # Router aggregator
│   │   ├── core/
│   │   │   └── config.py         # App configuration & risk thresholds
│   │   ├── models/
│   │   │   └── schemas.py        # Pydantic models (URL features, categories, responses)
│   │   ├── services/
│   │   │   ├── url_analyzer.py   # Heuristic entropy, brand lookalikes & threat feeds
│   │   │   └── risk_scorer.py    # 0–100 composite risk scoring engine
│   │   ├── conftest.py           # Path configuration
│   │   └── main.py               # FastAPI entry point & static frontend server
│   ├── tests/
│   │   ├── test_api.py           # API endpoints test suite
│   │   ├── test_risk_scorer.py   # Composite scoring & threshold test suite
│   │   └── test_url_analyzer.py  # Structural heuristics & entropy tests
│   └── requirements.txt          # Python dependencies
│
├── frontend/
│   ├── css/
│   │   └── style.css             # Palette styles (#F5F5F5, #DFF1F1, #BBD5DA, #FF0000)
│   ├── js/
│   │   └── app.js                # Frontend controller & URL inspector logic
│   └── index.html                # Clean landing page matching reference design
│
├── pytest.ini                    # Pytest configuration
├── .gitignore
└── README.md
```

---

## 🔍 Core Detection Capabilities

1. **Shannon Entropy Engine**:
   - Calculates mathematical entropy across domain names to flag Algorithmically Generated Domains (DGA) and random token stuffing.
2. **Brand Typosquatting & Impersonation Defense**:
   - Uses Levenshtein distance and prefix/suffix matching to catch deceptive lookalikes mimicking top banks, payment apps, and tech brands (SBI, HDFC, ICICI, Paytm, GPay, Google, Apple, Microsoft, PayPal).
3. **Structural Heuristics & Evasion Checks**:
   - High-abuse TLDs (`.xyz`, `.top`, `.club`, `.work`, `.cam`, `.zip`, `.live`, etc.).
   - Raw IP address hosts (bypassing DNS reputation).
   - Obfuscated `@` symbol redirect tricks.
   - Non-standard network ports (e.g. `:8080`, `:8443`).
   - Double slashes (`//`) in path segments and percent encoding.
   - Excessive URL length & subdomain depth (>= 3 subdomains).
4. **Threat Intelligence Correlation**:
   - Instant cross-referencing against verified phishing domain feeds.

---

## 🚀 How to Run and Test

### 1. Run Automated Unit & Integration Tests
```powershell
.\.venv\Scripts\python -m pytest -v
```
*(All 14 tests run in under 0.5s).*

### 2. Start the Server
```powershell
cd backend
..\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
```

### 3. Open in Browser
- **Landing Page**: [http://localhost:8000/](http://localhost:8000/)
- **Interactive Swagger Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
