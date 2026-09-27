# CyberShield: Community Threat Intelligence & Fraud Detection Platform

CyberShield is a community-focused cybersecurity and threat-intelligence platform designed to detect malicious phishing URLs, digital financial scams, and fraudulent campaigns with native multilingual support (English, Tamil, and Tanglish).

---

## 🚀 Key Features (Phase 1 Implemented)

- **🌐 Real-Time URL Heuristics & Brand Impersonation**:
  - Analyzes Shannon entropy, subdomain depth, IP-based URLs, obfuscated symbols (`@`), and high-abuse TLDs (`.xyz`, `.top`, `.club`, etc.).
  - Levenshtein-distance fuzzy matching to detect brand impersonation against major banks and utilities (SBI, HDFC, ICICI, Paytm, PhonePe, TNEB, etc.).
- **💬 Multilingual Message & Social Engineering NLP**:
  - Detects scams in **English**, **Tamil** script, and **Tanglish** (phonetic Tamil in Latin script).
  - Flags social engineering signals: artificial urgency, fear/service disconnection threats, credential/OTP demands, and financial lures.
  - Granular taxonomy classification: `BANKING_FRAUD`, `KYC_EXPIRY`, `UPI_FRAUD`, `ELECTRICITY_BILL`, `LOTTERY_PRIZE`, `JOB_SCAM`, `OTP_THEFT`.
- **🔍 Indian Entity Extractor**:
  - Extracts Indian mobile numbers (`+91`), UPI handles (`user@bank`), URLs, domains, and targeted organizations.
- **🛡️ Threat Intelligence Cross-Referencing**:
  - Cross-checks extracted indicators against known threat feeds and verified community records.
- **⚖️ Dynamic 0–100 Risk Scorer**:
  - Provides a transparent, composite risk assessment (`SAFE_LOW`, `SUSPICIOUS`, `HIGH_RISK`, `CRITICAL`) with granular contributing factors and actionable citizen safety advice.

---

## 🛠️ Setup & Running

### 1. Activate Virtual Environment
```bash
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Automated Tests
```bash
python -m pytest -v
```

### 4. Start the FastAPI Server
```bash
python -m uvicorn app.main:app --reload --port 8000
```
- Interactive API Docs (Swagger): [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- Alternative Docs (ReDoc): [http://localhost:8000/api/v1/redoc](http://localhost:8000/api/v1/redoc)
- Health Check: [http://localhost:8000/health](http://localhost:8000/health)

---

## 📡 API Endpoints

### 1. `POST /api/v1/scan/url`
Scan a URL for phishing heuristics and brand impersonation:
```json
{
  "url": "http://sbi-kyc-update-portal.xyz/login"
}
```

### 2. `POST /api/v1/scan/message`
Scan an SMS or chat message in English, Tamil, or Tanglish:
```json
{
  "message": "Ungal TNEB power bill kattavum udane illaiyendral innum 2 hours la current vettpadum. Contact 9840123456 or pay to tneb.officer984@okhdfcbank"
}
```

### 3. `POST /api/v1/scan/unified`
Multi-vector scan analyzing message text, embedded links, and extracted entities concurrently:
```json
{
  "text": "Your account has been suspended! Restore now: http://hdfc-verify.xyz/auth",
  "url": "http://hdfc-verify.xyz/auth"
}
```

---

## 🧭 Project Roadmap

- [x] **Phase 1: Core Detection Engines & Scorer (Completed)**
- [ ] **Phase 2: Community Fraud Reporting & Verification Pipeline**
- [ ] **Phase 3: Entity Relationship Analysis & Graph Campaign Clustering**
- [ ] **Phase 4: GenAI Explanations & Threat Intelligence Analytics**
- [ ] **Phase 5: Modern Unified Web Dashboard & Visualizer**
