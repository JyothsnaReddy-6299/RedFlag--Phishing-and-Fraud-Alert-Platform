# CyberShield: Community Threat Intelligence & Fraud Detection Platform

CyberShield is a community-focused cybersecurity and threat-intelligence platform designed to detect malicious phishing URLs, digital financial scams, and fraudulent campaigns with native multilingual support (English, Tamil, and Tanglish), relationship graph analysis, and crowdsourced reporting.

---

## 📁 Clean Architecture Layout

The codebase is organized into separated **`backend`** and **`frontend`** directories:

```
Phishing detector/
├── backend/
│   ├── app/
│   │   ├── api/                  # FastAPI REST endpoints
│   │   │   ├── endpoints.py      # Real-time URL & Message scanners
│   │   │   ├── report_endpoints.py # Community reporting & verification
│   │   │   └── graph_endpoints.py  # Graph & campaign detection API
│   │   ├── core/                 # Configuration & settings
│   │   ├── db/                   # SQLAlchemy models & SQLite session
│   │   ├── models/               # Pydantic schemas (scans, reports, graphs)
│   │   ├── services/             # Core detection & intelligence engines
│   │   │   ├── url_analyzer.py   # Heuristic entropy & brand lookalike engine
│   │   │   ├── message_analyzer.py # Multilingual Tamil/Tanglish/English NLP
│   │   │   ├── entity_extractor.py # Regex/NER (+91, UPI, URLs, domains)
│   │   │   ├── threat_engine.py  # Static feeds + Dynamic DB intelligence
│   │   │   ├── risk_scorer.py    # 0–100 risk scoring & mitigation advice
│   │   │   ├── report_engine.py  # Crowdsourced reporting & verification
│   │   │   └── graph_engine.py   # NetworkX campaign clustering
│   │   ├── utils/                # Privacy-first PII masking utilities
│   │   └── main.py               # FastAPI entry point
│   ├── tests/                    # 24 unit & integration tests
│   └── requirements.txt          # Python dependencies
│
├── frontend/
│   ├── css/
│   │   └── style.css             # Modern styling & canvas themes
│   ├── js/
│   │   └── app.js                # Frontend controller & Vis.js graph visualizer
│   └── index.html                # Responsive web dashboard
│
├── .gitignore
└── README.md
```

---

## 🛠️ How to Run and Test

### 1. Run Automated Backend Tests
From the root directory or inside `backend/`:
```powershell
.\.venv\Scripts\python -m pytest backend/tests -v
```
*(All 24 automated tests will run and pass.)*

---

### 2. Start the Backend & Frontend Server
Run the FastAPI application from inside `backend/`:
```powershell
cd backend
..\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
```

---

### 3. Open the Web Application
Open your web browser and navigate to:
👉 **[http://localhost:8000/](http://localhost:8000/)**

- **Interactive API Documentation (Swagger)**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 🧭 Implemented Features

- [x] **Phase 1: Core Detection Engines & Scorer**
  - URL structural heuristics, Shannon entropy, brand impersonation fuzzy matcher.
  - Multilingual Tamil, Tanglish, and English message analyzer with social-engineering cues.
  - Indian entity extractor (+91 phone numbers, UPI handles, domains, URLs, organizations).
  - Dynamic 0–100 composite risk scoring engine.
- [x] **Phase 2: Community Fraud Reporting & Verification Pipeline**
  - Crowdsourced reporting with privacy-first data masking (masked phone numbers and UPIs).
  - Analyst verification workflow (`PENDING` ➔ `VERIFIED` / `REJECTED`).
  - Dynamic intelligence accumulation (verified community reports instantly feed the live scanner).
- [x] **Phase 3: Entity Relationship Analysis & Graph Campaign Detection**
  - NetworkX multi-relational graph connecting Reports, Phones, UPIs, Domains, Brands, Locations.
  - Infrastructure clustering algorithm identifying syndicated fraud campaigns.
  - 2-hop ego neighborhood investigator search.
- [x] **Frontend: Interactive Web Dashboard**
  - Real-time scanner with sample presets.
  - Community report submission form.
  - Live crowdsourced threat feed.
  - Vis.js interactive campaign graph visualizer.
  - Deep entity investigation search portal.
