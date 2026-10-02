# RedFlag — Phishing & Fraud Alert Platform

**A multilingual, multimodal, explainable fraud-alert platform for the South Chennai threat landscape.**

NextGen AI Hacks 2026 · Track: Digital Trust, Forensics & Anti-Fraud Systems

> Paste it, screenshot it, or scan it. RedFlag tells you what is suspicious, **why** it is
> suspicious, whether it resembles a known campaign, and what to do next.

RedFlag accepts a suspicious SMS/WhatsApp message, a URL, a screenshot or a QR-derived link.
It normalizes the evidence, performs OCR where needed, understands Tamil / English / Tanglish
scam intent, analyzes URLs and extracted entities, computes an evidence-backed 0–100 risk
score, explains the red flags, and enables community reporting.

The loop is **Detect → Explain → Correlate → Report → Learn → Protect.** Repeated phones,
domains, UPI IDs, handles and message templates become campaign relationships, turning
isolated warnings into reusable regional threat intelligence.

---

## 1. Quick start (fresh checkout)

**Prerequisites:** Python 3.11+, Node 18+, npm.

```bash
git clone https://github.com/nandv2007/RedFlag--Phishing-and-Fraud-Alert-Platform.git
cd RedFlag--Phishing-and-Fraud-Alert-Platform

# Optional but recommended — enables screenshot OCR (incl. Tamil) and QR decoding.
# Without these RedFlag still runs; the checks simply report as "degraded".
sudo apt-get install -y tesseract-ocr tesseract-ocr-tam libzbar0

./run.sh                 # installs deps, builds the dataset, trains the model,
                         # seeds the demo, measures metrics, then serves everything
```

Then open **http://localhost:5173**.

| Sub-command | What it does |
|---|---|
| `./run.sh` | Full sequence: setup → seed → evaluate → serve |
| `./run.sh setup` | Install Python + npm deps, build dataset, train classifier |
| `./run.sh seed` | Reset and reseed the repeatable demo database |
| `./run.sh evaluate` | Run `backend/evaluate.py` and publish `metrics.json` to the UI |
| `./run.sh test` | Run the full test suite (118 tests) |
| `./run.sh serve` | Backend on `:8000`, frontend dev server on `:5173` |

<details>
<summary>Manual start (no script)</summary>

```bash
pip install -r requirements.txt
cd backend
python data/build_dataset.py            # synthetic dataset, disjoint train/test
python -m app.intel.classifier --train  # optional TF-IDF classifier
python seed_demo.py                     # repeatable demo graph
python evaluate.py                      # writes data/metrics.json
cp data/metrics.json ../frontend/public/metrics.json
python -m uvicorn app.main:app --reload --port 8000

# in a second terminal
cd frontend && npm install && npm run dev
```
</details>

Copy `.env.example` to `backend/.env` to change limits, the database URL or CORS.
**No secrets are committed to this repository.**

---

## 2. What is in the box

### Screens

| Screen | Contents |
|---|---|
| **Analyze** | Four first-class inputs — Message, Link, Screenshot, QR — plus demo samples |
| **Result** | Risk dial, verdict, category, confidence, red flags, score breakdown, entities, actions |
| **Campaigns** | Interactive graph, timeline, shared indicators, infrastructure-rotation note |
| **Community** | Moderated public feed (contact details masked) + indicator search |
| **Threat pulse** | Volume trend, category/language/locality breakdown, top indicators, **measured** metrics |
| **Moderate** | Review queue with duplicate candidates: approve / merge / reject, campaign status |
| **Classic scanner** | The original light-theme URL + SMS scanner, fully preserved |

A result is reachable in **≤ 3 clicks** from landing: pick an input card → paste/upload → Analyze.

### API

Everything the UI does is available over HTTP. Interactive docs at `/api/v1/docs`.

```
POST /api/analyze/text      POST /api/analyze/url
POST /api/analyze/image     POST /api/analyze/qr
GET  /api/analysis/{id}     GET  /api/analysis/{id}/evidence
POST /api/reports           GET  /api/reports/queue
POST /api/reports/{id}/approve | /reject | /merge
GET  /api/feed              GET  /api/entities        GET /api/entities/{type}/{value}
GET  /api/campaigns         GET  /api/campaigns/{id}  POST /api/campaigns/{id}/status
GET  /api/pulse             GET  /api/health          GET /api/meta

# preserved baseline
POST /api/v1/scan/url       POST /api/v1/scan/sms     GET /api/v1/threats/known
GET  /health
```

A browser extension, Telegram/WhatsApp bot or mobile client can reuse these directly — the
analysis endpoints are stateless JSON and need no session.

---

## 3. The canonical result object

Every input type — text, URL, image, QR — converges on **one** schema. There is no separate
business logic per mode.

```jsonc
{
  "analysis_id": "an_7d4ff0…", "input_type": "text", "language": "ta-en",
  "verdict": "CRITICAL", "risk_score": 98, "confidence": 0.95,
  "scam_category": "kyc_account_freeze",
  "summary": "Do not act on this message. …",
  "red_flags": [ { "title": "…", "detail": "…", "evidence_span": "…", "kind": "observed" } ],
  "risk_factors": [ { "name": "…", "family": "message_intent", "weight": 8.0,
                      "observed_value": "…", "evidence_span": "…", "source": "rule:intent" } ],
  "entities": [ { "type": "upi", "raw_value": "…", "display_value": "…",
                  "canonical_hash": "…", "evidence_span": "…" } ],
  "campaign_links": [ { "campaign_id": "camp_…", "reasons": [ { "relation": "same_indicator" } ] } ],
  "recommended_actions": [ { "priority": "critical", "action": "…", "why": "…" } ],
  "model_version": "redflag-intel-1.0.0", "degraded_checks": [], "created_at": "…"
}
```

### Scoring — interpretable, decomposable, capped

```
Risk = min(100, Σ capped family contributions − legitimate-message credit)
```

| Signal family | Cap | What it measures |
|---|---:|---|
| Message intent | 25 | Urgency, threat, credential/payment request, reward bait, authority, remote access |
| URL technical risk | 25 | Host/path/encoding/typosquat/homoglyph/shortener/redirect signals |
| Entity reputation | 20 | Previously **reported** phone / domain / UPI / handle |
| Campaign similarity | 15 | Shared indicator or message-template overlap |
| Context anomalies | 15 | Brand ↔ domain mismatch, bank message from a personal number, pay-to-stranger UPI |

Bands: **0–24 Low · 25–49 Caution · 50–74 High · 75–100 Critical.**
These are product thresholds, not legal truth.

Every contribution is stored as a `risk_factor` with its weight, observed value, evidence
span and source — visible in the UI under **“Show how we know”** and in the database table
`risk_factors`. Judges can inspect exactly why a number moved.

---

## 4. Tamil / English / Tanglish

| Stage | Implementation |
|---|---|
| Language ID | Script-block ratios + Tanglish lexicon hits + English stopword share → `ta` / `en` / `ta-en` |
| Normalization | Unicode NFC, safe casing, letter-elongation collapse. **URLs, emails, UPI IDs and numbers are protected from every edit** so evidence stays byte-accurate |
| Transliteration | ~110 Tanglish and ~100 Tamil-script entries fold to canonical English concepts; the original wording is always retained and shown |
| Intent | Urgency, threat, credential request, payment request, reward bait, authority impersonation, remote access, contact pivot |
| Scam class | phishing link, KYC/freeze, impersonation, refund/cashback, job/investment, lottery/prize, delivery, remote access, utility bill, legitimate |
| Evidence spans | Every signal returns the exact fragment it matched |

**Language is a routing signal, never a verdict.** A Tamil message is not suspicious because
it is Tamil — there is a regression test (`test_language_alone_is_not_a_verdict`) that fails
the build if that ever changes.

---

## 5. Multimodal input

- **Text** — SMS, chat, email snippets.
- **URL** — direct, or extracted from the message.
- **Image** — Tesseract OCR with `eng+tam`, per-word confidence, bounding boxes, and an
  **editable text box** so the user corrects OCR before analysis. The UI always shows
  “OCR may be wrong”, and nothing is ever invented to fill a gap.
- **QR** — decoded locally with pyzbar (OpenCV fallback). The destination is **displayed and
  never opened automatically**, then sent through URL analysis.

If Tesseract or zbar is absent the request still succeeds: the adapter returns
`available: false` with a reason, the API lists it under `degraded_checks`, and the UI shows
an amber banner inviting manual text entry.

---

## 6. Campaign graph

For the MVP, correlation is **deterministic and explainable** rather than clever:

- **Hard indicators** — domain, phone, UPI, handle, email, IFSC — merge observations.
- **Message fingerprint** — digits and URLs stripped, remaining tokens sorted and hashed, so
  the same template with a rotated link or amount still collides.

Relations stored: `reported_in`, `mentions`, `same_indicator`, `shares_template`, `similar_to`.

The campaign view shows the graph, the sighting timeline, the indicators shared by 2+ reports,
and an infrastructure-rotation note. Shared infrastructure is presented as **evidence of
overlap, not proof of identical actors**.

Only **moderated** reports enter the graph. That is the answer to report poisoning.

---

## 7. Measured evaluation — not fabricated

Run it yourself:

```bash
cd backend && python evaluate.py
```

It evaluates on a **held-out validation split whose templates are disjoint from training**
(the build script asserts this), with community reputation and campaign boosts **disabled**
so the number cannot be inflated by the seed data.

Latest run on this machine (`backend/data/metrics.json`, 124 held-out samples):

| Metric | Target | Measured |
|---|---|---|
| Precision | ≥ 0.90 | **1.000** |
| Recall | ≥ 0.90 | **0.935** |
| F1 | — | **0.967** |
| False-positive rate | low | **0.000** |
| Latency P95 | < 2.5 s | **~190 ms** |
| Explanation coverage | 100 % | **100 %** |
| OCR accuracy | — | **not measured** (no labeled screenshot set ships here) |

Per-language accuracy: `en` 1.00 · `ta-en` 0.96 · `ta` 0.67 (12 samples).

These describe this synthetic dataset only. They are **not** a claim about field performance,
and the UI repeats that caveat next to the numbers. Anything we did not measure is labelled
*“not measured”* rather than guessed.

---

## 8. Privacy, safety & security

| Control | Implementation |
|---|---|
| Data minimization | Narratives are private by default; only normalized indicators become public |
| Pseudonymous joins | Entities join on `sha256(type:canonical)[:32]`, not raw values |
| Public feed redaction | Phone numbers, emails and long digit strings are masked before publication |
| Consent | Reports carry an explicit consent flag; without it nothing is published |
| Upload hardening | MIME allowlist, 8 MB ceiling, magic-byte sniffing (a renamed `.exe` is rejected) |
| Rate limiting | Sliding window per IP per endpoint group (analyze / report / read) |
| Safe errors | Unhandled exceptions return a correlation ID only — never a stack trace or path |
| Headers | `nosniff`, `SAMEORIGIN`, `no-referrer`, restrictive `Permissions-Policy` |
| Secrets | None in the repo; `.env.example` only; `/api/health` reports dependency state without exposing keys |
| Audit | `analyses` stores id, timestamp, model version and the full decomposed decision |
| Data provenance | 100 % synthetic training and demo data, generated by `backend/data/build_dataset.py` |

**No live external reputation feed is connected in this build.** `/api/health` says so
explicitly (`external_threat_feeds: local_only`) rather than implying a capability we do not
have. If a feed fails or is absent, local analysis still returns a useful result and the UI
lists which checks were unavailable.

---

## 9. Architecture

```
frontend/  React 19 + TypeScript + Vite + Tailwind v4
  src/intel/        RedFlag Intelligence console (dark security theme)
    IntelConsole    shell, nav, health pill
    AnalyzeHub      four first-class inputs + OCR correction flow
    ResultView      score, red flags, breakdown, entities, actions, audit trail
    CampaignView    deterministic SVG graph, timeline, shared indicators
    Community       report form, public feed, moderation queue, threat pulse
  src/components/   preserved classic scanner (light theme)

backend/   FastAPI
  app/api/intel_routes.py   contract endpoints
  app/api/endpoints.py      preserved /api/v1 baseline
  app/core/security.py      rate limits, body ceiling, safe errors, headers
  app/intel/
    language.py    Tamil/English/Tanglish detection + normalization
    entities.py    phone/url/domain/email/UPI/handle/brand/amount/txn extraction
    intent.py      intent families + scam classes with evidence spans
    classifier.py  optional TF-IDF + logistic regression
    adapters.py    OCR and QR, both degrading gracefully
    analyzer.py    evidence fusion → canonical AnalysisResult
    graph.py       fingerprints, correlation, campaign graph, threat pulse
    reports.py     reporting, duplicate detection, moderation, evidence bundle
    db.py          SQLAlchemy models (SQLite demo / PostgreSQL deployment)
  app/services/    preserved URL engine: entropy, homograph, brand, lexical,
                   network, normalizer, expander, risk scorer, SMS analyzer
  data/            synthetic dataset generator, validation split, metrics
  seed_demo.py     repeatable demo
  evaluate.py      measured metrics
```

Database tables: `users`, `analyses`, `evidence`, `entities`, `analysis_entities`,
`risk_factors`, `reports`, `relationships`, `campaigns`.

---

## 10. Three-minute demo script

| Time | Action | Takeaway |
|---|---|---|
| 0:00–0:20 | Open RedFlag; one-line problem statement | Clarity |
| 0:20–0:55 | **Analyze → Message → “Tanglish KYC freeze”** sample → Analyze | Regional NLP |
| 0:55–1:20 | Point at the 98/100 dial, the red flags, **Show how we know** | Explainable AI |
| 1:20–1:45 | **Screenshot** tab → upload the same message as an image → edit OCR → Analyze | Multimodal |
| 1:45–2:10 | **Campaigns** → KYC cluster → shared phone + domain light up | Community intelligence |
| 2:10–2:35 | Result → **Report this incident** → **Moderate** → Approve → graph grows | Closed loop |
| 2:35–2:55 | Scroll to **What to do next** → 1930 / cybercrime.gov.in | Impact |
| 2:55–3:00 | Closing line | Memorable |

Re-run `./run.sh seed` before each rehearsal to get an identical starting dashboard.

Also worth showing: the **Legitimate bank SMS** sample scores 12/LOW — RedFlag is not a
machine that shouts "scam" at everything.

---

## 11. Testing

```bash
./run.sh test      # or: python -m pytest -q
```

**118 tests.** `backend/tests/test_intel_pipeline.py` and `test_intel_api.py` are written as
acceptance tests against the implementation contract — each one names the P0 row it protects:
baseline preservation, unified schema, score+verdict+evidence, all three languages, URL
evidence, OCR correction, entity extraction, community reporting, campaign clustering,
duplicate merge, polished result contract, seeded demo, and security basics.

---

## 12. Honest limitations

- Trained and evaluated on **synthetic** data. Real-world precision and recall will differ.
- Pure-Tamil-script recall is the weakest arm (0.67 on 12 samples) and is the first thing
  more data should fix.
- No live threat feed, no WHOIS/domain-age lookup, no sandbox detonation of links.
- The campaign graph is deterministic overlap, not graph ML.
- RedFlag is **risk assessment and decision support**. It does not prove fraud, is not a legal
  determination, and never infers who owns an indicator.
- Never take an irreversible financial action based on the score alone.

## 13. Roadmap

- **Phase 2 — Public beta:** browser extension, mobile client, threat-feed ingestion, a
  stronger Indic multilingual model.
- **Phase 3 — Ecosystem:** messaging integrations, institutional dashboards, partner APIs.
- **Phase 4 — Advanced intelligence:** graph ML, temporal anomaly detection, cross-platform
  correlation, privacy-preserving analytics.

---

**Report cyber-fraud in India: call 1930 or file at cybercrime.gov.in.**
