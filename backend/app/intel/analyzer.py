"""Unified multimodal analysis engine (contract sections 8, 13, 18).

Every input type — text, url, image(OCR), qr — converges on ONE canonical
AnalysisResult so there is no separate business logic per mode.

Canonical result object (contract p.15):
  analysis_id, input_type, language, verdict, risk_score, confidence,
  scam_category, summary, red_flags[], risk_factors[], entities[],
  campaign_links[], recommended_actions[], model_version, degraded_checks[],
  created_at

Scoring is an interpretable weighted sum capped at 100:
  message intent      0-25
  url technical risk  0-25
  entity reputation   0-20
  campaign similarity 0-15
  context anomalies   0-15
Every contribution is stored as a risk_factor with its evidence span so a
judge can inspect exactly why the number moved.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.intel import MODEL_VERSION, classifier, entities as ent_mod, graph, language
from app.intel import db as m
from app.intel.intent import SCAM_CLASSES, classify

# ---------------------------------------------------------------------------
# Bands (contract section 13) — product thresholds, not legal truth.
# ---------------------------------------------------------------------------
BANDS = [(0, 24, "LOW", "Low risk"),
         (25, 49, "CAUTION", "Caution"),
         (50, 74, "HIGH", "High risk"),
         (75, 100, "CRITICAL", "Critical risk")]

CAPS = {"message_intent": 25.0, "url_technical": 25.0, "entity_reputation": 20.0,
        "campaign_similarity": 15.0, "context_anomaly": 15.0}

INTENT_WEIGHTS = {
    "credential_request": 10.0,
    "threat": 8.0,
    "payment_request": 7.5,
    "remote_access": 9.0,
    "urgency": 6.0,
    "reward_bait": 6.5,
    "authority_impersonation": 6.5,
    "contact_pivot": 4.0,
}

INTENT_LABEL = {
    "urgency": "Artificial time pressure",
    "threat": "Threat of loss or penalty",
    "credential_request": "Asks for credentials (OTP/PIN/password)",
    "payment_request": "Asks you to pay or transfer money",
    "reward_bait": "Too-good-to-be-true reward",
    "authority_impersonation": "Claims to be an authority or official",
    "remote_access": "Pushes remote-access or sideloaded apps",
    "contact_pivot": "Pushes you to a private channel",
}


def band(score: int):
    for lo, hi, key, label in BANDS:
        if lo <= score <= hi:
            return key, label
    return "CRITICAL", "Critical risk"


class RiskFactorBuilder:
    def __init__(self) -> None:
        self.items: List[dict] = []

    def add(self, name: str, family: str, weight: float, observed_value: str,
            evidence_span: str = "", source: str = "rule") -> None:
        if weight <= 0:
            return
        self.items.append({
            "name": name, "family": family, "weight": round(weight, 2),
            "observed_value": observed_value,
            "evidence_span": evidence_span, "source": source,
        })

    def family_total(self, family: str) -> float:
        return sum(i["weight"] for i in self.items if i["family"] == family)

    def capped(self) -> Dict[str, float]:
        return {fam: min(CAPS[fam], self.family_total(fam)) for fam in CAPS}


# ---------------------------------------------------------------------------
# URL sub-analysis, reusing the preserved baseline engine
# ---------------------------------------------------------------------------
def analyze_urls(urls: List[str], degraded: List[dict]) -> List[dict]:
    from app.services.risk_scorer import url_risk_scorer
    from app.services.url_analyzer import url_analyzer

    out: List[dict] = []
    for raw in urls[:5]:
        try:
            features = url_analyzer.analyze(raw)
            try:
                threat_match = url_analyzer.check_threat_feeds(features.domain)
            except Exception as exc:
                threat_match = None
                degraded.append({"check": "threat_feed_lookup", "status": "unavailable",
                                 "reason": str(exc)[:200]})
            res = url_risk_scorer.evaluate(features, threat_match)
            out.append(res.model_dump() if hasattr(res, "model_dump") else dict(res))
        except Exception as exc:
            degraded.append({"check": "url_engine", "status": "failed",
                             "target": raw, "reason": str(exc)[:200]})
    return out


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def analyze(text: str, *, input_type: str = "text",
            sender_id: Optional[str] = None,
            session: Optional[Session] = None,
            ocr: Optional[dict] = None,
            qr: Optional[dict] = None,
            extra_urls: Optional[List[str]] = None,
            persist: bool = True,
            user_id: Optional[str] = None) -> dict:
    started = time.perf_counter()
    degraded: List[dict] = []
    analysis_id = "an_" + uuid.uuid4().hex[:12]
    created_at = datetime.now(timezone.utc)

    # ---------------- 1. Normalize + language ----------------
    norm = language.normalize(text or "")
    lang = language.detect(norm.normalized)

    # ---------------- 2. Entities ----------------
    found = ent_mod.extract(norm.normalized, sender_id=sender_id)
    entity_dicts = [e.to_dict() for e in found]

    url_values = [e.raw_value for e in found if e.type == "url"]
    for u in (extra_urls or []):
        if u and u not in url_values:
            url_values.append(u)

    # ---------------- 3. Intent / scam class ----------------
    clf = None
    try:
        clf = classifier.predict(norm.folded or norm.normalized)
    except Exception as exc:                                   # pragma: no cover
        degraded.append({"check": "ml_classifier", "status": "unavailable",
                         "reason": str(exc)[:200]})
    if clf is None and classifier.status().get("available") is False:
        degraded.append({"check": "ml_classifier", "status": "unavailable",
                         "reason": classifier.status().get("reason") or "model not loaded"})

    intent = classify(norm.normalized, norm.folded, clf)

    # ---------------- 4. URL technical analysis ----------------
    url_reports = analyze_urls(url_values, degraded)

    rf = RiskFactorBuilder()
    red_flags: List[dict] = []

    # ---- family: message intent (0-25)
    for fam, sigs in intent.intents.items():
        w = INTENT_WEIGHTS.get(fam, 3.0)
        # Repeated hits in the same family add a little, with heavy damping.
        w = w * (1 + 0.25 * min(2, len(sigs) - 1))
        rf.add(name=INTENT_LABEL.get(fam, fam), family="message_intent", weight=w,
               observed_value=f"{len(sigs)} matching phrase(s)",
               evidence_span=sigs[0].evidence_span, source="rule:intent")
        red_flags.append({
            "title": INTENT_LABEL.get(fam, fam),
            "detail": f"Detected {len(sigs)} phrase(s) in this family.",
            "evidence_span": sigs[0].evidence_span,
            "family": "message_intent", "kind": "observed",
            "weight": round(min(CAPS["message_intent"], w), 1),
        })

    # A recognised scam TEMPLATE is itself evidence, separate from the
    # individual intent phrases that make it up.
    if intent.category_scores:
        top = max(intent.category_scores.values())
        rf.add(name=f"Matches a known {_pretty(intent.scam_category)} pattern",
               family="message_intent", weight=min(11.0, 4.5 + 1.8 * top),
               observed_value=f"{len([p for p in intent.category_scores if p])} candidate "
                              f"class(es); strongest: {intent.scam_label}",
               evidence_span=(intent.signals[0].evidence_span if intent.signals else ""),
               source="rule:scam_template")

    if intent.classifier_used and intent.classifier_category not in (None, "legitimate") \
            and intent.classifier_confidence >= 0.45:
        rf.add(name=f"Model suggests {_pretty(intent.classifier_category)}",
               family="message_intent",
               weight=8.0 * intent.classifier_confidence,
               observed_value=f"TF-IDF classifier confidence {intent.classifier_confidence:.2f}",
               evidence_span="", source="model:tfidf-logreg")

    # Benign markers reduce the intent family (false-positive control).
    benign_credit = 0.0
    if intent.benign_signals:
        benign_credit = min(10.0, 4.0 * len(intent.benign_signals))

    # ---- family: URL technical risk (0-25)
    worst_url = None
    for ur in url_reports:
        score = int(ur.get("risk_score", 0) or 0)
        if worst_url is None or score > int(worst_url.get("risk_score", 0) or 0):
            worst_url = ur
    if worst_url:
        score = int(worst_url.get("risk_score", 0) or 0)
        contrib = CAPS["url_technical"] * (score / 100.0)
        factors = worst_url.get("contributing_factors") or []
        rf.add(name="URL structural risk", family="url_technical", weight=contrib,
               observed_value=f"URL engine score {score}/100 for {worst_url.get('domain')}",
               evidence_span=worst_url.get("url", ""), source="engine:url_analyzer")
        for f in factors[:5]:
            red_flags.append({
                "title": "URL signal",
                "detail": f if isinstance(f, str) else str(f),
                "evidence_span": worst_url.get("url", ""),
                "family": "url_technical", "kind": "observed",
                "weight": None,
            })
        if worst_url.get("threat_intel_match"):
            rf.add(name="Domain in RedFlag threat list", family="url_technical",
                   weight=8.0, observed_value=str(worst_url.get("domain")),
                   evidence_span=worst_url.get("url", ""), source="threat_feed")
        if worst_url.get("is_shortened_url"):
            rf.add(name="Shortened link conceals the destination",
                   family="url_technical", weight=6.0,
                   observed_value=str(worst_url.get("shortener_domain")),
                   evidence_span=worst_url.get("url", ""), source="rule:url")
            red_flags.append({
                "title": "Shortened link hides its destination",
                "detail": f"Shortener: {worst_url.get('shortener_domain')}. "
                          f"Resolved destination: {worst_url.get('destination_url') or 'not resolved'}.",
                "evidence_span": worst_url.get("url", ""),
                "family": "url_technical", "kind": "observed", "weight": None,
            })
    elif url_values:
        degraded.append({"check": "url_engine", "status": "no_result",
                         "reason": "No URL could be parsed from the extracted candidates."})

    # ---- family: context anomalies (0-15)
    conflicts = ent_mod.brand_domain_conflict(found)
    for c in conflicts[:3]:
        rf.add(name="Brand / domain mismatch", family="context_anomaly", weight=7.0,
               observed_value=f"Mentions {c['brand']} but links to {c['linked_domain']}",
               evidence_span=c["evidence_span"], source="rule:context")
        red_flags.append({
            "title": "Brand does not match the link",
            "detail": (f"The message refers to {c['brand']}, but the link points to "
                       f"{c['linked_domain']}. Official domains: "
                       f"{c['official_domains'] or 'not on file'}."),
            "evidence_span": c["evidence_span"],
            "family": "context_anomaly", "kind": "observed", "weight": 7.0,
        })

    sender = next((e for e in found if (e.attributes or {}).get("role") == "sender"), None)
    if sender and sender.type == "phone" and any(e.type == "brand" for e in found):
        brand = next(e for e in found if e.type == "brand")
        rf.add(name="Bank/brand message from a personal number",
               family="context_anomaly", weight=6.0,
               observed_value=f"{brand.display_value} message sent from {sender.display_value}",
               evidence_span=sender.raw_value, source="rule:context")
        red_flags.append({
            "title": "Institutional message from a personal mobile number",
            "detail": (f"A message claiming to be from {brand.display_value} arrived from "
                       f"{sender.display_value}. Banks use registered sender IDs, not "
                       f"personal numbers."),
            "evidence_span": sender.raw_value,
            "family": "context_anomaly", "kind": "observed", "weight": 6.0,
        })

    upis = [e for e in found if e.type == "upi"]
    pressure = ("threat", "urgency", "authority_impersonation",
                "payment_request", "reward_bait")
    if upis and any(f in intent.intents for f in pressure):
        rf.add(name="Payment handle inside a pressure message",
               family="context_anomaly", weight=6.0,
               observed_value=upis[0].display_value,
               evidence_span=upis[0].raw_value, source="rule:context")
        red_flags.append({
            "title": "Pay-to-a-stranger UPI handle",
            "detail": (f"The message pushes you toward the UPI ID {upis[0].display_value}. "
                       "Legitimate refunds never require you to pay or approve a collect "
                       "request first."),
            "evidence_span": upis[0].raw_value,
            "family": "context_anomaly", "kind": "observed", "weight": 6.0,
        })

    phones = [e for e in found if e.type == "phone"
              and (e.attributes or {}).get("role") != "sender"]
    if phones and not url_values and any(
            f in intent.intents for f in ("payment_request", "reward_bait",
                                          "authority_impersonation", "remote_access")):
        rf.add(name="Callback number is the only channel offered",
               family="context_anomaly", weight=5.0,
               observed_value=phones[0].display_value,
               evidence_span=phones[0].raw_value, source="rule:context")
        red_flags.append({
            "title": "Asks you to call a number from the message",
            "detail": (f"The only contact route offered is {phones[0].display_value}. "
                       "Always use the number printed on your card, bill or the official "
                       "website instead."),
            "evidence_span": phones[0].raw_value,
            "family": "context_anomaly", "kind": "observed", "weight": 5.0,
        })

    if ocr and ocr.get("available") and ocr.get("mean_confidence", 100) < 60:
        degraded.append({"check": "ocr_confidence", "status": "low",
                         "reason": f"Mean OCR confidence {ocr.get('mean_confidence')}%. "
                                   "Verify the extracted text before trusting the result."})

    # ---- family: entity reputation (0-20) & campaign similarity (0-15)
    campaign_links: List[dict] = []
    reputation: List[dict] = []
    fingerprint = graph.message_fingerprint(norm.normalized)

    if session is not None:
        try:
            reputation = graph.entity_reputation(session, entity_dicts)
            for r in reputation:
                w = min(10.0, 3.0 + 2.5 * min(3, r["report_count"]))
                rf.add(name=f"Previously reported {r['type']}",
                       family="entity_reputation", weight=w,
                       observed_value=(f"{r['display_value']} — {r['report_count']} community "
                                       f"report(s), first seen {(r['first_seen'] or '')[:10]}"),
                       evidence_span=r.get("evidence_span", ""), source="community_db")
                red_flags.append({
                    "title": f"This {r['type']} has been reported before",
                    "detail": (f"{r['display_value']} appears in {r['report_count']} moderated "
                               f"community report(s)."),
                    "evidence_span": r.get("evidence_span", ""),
                    "family": "entity_reputation", "kind": "observed", "weight": round(w, 1),
                })
            campaign_links = graph.find_campaign_links(
                session, entity_dicts, fingerprint, norm.normalized)
            for link in campaign_links[:3]:
                w = CAPS["campaign_similarity"] * link["strength"]
                reasons = ", ".join(
                    f"{r['relation']} ({r.get('indicator', '')})" for r in link["reasons"][:3])
                rf.add(name="Matches a tracked campaign", family="campaign_similarity",
                       weight=w, observed_value=f"{link['label']} — {reasons}",
                       evidence_span=link["reasons"][0].get("evidence_span", ""),
                       source="campaign_graph")
                red_flags.append({
                    "title": "Resembles a known campaign",
                    "detail": f"{link['label']} ({link['report_count']} report(s)). Why: {reasons}.",
                    "evidence_span": link["reasons"][0].get("evidence_span", ""),
                    "family": "campaign_similarity", "kind": "observed", "weight": round(w, 1),
                })
        except Exception as exc:
            degraded.append({"check": "campaign_correlation", "status": "unavailable",
                             "reason": str(exc)[:200]})
    else:
        degraded.append({"check": "campaign_correlation", "status": "unavailable",
                         "reason": "No database session for this request."})

    # ---------------- 5. Fuse ----------------
    capped = rf.capped()
    raw_total = sum(capped.values())
    score = max(0, min(100, round(raw_total - benign_credit)))
    verdict, verdict_label = band(score)

    if benign_credit:
        rf.add(name="Legitimate-message markers", family="message_intent",
               weight=0.0, observed_value=f"-{benign_credit:.0f} points",
               evidence_span=intent.benign_signals[0].evidence_span,
               source="rule:benign")

    # ---------------- 6. Confidence & uncertainty ----------------
    evidence_count = len([i for i in rf.items if i["weight"] > 0])
    families_hit = len([f for f, v in capped.items() if v > 0])
    confidence = min(0.95, 0.35 + 0.12 * families_hit + 0.03 * min(6, evidence_count))
    if lang.language == "und":
        confidence -= 0.1
    if degraded:
        confidence -= 0.05 * min(3, len(degraded))
    if ocr and ocr.get("available") and ocr.get("mean_confidence", 100) < 60:
        confidence -= 0.1
    confidence = round(max(0.2, confidence), 2)

    uncertainties: List[str] = []
    if not url_values:
        uncertainties.append("No link was present, so technical URL signals could not contribute.")
    if session is None or not reputation:
        uncertainties.append("No prior community reports matched these indicators.")
    if lang.language == "ta-en":
        uncertainties.append("Tanglish was normalized before analysis; review the original wording.")
    for d in degraded:
        uncertainties.append(f"{d['check']} was {d['status']}: {d.get('reason', '')}")

    scam_category = intent.scam_category if score >= 25 else (
        intent.scam_category if intent.category_scores else "legitimate")
    scam_label = SCAM_CLASSES.get(scam_category, {}).get("label", "Unclassified")

    summary = build_summary(score, verdict_label, scam_label, lang, red_flags,
                            worst_url, campaign_links)
    actions = recommended_actions(score, scam_category, found, worst_url, campaign_links)

    red_flags.sort(key=lambda r: -(r.get("weight") or 0))
    latency_ms = round((time.perf_counter() - started) * 1000, 1)

    result = {
        "analysis_id": analysis_id,
        "input_type": input_type,
        "language": lang.language,
        "language_detail": lang.to_dict(),
        "verdict": verdict,
        "verdict_label": verdict_label,
        "risk_score": score,
        "risk_band": {"key": verdict, "label": verdict_label,
                      "bands": [{"min": lo, "max": hi, "key": k, "label": l}
                                for lo, hi, k, l in BANDS]},
        "confidence": confidence,
        "scam_category": scam_category,
        "scam_category_label": scam_label,
        "summary": summary,
        "red_flags": red_flags[:12],
        "risk_factors": rf.items,
        "score_breakdown": [{"family": f, "points": round(v, 1), "cap": CAPS[f]}
                            for f, v in capped.items()],
        "benign_adjustment": -round(benign_credit, 1),
        "entities": entity_dicts,
        "entity_reputation": reputation,
        "campaign_links": campaign_links,
        "recommended_actions": actions,
        "uncertainties": uncertainties,
        "model_version": MODEL_VERSION,
        "degraded_checks": degraded,
        "created_at": created_at.isoformat(),
        "latency_ms": latency_ms,
        # Supporting detail
        "input_preview": norm.normalized[:4000],
        "normalization": {
            "normalized_text": norm.normalized[:4000],
            "analysis_text": norm.folded[:4000],
            "replacements": norm.replacements,
        },
        "intent": intent.to_dict(),
        "url_reports": url_reports,
        "ocr": ocr,
        "qr": qr,
        "message_fingerprint": fingerprint,
        "evidence_hash": hashlib.sha256((norm.normalized or "").encode()).hexdigest(),
        "disclaimer": ("RedFlag is risk assessment and decision support. It does not prove "
                       "fraud and is not a legal determination."),
    }

    if persist and session is not None:
        try:
            store(session, result, user_id=user_id)
            session.commit()
        except Exception as exc:                               # pragma: no cover
            session.rollback()
            result["degraded_checks"].append(
                {"check": "persistence", "status": "failed", "reason": str(exc)[:200]})
    return result


def _pretty(key: Optional[str]) -> str:
    return (key or "unclassified").replace("_", " ")


def build_summary(score: int, verdict_label: str, scam_label: str,
                  lang: language.LanguageResult, red_flags: List[dict],
                  worst_url: Optional[dict], campaign_links: List[dict]) -> str:
    if score >= 75:
        lead = "Do not act on this message."
    elif score >= 50:
        lead = "Treat this as unsafe until verified independently."
    elif score >= 25:
        lead = "Some suspicious signals are present — verify before acting."
    else:
        lead = "No strong scam signals were found, but stay careful."

    bits = [lead]
    if score >= 25 and scam_label and scam_label != "No scam pattern detected":
        bits.append(f"The pattern resembles a {scam_label.lower()}.")
    top = [r["title"] for r in sorted(red_flags, key=lambda r: -(r.get("weight") or 0))[:2]]
    if top:
        bits.append("Main reasons: " + "; ".join(top).lower() + ".")
    if worst_url and int(worst_url.get("risk_score", 0) or 0) >= 50:
        bits.append(f"The link {worst_url.get('domain')} scored "
                    f"{worst_url.get('risk_score')}/100 on structural checks.")
    if campaign_links:
        bits.append(f"It also matches a tracked campaign: {campaign_links[0]['label']}.")
    bits.append(f"Detected language: {lang.label}.")
    return " ".join(bits)


def recommended_actions(score: int, category: str, found: List[ent_mod.Entity],
                        worst_url: Optional[dict],
                        campaign_links: List[dict]) -> List[dict]:
    acts: List[dict] = []
    has_url = any(e.type == "url" for e in found)
    has_upi = any(e.type == "upi" for e in found)

    if score >= 50:
        acts.append({"priority": "critical", "action": "Do not open the link or scan the QR code.",
                     "why": "The destination shows multiple deception signals."} if has_url else
                    {"priority": "critical", "action": "Do not reply or call back.",
                     "why": "Responding confirms your number is active."})
        acts.append({"priority": "critical",
                     "action": "Never share an OTP, PIN, CVV or password — not even with someone claiming to be from your bank.",
                     "why": "No legitimate bank or government body ever asks for these."})
    if score >= 25:
        acts.append({"priority": "high",
                     "action": "Verify independently: type the official website yourself or call the number printed on your card/bill.",
                     "why": "Never use contact details supplied inside a suspicious message."})
    if has_upi:
        acts.append({"priority": "high",
                     "action": "Never 'approve' a UPI collect request to RECEIVE money. Approving sends money out.",
                     "why": "Refund and cashback scams rely on this confusion."})
    if category == "remote_access_scam":
        acts.append({"priority": "critical",
                     "action": "Do not install AnyDesk, TeamViewer or any APK sent to you; uninstall immediately if already installed.",
                     "why": "These give the caller full control of your device."})
    if score >= 50:
        acts.append({"priority": "high",
                     "action": "Report it: call the national cyber-fraud helpline 1930 or file at cybercrime.gov.in.",
                     "why": "Fast reporting improves the chance of freezing a fraudulent transfer."})
        acts.append({"priority": "medium",
                     "action": "If you already paid or shared credentials, call your bank's official helpline now and block the card/account.",
                     "why": "The first hour matters most."})
    acts.append({"priority": "medium",
                 "action": "Submit this to the RedFlag community feed so others in your area are warned.",
                 "why": "Repeated indicators are what reveal a campaign."})
    if campaign_links:
        acts.append({"priority": "medium",
                     "action": f"Open the campaign view for '{campaign_links[0]['label']}' to see shared infrastructure.",
                     "why": "Context helps you recognise the next variant."})
    if score < 25:
        acts.append({"priority": "low",
                     "action": "If anything still feels off, confirm through an official channel before acting.",
                     "why": "A low score is not a guarantee of safety."})
    return acts


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def store(session: Session, result: dict, user_id: Optional[str] = None) -> m.Analysis:
    row = m.Analysis(
        id=result["analysis_id"], user_id=user_id,
        input_type=result["input_type"], language=result["language"],
        language_label=result["language_detail"]["label"],
        verdict=result["verdict"], risk_score=result["risk_score"],
        confidence=result["confidence"], scam_category=result["scam_category"],
        summary=result["summary"], model_version=result["model_version"],
        message_fingerprint=result["message_fingerprint"],
        payload=result, created_at=m.utcnow(),
    )
    session.add(row)
    session.flush()

    for f in result["risk_factors"]:
        session.add(m.RiskFactor(
            analysis_id=row.id, factor=f["name"], family=f["family"],
            weight=f["weight"], observed_value=f["observed_value"],
            evidence_span=f["evidence_span"], source=f["source"],
        ))

    session.add(m.Evidence(
        analysis_id=row.id, type="raw_text",
        redacted_value=result["input_preview"][:2000],
        hash=result["evidence_hash"], is_public=False,
    ))
    if result.get("ocr") and result["ocr"].get("text"):
        session.add(m.Evidence(
            analysis_id=row.id, type="ocr_text",
            redacted_value=result["ocr"]["text"][:2000],
            hash=hashlib.sha256(result["ocr"]["text"].encode()).hexdigest(),
            is_public=False,
        ))

    for e in result["entities"]:
        ent = graph.upsert_entity(session, e["type"], e["canonical_hash"],
                                  e["display_value"])
        session.add(m.AnalysisEntity(
            analysis_id=row.id, entity_id=ent.id,
            confidence=e["confidence"], evidence_span=e["raw_value"][:255],
        ))
    return row
