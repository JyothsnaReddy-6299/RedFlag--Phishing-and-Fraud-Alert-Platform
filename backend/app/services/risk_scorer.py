from typing import Optional, List
from app.models.schemas import (
    RiskLevel,
    ScamCategory,
    RiskAssessment,
    URLFeatureAnalysis,
    MessageAnalysisResult,
    ExtractedEntities
)
from app.core.config import settings

class RiskScorer:
    def evaluate(
        self,
        url_analysis: Optional[URLFeatureAnalysis] = None,
        message_analysis: Optional[MessageAnalysisResult] = None,
        threat_match: Optional[dict] = None,
        extracted_entities: Optional[ExtractedEntities] = None
    ) -> RiskAssessment:
        factors: List[str] = []
        advice: List[str] = []
        raw_score = 0.0
        primary_category = ScamCategory.UNKNOWN
        confidence = 0.50

        # 1. URL Analysis signals
        if url_analysis:
            raw_score += url_analysis.base_risk_score
            factors.extend(url_analysis.threat_signals)
            if url_analysis.brand_impersonated:
                primary_category = ScamCategory.BANKING_FRAUD if url_analysis.brand_impersonated in ["SBI", "HDFC", "ICICI", "AXIS"] else ScamCategory.IMPERSONATION
                confidence = max(confidence, 0.88)
            elif url_analysis.base_risk_score > 50:
                primary_category = ScamCategory.MALICIOUS_URL
                confidence = max(confidence, 0.80)

        # 2. Message Analysis signals
        if message_analysis:
            if message_analysis.scam_category != ScamCategory.LEGITIMATE:
                raw_score += message_analysis.base_risk_score
                factors.extend(message_analysis.threat_signals)
                primary_category = message_analysis.scam_category
                confidence = max(confidence, message_analysis.confidence)
            else:
                # If legitimate message detected and no bad URL
                if not url_analysis or url_analysis.base_risk_score < 25:
                    primary_category = ScamCategory.LEGITIMATE
                    confidence = 0.85
                    raw_score = min(raw_score, 10.0)

        # 3. Threat Intelligence matches
        if threat_match and threat_match.get("matched"):
            boost = threat_match.get("threat_score_boost", 0.0)
            raw_score += boost
            for ind in threat_match.get("matched_indicators", []):
                factors.append(f"Confirmed Threat Match: {ind['type']} '{ind['value']}' flagged in {ind.get('source', 'Threat Intelligence')}")
            confidence = max(confidence, 0.98)

        # 4. Multi-signal synergy (e.g. both URL + SMS scam markers)
        if url_analysis and message_analysis and url_analysis.base_risk_score > 30 and message_analysis.base_risk_score > 30:
            raw_score += 15.0
            factors.append("Multi-vector attack: Suspicious message carries an obfuscated phishing link")

        # Normalize score
        final_score = int(min(100, max(0, round(raw_score))))

        # Map to Risk Level
        if final_score < settings.RISK_THRESHOLD_LOW:
            level = RiskLevel.SAFE_LOW
            explanation = "No significant phishing or fraud indicators detected. Appears benign."
            advice.append("Standard caution: Never share sensitive banking PINs or OTPs.")
        elif final_score < settings.RISK_THRESHOLD_SUSPICIOUS:
            level = RiskLevel.SUSPICIOUS
            explanation = "Exhibits suspicious characteristics commonly associated with deceptive communications."
            advice.append("Do not click links or call back phone numbers provided in this message.")
            advice.append("Verify directly through the organization's official app or verified customer care number.")
        elif final_score < settings.RISK_THRESHOLD_HIGH:
            level = RiskLevel.HIGH_RISK
            explanation = f"High probability of digital financial fraud ({primary_category.value})."
            advice.append("Do NOT provide OTPs, passwords, or initiate UPI payments.")
            advice.append("Block the sender and report this indicator to your local cyber crime portal.")
        else:
            level = RiskLevel.CRITICAL
            explanation = f"Critical active scam detected ({primary_category.value}) verified by threat intelligence."
            advice.append("IMMEDIATE ACTION: Do not interact with this link or sender.")
            advice.append("If you have shared credentials or paid money, contact your bank immediately to freeze your account.")

        # Specific scam category mitigation advice
        if primary_category == ScamCategory.ELECTRICITY_BILL:
            advice.append("Electricity boards never disconnect power via SMS alerts demanding payments to private UPI IDs.")
        elif primary_category == ScamCategory.KYC_EXPIRY:
            advice.append("RBI guidelines strictly forbid banks from requesting KYC updates through unverified third-party links.")
        elif primary_category == ScamCategory.UPI_FRAUD:
            advice.append("Entering your UPI PIN always deducts money from your account; you never enter a PIN to receive cashback or prizes.")

        # De-duplicate factors
        unique_factors = []
        for f in factors:
            if f not in unique_factors:
                unique_factors.append(f)

        return RiskAssessment(
            risk_score=final_score,
            risk_level=level,
            primary_category=primary_category,
            confidence=round(confidence, 2),
            contributing_factors=unique_factors,
            mitigation_advice=advice,
            explanation=explanation
        )

risk_scorer = RiskScorer()
