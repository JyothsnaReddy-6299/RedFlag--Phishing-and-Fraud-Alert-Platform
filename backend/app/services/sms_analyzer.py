import re
from typing import List, Dict, Tuple, Optional
from app.models.schemas import RiskLevel, URLScanResponse
from app.services.url_analyzer import url_analyzer
from app.services.risk_scorer import url_risk_scorer

URGENCY_PHRASES = [
    "immediately", "urgent", "tonight", "within 24 hours", "24 hrs", "today",
    "will be blocked", "will be suspended", "deactivated", "last reminder",
    "action required", "expir", "penalty", "disconnect", "disconnected"
]

FINANCIAL_LURES = [
    "lottery", "prize", "cashback", "bonus", "reward", "credited", "refund",
    "earn rs", "work from home", "part time job", "income tax refund", "gift card"
]

KYC_TRAPS = [
    "kyc", "pan card", "aadhaar", "yono", "netbanking", "update kyc",
    "link pan", "verify account", "unblock", "reactivate", "credit card limit"
]

UTILITY_TRAPS = [
    "electricity", "power", "meter", "bill unpaid", "disconnection",
    "officer", "chalan", "traffic fine", "challan", "tneb", "bescom"
]

URL_REGEX = re.compile(
    r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:xyz|top|club|site|online|bank\.in|com|co\.in|org|net|live|fun|in)/[^\s]*)',
    re.IGNORECASE
)

PHONE_REGEX = re.compile(r'(?:\+91[\-\s]?)?[6-9]\d{9}')

class SMSAnalyzer:
    def extract_urls(self, text: str) -> List[str]:
        raw_matches = URL_REGEX.findall(text)
        cleaned = []
        for match in raw_matches:
            # strip trailing punctuation
            u = match.rstrip(".,;:)'\"!?")
            if u:
                cleaned.append(u)
        return list(dict.fromkeys(cleaned))

    def analyze_sms(self, text: str, sender_id: Optional[str] = None) -> Dict:
        text_clean = text.strip()
        text_lower = text_clean.lower()
        signals: List[str] = []
        urgency_found: List[str] = []
        score = 0.0

        # 1. Extract and inspect embedded URLs
        extracted_urls = self.extract_urls(text_clean)
        analyzed_urls: List[URLScanResponse] = []
        max_url_score = 0

        for url_str in extracted_urls:
            features = url_analyzer.analyze(url_str)
            threat_match = url_analyzer.check_threat_feeds(features.domain)
            url_res = url_risk_scorer.evaluate(features, threat_match)
            analyzed_urls.append(url_res)
            max_url_score = max(max_url_score, url_res.risk_score)

        if max_url_score >= 80:
            signals.append(f"Contains high-risk phishing URL ({analyzed_urls[0].domain})")
            score += 65.0
        elif max_url_score >= 40:
            signals.append("Contains suspicious link with abnormal structure")
            score += 35.0
        elif len(extracted_urls) > 0 and max_url_score == 0:
            signals.append("Contains verified legitimate portal link")

        # 2. Check Urgency / Coercion Tactics
        for phrase in URGENCY_PHRASES:
            if phrase in text_lower:
                urgency_found.append(phrase)

        if len(urgency_found) >= 2:
            signals.append(f"High-pressure psychological urgency: {', '.join(urgency_found[:3])}")
            score += 25.0
        elif len(urgency_found) == 1:
            signals.append(f"Urgency indicator detected: '{urgency_found[0]}'")
            score += 12.0

        # 3. Categorize scam theme
        has_kyc = any(k in text_lower for k in KYC_TRAPS)
        has_fin = any(f in text_lower for f in FINANCIAL_LURES)
        has_utility = any(u in text_lower for u in UTILITY_TRAPS)

        if has_kyc:
            signals.append("KYC/PAN account verification trap targeted at banking customers")
            score += 30.0
            scam_category = "KYC_BANKING_FRAUD"
        elif has_utility:
            signals.append("Electricity or utility disconnection intimidation scam")
            score += 30.0
            scam_category = "UTILITY_DISCONNECTION_SCAM"
        elif has_fin:
            signals.append("Unsolicited reward / cashback / lottery bait")
            score += 25.0
            scam_category = "FINANCIAL_LOTTERY_SCAM"
        elif len(extracted_urls) > 0 and max_url_score > 30:
            scam_category = "MALICIOUS_LINK_DISTRIBUTION"
        else:
            scam_category = "GENERAL_MESSAGE"

        # 4. Check for personal mobile number acting as bank official
        phone_matches = PHONE_REGEX.findall(text_clean)
        if phone_matches and (has_kyc or has_utility or "bank" in text_lower):
            signals.append(f"Unverified personal 10-digit mobile number ({phone_matches[0]}) masquerading as official support")
            score += 20.0

        # 5. Check sender ID spoofing (e.g. personal number sending bank KYC alerts)
        if sender_id:
            sender_id_clean = sender_id.strip()
            if re.match(r'^\+?[0-9]{10,13}$', sender_id_clean) and (has_kyc or "bank" in text_lower):
                signals.append(f"Personal mobile number ({sender_id_clean}) used to dispatch banking alerts (banks only use 6-character alphabetic headers like VK-SBIINB)")
                score += 25.0

        # Adjust score for benign messages (like official bank credit/debit alerts)
        is_official_bank_alert = (
            ("credited with" in text_lower or "debited with" in text_lower or "avl bal" in text_lower or "otp is" in text_lower)
            and len(extracted_urls) == 0
            and not has_kyc
            and not has_utility
        )
        if is_official_bank_alert:
            score = 0.0
            scam_category = "LEGITIMATE_BANK_NOTIFICATION"
            signals = ["Standard transactional credit/debit notification with no external link"]

        final_score = int(min(100, max(0, round(score))))

        # Determine Risk Level
        if final_score < 25:
            level = RiskLevel.SAFE_LOW
            explanation = "Message appears to be a standard benign notification with no high-risk phishing indicators."
            advice = ["Standard notification. Never share OTPs or login passwords with anyone."]
        elif final_score < 60:
            level = RiskLevel.SUSPICIOUS
            explanation = "Message exhibits suspicious characteristics (unverified links or urgency demands). Exercise caution."
            advice = [
                "Do not click links inside this message.",
                "Call your bank's verified customer care number from the official debit card or passbook."
            ]
        elif final_score < 80:
            level = RiskLevel.HIGH_RISK
            explanation = f"High-risk scam message detected ({scam_category}). Uses social engineering to deceive recipients."
            advice = [
                "DO NOT call numbers or click links in this message.",
                "Banks and electricity boards never threaten disconnection via SMS within 24 hours.",
                "Report this SMS to the National Cyber Crime Reporting Portal (1930 or cybercrime.gov.in)."
            ]
        else:
            level = RiskLevel.CRITICAL
            explanation = f"CRITICAL SCAM ATTEMPT ({scam_category}). Confirmed social engineering message designed to siphon funds or steal banking access."
            advice = [
                "IMMEDIATE DANGER: Do not interact with this message.",
                "Delete and block the sender immediately.",
                "If you entered any credentials, contact your bank immediately to freeze your account."
            ]

        return {
            "text": text_clean,
            "risk_score": final_score,
            "risk_level": level,
            "scam_category": scam_category,
            "confidence": 0.92 if final_score > 60 else 0.85,
            "detected_entities": {
                "urls": extracted_urls,
                "phone_numbers": phone_matches,
                "urgency_keywords": urgency_found
            },
            "urgency_indicators": urgency_found,
            "extracted_urls": analyzed_urls,
            "threat_signals": signals,
            "mitigation_advice": advice,
            "explanation": explanation
        }

sms_analyzer = SMSAnalyzer()
