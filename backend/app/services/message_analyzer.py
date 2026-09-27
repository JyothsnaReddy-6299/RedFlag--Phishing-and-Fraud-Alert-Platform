import re
from typing import List, Tuple
from app.models.schemas import (
    DetectedLanguage,
    ScamCategory,
    SocialEngineeringSignals,
    MessageAnalysisResult,
    ExtractedEntities
)
from app.services.entity_extractor import entity_extractor

# Tamil Unicode range
TAMIL_SCRIPT_REGEX = re.compile(r'[\u0B80-\u0BFF]')

# Tanglish (Tamil in Latin script) keyword stems
TANGLISH_VOCAB = {
    # Pronouns & Connectors
    "ungal", "ungalin", "ennai", "neengal", "udane", "ippothu", "kaal", "neram",
    # Financial / Banking
    "panam", "vangi", "kanakku", "kaas", "kadan", "roobai", "selavu",
    # Actions & Verbs
    "kattavum", "anuppavum", "seyyavum", "seithu", "alikka", "thodarbu", "kollavum",
    # Fear & Disconnection
    "vettpadum", "thunikkapadum", "mudakkapadum", "thadaigal", "illaiyendral", "thavaraamal",
    # Scam / Job
    "velai", "parisu", "kidaikkum", "vetri", "adhavan", "aduthu"
}

# Scam intent pattern dictionaries
URGENCY_KEYWORDS = [
    "immediately", "urgent", "urgently", "tonight", "24 hours", "12 hours", "today",
    "expire", "expiring", "last chance", "final warning", "now or never", "quick",
    # Tamil & Tanglish
    "udane", "innum sila nerathil", "ippothu", "kadasiaaga", "irudhi echcharikkai",
    "உடனே", "இப்போதே", "இறுதி எச்சரிக்கை", "இன்றிரவு"
]

FEAR_THREAT_KEYWORDS = [
    "suspended", "suspend", "disconnected", "disconnection", "blocked", "deactivated",
    "terminate", "closed", "legal action", "arrest", "court", "fir", "police", "penalty",
    # Tamil & Tanglish
    "vettpadum", "mudakkapadum", "thunikkapadum", "thadaigal",
    "துண்டிக்கப்படும்", "முடக்கப்படும்", "நிறுத்தப்படும்", "நடவடிக்கை"
]

INCENTIVE_KEYWORDS = [
    "lottery", "winner", "won", "reward", "cashback", "bonus", "gift", "congratulations",
    "part-time job", "daily income", "work from home", "earn 5000", "free recharge",
    # Tamil & Tanglish
    "parisu", "panam kidaikkum", "vetri", "velai",
    "பரிசு", "வெற்றி", "பணம் கிடைக்கும்", "வேலை"
]

CREDENTIAL_OTP_KEYWORDS = [
    "otp", "pin", "password", "cvv", "share otp", "kyc update", "pan card",
    "aadhaar link", "verify kyc", "biometric", "credentials", "login details",
    # Tamil & Tanglish
    "en", "adaiyaalam",
    "கேஒய்சி", "கடவுச்சொல்", "ஆதார்"
]

ACTION_KEYWORDS = [
    "click", "link", "call", "dial", "download", "install", "apk", "paytm", "gpay",
    "send money", "pay now", "contact officer",
    # Tamil & Tanglish
    "thodarbu kollavum", "kattavum", "anuppavum",
    "தொடர்பு கொள்ளவும்", "கட்டவும்", "அனுப்பவும்"
]

class MessageAnalyzer:
    def detect_language(self, text: str) -> DetectedLanguage:
        tamil_chars = len(TAMIL_SCRIPT_REGEX.findall(text))
        total_chars = max(1, len(re.findall(r'\w', text)))
        
        # Check Tamil Script
        if tamil_chars / total_chars > 0.15:
            # Check if there is also English
            has_english = bool(re.search(r'[a-zA-Z]{3,}', text))
            return DetectedLanguage.MIXED if has_english else DetectedLanguage.TAMIL

        # Check Tanglish
        words = set(re.findall(r'[a-zA-Z]+', text.lower()))
        tanglish_matches = words.intersection(TANGLISH_VOCAB)
        if len(tanglish_matches) >= 2 or (len(tanglish_matches) >= 1 and len(words) <= 8):
            return DetectedLanguage.TANGLISH

        return DetectedLanguage.ENGLISH

    def extract_social_engineering(self, text: str) -> SocialEngineeringSignals:
        text_lower = text.lower()
        patterns = []

        def match_any(keywords):
            matched = []
            for kw in keywords:
                if kw.lower() in text_lower:
                    matched.append(kw)
            return matched

        urgency_matches = match_any(URGENCY_KEYWORDS)
        if urgency_matches:
            patterns.append(f"Urgency cue: '{urgency_matches[0]}'")

        threat_matches = match_any(FEAR_THREAT_KEYWORDS)
        if threat_matches:
            patterns.append(f"Threat/Disconnection cue: '{threat_matches[0]}'")

        incentive_matches = match_any(INCENTIVE_KEYWORDS)
        if incentive_matches:
            patterns.append(f"Financial lure: '{incentive_matches[0]}'")

        cred_matches = match_any(CREDENTIAL_OTP_KEYWORDS)
        if cred_matches:
            patterns.append(f"Credential/OTP demand: '{cred_matches[0]}'")

        action_matches = match_any(ACTION_KEYWORDS)
        if action_matches:
            patterns.append(f"Call to action: '{action_matches[0]}'")

        # Impersonation check
        impersonation = False
        orgs = entity_extractor.extract_organizations(text)
        if orgs and (threat_matches or cred_matches or urgency_matches):
            impersonation = True
            patterns.append(f"Impersonating organization: '{orgs[0]}'")

        return SocialEngineeringSignals(
            urgency_detected=bool(urgency_matches),
            fear_or_threat_detected=bool(threat_matches),
            financial_incentive_detected=bool(incentive_matches),
            credential_or_otp_demand=bool(cred_matches),
            impersonation_detected=impersonation,
            action_requested=bool(action_matches),
            detected_patterns=patterns
        )

    def classify_scam(self, text: str, entities: ExtractedEntities, signals: SocialEngineeringSignals) -> Tuple[ScamCategory, float]:
        text_lower = text.lower()

        # 1. Electricity / Utility bill scams (extremely prevalent in South India: TNEB power disconnection)
        if any(w in text_lower for w in ["electricity", "power", "tneb", "tangedco", "light will be disconnected", "vettpadum", "துண்டிக்கப்படும்"]):
            if signals.fear_or_threat_detected or signals.urgency_detected or entities.phone_numbers or entities.upi_ids:
                return ScamCategory.ELECTRICITY_BILL, 0.95

        # 2. KYC / Account Expiry
        if any(w in text_lower for w in ["kyc", "pan", "aadhaar", "document verification", "account blocked", "sim deactivation"]):
            if signals.credential_or_otp_demand or signals.fear_or_threat_detected or signals.urgency_detected:
                return ScamCategory.KYC_EXPIRY, 0.92

        # 3. OTP Theft
        if any(w in text_lower for w in ["otp", "one time password", "do not share", "secret code"]) and signals.action_requested:
            return ScamCategory.OTP_THEFT, 0.90

        # 4. UPI / Payment Fraud
        if entities.upi_ids or any(w in text_lower for w in ["upi pin", "gpay reward", "phonepe cashback", "collect request"]):
            if signals.financial_incentive_detected or signals.action_requested:
                return ScamCategory.UPI_FRAUD, 0.88

        # 5. Lottery / Prize Fraud
        if signals.financial_incentive_detected and any(w in text_lower for w in ["lottery", "won", "congratulations", "lucky draw", "crore", "lakh"]):
            return ScamCategory.LOTTERY_PRIZE, 0.93

        # 6. Job Scams
        if any(w in text_lower for w in ["part-time", "part time", "work from home", "daily salary", "telegram task", "youtube subscribe"]):
            return ScamCategory.JOB_SCAM, 0.89

        # 7. Banking Fraud
        if entities.organizations or any(w in text_lower for w in ["bank", "sbi", "hdfc", "icici", "debit card", "credit card"]):
            if signals.fear_or_threat_detected or signals.urgency_detected:
                return ScamCategory.BANKING_FRAUD, 0.85

        # 8. Malicious URL delivery in SMS
        if entities.urls and (signals.urgency_detected or signals.fear_or_threat_detected or signals.action_requested):
            return ScamCategory.MALICIOUS_URL, 0.82

        # 9. Generic Impersonation
        if signals.impersonation_detected:
            return ScamCategory.IMPERSONATION, 0.78

        # 10. Legitimate Check
        if not (signals.fear_or_threat_detected or signals.urgency_detected or signals.credential_or_otp_demand or signals.financial_incentive_detected):
            return ScamCategory.LEGITIMATE, 0.80

        return ScamCategory.UNKNOWN, 0.50

    def analyze(self, text: str) -> MessageAnalysisResult:
        language = self.detect_language(text)
        entities = entity_extractor.extract_all(text)
        social_eng = self.extract_social_engineering(text)
        category, confidence = self.classify_scam(text, entities, social_eng)

        threat_signals = []
        score = 0.0

        if social_eng.credential_or_otp_demand:
            threat_signals.append("Demands confidential OTP / KYC / Banking credentials")
            score += 35.0

        if social_eng.fear_or_threat_detected:
            threat_signals.append("Uses coercive fear tactics or service suspension threats")
            score += 25.0

        if social_eng.urgency_detected:
            threat_signals.append("Creates artificial urgency to prevent critical evaluation")
            score += 20.0

        if social_eng.financial_incentive_detected:
            threat_signals.append("Dangles unrealistic lottery, job, or cashback rewards")
            score += 20.0

        if social_eng.impersonation_detected:
            threat_signals.append("Impersonates reputable institution (Bank/Utility/Govt)")
            score += 25.0

        if entities.upi_ids and (social_eng.fear_or_threat_detected or social_eng.urgency_detected):
            threat_signals.append(f"Directs victim to private UPI handle: {entities.upi_ids[0]}")
            score += 25.0

        if entities.phone_numbers and social_eng.action_requested:
            threat_signals.append(f"Provides suspicious direct callback contact: {entities.phone_numbers[0]}")
            score += 15.0

        if entities.urls:
            threat_signals.append("Contains unverified external link inside suspicious message")
            score += 20.0

        if category == ScamCategory.LEGITIMATE:
            score = 5.0
            threat_signals.clear()

        base_risk_score = min(100.0, max(0.0, round(score, 1)))

        return MessageAnalysisResult(
            original_text=text,
            detected_language=language,
            scam_category=category,
            confidence=confidence,
            social_engineering=social_eng,
            extracted_entities=entities,
            threat_signals=threat_signals,
            base_risk_score=base_risk_score
        )

message_analyzer = MessageAnalyzer()
