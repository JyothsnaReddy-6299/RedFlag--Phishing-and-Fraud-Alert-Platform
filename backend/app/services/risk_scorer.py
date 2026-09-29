from typing import List, Optional, Dict
from app.models.schemas import RiskLevel, URLCategory, URLFeatureAnalysis, URLScanResponse
from app.core.config import settings

class URLRiskScorer:
    def evaluate(self, features: URLFeatureAnalysis, threat_match: Optional[Dict[str, str]] = None) -> URLScanResponse:
        factors = list(features.threat_signals)
        advice: List[str] = []
        sources: List[str] = []

        # 1. VERIFIED OFFICIAL DOMAIN CHECK (Immunity from False Positives)
        if features.is_official_domain:
            return URLScanResponse(
                url=features.url,
                original_url=features.original_url or features.url,
                normalized_url=features.normalized_url or features.url,
                domain=features.domain,
                canonical_domain=features.canonical_domain or features.domain,
                subdomain=features.subdomain,
                registered_domain=features.registered_domain,
                tld=features.tld or features.detected_tld,
                scheme=features.scheme or features.protocol,
                port=features.port,
                path=features.path,
                query=features.query,
                fragment=features.fragment,
                components=features.components,
                punycode_domain=features.punycode_domain,
                stripped_tracking_params=features.stripped_tracking_params,
                risk_score=0,
                risk_level=RiskLevel.SAFE_LOW,
                category=URLCategory.LEGITIMATE,
                confidence=0.99,
                url_features=features,
                threat_intel_match=False,
                threat_sources=[],
                contributing_factors=[f"Verified Official Portal: Belongs to {features.official_brand_name or 'authorized registry'}"],
                mitigation_advice=["This is the legitimate, verified official portal. It is safe to use."],
                explanation=f"Verified authentic official domain of {features.official_brand_name or 'the organization'}."
            )

        # 2. General Evaluation
        raw_score = features.base_risk_score
        confidence = 0.70
        is_threat_match = False

        # Threat feed correlation
        if threat_match:
            is_threat_match = True
            raw_score += 55.0
            sources.append(threat_match["source"])
            factors.append(f"Confirmed Malicious: Domain matches active blacklist feed ({threat_match['source']})")
            confidence = 0.99

        final_score = int(min(100, max(0, round(raw_score))))

        # Determine Category
        if is_threat_match:
            category = URLCategory.KNOWN_PHISHING
        elif features.has_homograph_attack or features.brand_impersonated:
            category = URLCategory.BRAND_IMPERSONATION
            confidence = max(confidence, 0.95 if features.has_homograph_attack else 0.90)
        elif features.ip_based:
            category = URLCategory.IP_BASED_ATTACK
            confidence = max(confidence, 0.85)
        elif features.suspicious_tld and len(features.suspicious_keywords) > 0:
            category = URLCategory.HIGH_ABUSE_TLD
            confidence = max(confidence, 0.80)
        elif final_score >= settings.RISK_THRESHOLD_LOW:
            category = URLCategory.SUSPICIOUS_STRUCTURE
        else:
            category = URLCategory.LEGITIMATE
            confidence = 0.88

        # Determine Risk Level & Advice
        if final_score < settings.RISK_THRESHOLD_LOW:
            level = RiskLevel.SAFE_LOW
            explanation = "URL exhibits standard structure with no deceptive brand imitation or known threat matches."
            advice.append("Always verify the browser address bar before entering confidential credentials.")
        elif final_score < settings.RISK_THRESHOLD_SUSPICIOUS:
            level = RiskLevel.SUSPICIOUS
            explanation = "URL displays unusual structural characteristics (e.g. length, subdomains, or keywords) that warrant caution."
            advice.append("Do not enter banking credentials, passwords, or personal identity details on this page.")
            advice.append("Verify the URL directly against the organization's official domain name.")
        elif final_score < settings.RISK_THRESHOLD_HIGH:
            level = RiskLevel.HIGH_RISK
            explanation = f"High-risk deceptive link identified ({category.value}). Exhibits clear brand imitation or attack indicators."
            advice.append("DO NOT OPEN this URL. It is strongly suspected to be a credential-harvesting trap.")
            advice.append("If received via SMS or email, report the message to your local cyber security reporting channel.")
        else:
            level = RiskLevel.CRITICAL
            if features.has_homograph_attack:
                explanation = f"CRITICAL THREAT: IDN Homograph attack ({features.punycode_domain}). Uses foreign unicode lookalike characters to spoof a legitimate service."
                advice.append("This domain uses deceptive internationalized characters (homoglyphs) to trick users into believing it is authentic.")
            elif features.brand_impersonated:
                explanation = f"CRITICAL THREAT: Deceptive link falsely mimicking {features.brand_impersonated} via lookalike domain, anagram, or typosquatting transposition."
                advice.append(f"This domain deceptively mimics {features.brand_impersonated}. Do NOT enter account credentials, passwords, or OTPs.")
            else:
                explanation = f"CRITICAL THREAT: Verified malicious URL ({category.value}) designed to steal credentials or financial assets."
            advice.append("IMMEDIATE WARNING: Avoid visiting or interacting with this host.")
            advice.append("If you have entered passwords or banking PINs, freeze your account and reset your passwords immediately.")

        return URLScanResponse(
            url=features.url,
            original_url=features.original_url or features.url,
            normalized_url=features.normalized_url or features.url,
            domain=features.domain,
            canonical_domain=features.canonical_domain or features.domain,
            subdomain=features.subdomain,
            registered_domain=features.registered_domain,
            tld=features.tld or features.detected_tld,
            scheme=features.scheme or features.protocol,
            port=features.port,
            path=features.path,
            query=features.query,
            fragment=features.fragment,
            components=features.components,
            punycode_domain=features.punycode_domain,
            stripped_tracking_params=features.stripped_tracking_params,
            risk_score=final_score,
            risk_level=level,
            category=category,
            confidence=round(confidence, 2),
            url_features=features,
            threat_intel_match=is_threat_match,
            threat_sources=sources,
            contributing_factors=factors,
            mitigation_advice=advice,
            explanation=explanation
        )

url_risk_scorer = URLRiskScorer()
