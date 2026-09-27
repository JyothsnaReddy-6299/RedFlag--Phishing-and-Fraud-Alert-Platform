from typing import Dict, List, Optional, Any
from app.models.schemas import ExtractedEntities

# Seed known malicious threat intelligence database
KNOWN_MALICIOUS_DOMAINS = {
    "sbi-kyc-update.xyz": {"category": "BANKING_FRAUD", "target": "SBI", "confidence": 0.99, "source": "ThreatFeed_URLhaus"},
    "tneb-bill-payment.net": {"category": "ELECTRICITY_BILL", "target": "TNEB", "confidence": 0.98, "source": "CommunityReports"},
    "hdfc-rewards-claim.top": {"category": "BANKING_FRAUD", "target": "HDFC", "confidence": 0.99, "source": "ThreatFeed_PhishTank"},
    "icici-netbanking-verify.cc": {"category": "BANKING_FRAUD", "target": "ICICI", "confidence": 0.99, "source": "ThreatFeed_OpenPhish"},
    "paytm-cashback-bonus.live": {"category": "UPI_FRAUD", "target": "Paytm", "confidence": 0.97, "source": "CommunityReports"},
    "parttime-telegram-job.club": {"category": "JOB_SCAM", "target": "General", "confidence": 0.95, "source": "CommunityReports"},
}

KNOWN_FRAUD_UPIS = {
    "tneb.officer984@okhdfcbank": {"category": "ELECTRICITY_BILL", "reports_count": 18, "status": "VERIFIED_MALICIOUS"},
    "electricitybill.eb@paytm": {"category": "ELECTRICITY_BILL", "reports_count": 24, "status": "VERIFIED_MALICIOUS"},
    "sbi.kyc.helpline@ybl": {"category": "KYC_EXPIRY", "reports_count": 31, "status": "VERIFIED_MALICIOUS"},
    "lotterywinner.tax@okaxis": {"category": "LOTTERY_PRIZE", "reports_count": 12, "status": "VERIFIED_MALICIOUS"},
}

KNOWN_FRAUD_PHONES = {
    "9840123456": {"category": "ELECTRICITY_BILL", "reports_count": 19, "status": "VERIFIED_MALICIOUS", "alias": "Fake TNEB Officer"},
    "9876543210": {"category": "KYC_EXPIRY", "reports_count": 27, "status": "VERIFIED_MALICIOUS", "alias": "Fake SBI KYC Helpline"},
    "8921345678": {"category": "JOB_SCAM", "reports_count": 14, "status": "VERIFIED_MALICIOUS", "alias": "Work-From-Home Recruiter"},
}

class ThreatIntelligenceEngine:
    def __init__(self):
        self.domains_db = KNOWN_MALICIOUS_DOMAINS
        self.upis_db = KNOWN_FRAUD_UPIS
        self.phones_db = KNOWN_FRAUD_PHONES

    def check_entities(self, entities: ExtractedEntities, db=None) -> Dict[str, Any]:
        matched_indicators = []
        threat_score_boost = 0.0
        reputation_verdict = "NEUTRAL"
        sources = []

        # 1. Check verified indicators in Database (Dynamic Intelligence Accumulation)
        if db is not None:
            try:
                from app.db.models import ThreatIndicator
                # Check DB for domains
                for domain in entities.domains:
                    db_ind = db.query(ThreatIndicator).filter(
                        ThreatIndicator.indicator_type == "DOMAIN",
                        ThreatIndicator.indicator_value == domain.lower(),
                        ThreatIndicator.status == "VERIFIED_MALICIOUS"
                    ).first()
                    if db_ind:
                        matched_indicators.append({
                            "type": "DOMAIN",
                            "value": domain.lower(),
                            "category": db_ind.category or "MALICIOUS",
                            "source": f"CommunityThreatDB ({db_ind.report_count} verified reports)",
                            "confidence": 0.99
                        })
                        threat_score_boost += 50.0
                        sources.append(f"Verified Threat Database ({db_ind.report_count} reports)")
                        reputation_verdict = "CONFIRMED_MALICIOUS"

                # Check DB for UPIs
                for upi in entities.upi_ids:
                    db_ind = db.query(ThreatIndicator).filter(
                        ThreatIndicator.indicator_type == "UPI",
                        ThreatIndicator.indicator_value == upi.lower(),
                        ThreatIndicator.status == "VERIFIED_MALICIOUS"
                    ).first()
                    if db_ind:
                        matched_indicators.append({
                            "type": "UPI_ID",
                            "value": upi.lower(),
                            "category": db_ind.category or "UPI_FRAUD",
                            "source": f"CommunityThreatDB ({db_ind.report_count} verified reports)",
                            "confidence": 0.98
                        })
                        threat_score_boost += 45.0
                        sources.append(f"Verified Threat Database ({db_ind.report_count} reports)")
                        reputation_verdict = "CONFIRMED_MALICIOUS"

                # Check DB for Phone Numbers
                for phone in entities.phone_numbers:
                    db_ind = db.query(ThreatIndicator).filter(
                        ThreatIndicator.indicator_type == "PHONE",
                        ThreatIndicator.indicator_value == phone,
                        ThreatIndicator.status == "VERIFIED_MALICIOUS"
                    ).first()
                    if db_ind:
                        matched_indicators.append({
                            "type": "PHONE_NUMBER",
                            "value": phone,
                            "category": db_ind.category or "FRAUD",
                            "source": f"CommunityThreatDB ({db_ind.report_count} verified reports)",
                            "confidence": 0.98
                        })
                        threat_score_boost += 45.0
                        sources.append(f"Verified Threat Database ({db_ind.report_count} reports)")
                        reputation_verdict = "CONFIRMED_MALICIOUS"
            except Exception:
                pass

        # 2. Check Static Seed Feeds
        # Check domains
        for domain in entities.domains:
            domain_clean = domain.lower()
            if domain_clean in self.domains_db:
                info = self.domains_db[domain_clean]
                matched_indicators.append({
                    "type": "DOMAIN",
                    "value": domain_clean,
                    "category": info["category"],
                    "source": info["source"],
                    "confidence": info["confidence"]
                })
                threat_score_boost += 50.0
                sources.append(info["source"])
                reputation_verdict = "CONFIRMED_MALICIOUS"

        # Check UPI IDs
        for upi in entities.upi_ids:
            upi_clean = upi.lower()
            if upi_clean in self.upis_db:
                info = self.upis_db[upi_clean]
                matched_indicators.append({
                    "type": "UPI_ID",
                    "value": upi_clean,
                    "category": info["category"],
                    "reports_count": info["reports_count"],
                    "status": info["status"]
                })
                threat_score_boost += 45.0
                sources.append(f"CommunityReports ({info['reports_count']} flags)")
                reputation_verdict = "CONFIRMED_MALICIOUS"

        # Check Phone Numbers
        for phone in entities.phone_numbers:
            if phone in self.phones_db:
                info = self.phones_db[phone]
                matched_indicators.append({
                    "type": "PHONE_NUMBER",
                    "value": phone,
                    "category": info["category"],
                    "reports_count": info["reports_count"],
                    "status": info["status"]
                })
                threat_score_boost += 40.0
                sources.append(f"CommunityFraudDB ({info['reports_count']} reports)")
                reputation_verdict = "CONFIRMED_MALICIOUS"

        return {
            "matched": len(matched_indicators) > 0,
            "matched_indicators": matched_indicators,
            "threat_score_boost": threat_score_boost,
            "verdict": reputation_verdict,
            "sources": list(set(sources))
        }

threat_engine = ThreatIntelligenceEngine()
