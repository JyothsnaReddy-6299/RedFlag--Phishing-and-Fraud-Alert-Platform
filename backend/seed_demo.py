#!/usr/bin/env python3
"""Reset + seed a repeatable RedFlag demo (contract P0 "Seeded demo").

Running this twice produces the SAME dashboard, the same campaign graph and
the same shared indicators, so a judge can be shown an identical run.

All content is synthetic. Indicators (domains, phones, UPI IDs) are invented
for the demo and deliberately do not correspond to real people.

Usage:
    python seed_demo.py            # wipe and reseed
    python seed_demo.py --keep     # seed without wiping
"""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.intel import analyzer, db as m, reports  # noqa: E402

random.seed(20261003)
NOW = datetime(2026, 10, 2, 9, 0, 0)

# (days_ago, hours, text, sender, channel, locality, consent/public)
SIGHTINGS = [
    # --- Campaign A: "SBI KYC freeze" — shared domain + shared phone ---------
    (9, 2, "Dear SBI customer, your KYC has expired. Update immediately at "
           "http://sbi-kyc-verify.xyz/login or your account will be blocked within 24 hours. "
           "Helpline 9123456780.",
     "VM-SBIINB", "sms", "Velachery", True),
    (7, 5, "SBI user, unga account KYC kaalavadhi mudinjiduchu. Udane "
           "http://sbi-kyc-verify.xyz/login la update pannunga illana account block aagidum. "
           "Call 9123456780.",
     "+919123456780", "whatsapp", "Adyar", True),
    (5, 1, "அன்புள்ள SBI வாடிக்கையாளரே, உங்கள் KYC காலாவதி ஆகிவிட்டது. உடனே "
           "http://sbi-kyc-verify.xyz/login இல் புதுப்பிக்கவும், இல்லையெனில் கணக்கு முடக்கப்படும்.",
     "AD-SBIBNK", "sms", "Thoraipakkam", True),
    (3, 4, "URGENT: SBI netbanking will be suspended today. Complete re-KYC here "
           "http://sbi-kyc-portal.top/verify. Officer 9123456780.",
     "+919123456780", "sms", "Medavakkam", True),

    # --- Campaign B: "Courier customs duty" — shared UPI across domains ------
    (8, 3, "Blue Dart: your parcel is on hold because the address is incomplete. "
           "Pay customs duty of Rs.850 at http://bluedart-clearance.site/pay or it will be "
           "returned. UPI refund.help@ybl",
     "BD-ALERT", "sms", "Sholinganallur", True),
    (6, 6, "India Post: unga package customs la stuck. Rs.850 duty kattunga "
           "refund.help@ybl la, illana parcel return pannidum. http://indiapost-duty.cam/clear",
     "+918012345671", "whatsapp", "Perungudi", True),
    (2, 2, "DHL: consignment held at customs. Unpaid shipping charge Rs.1,250. "
           "Settle now at http://dhl-customs-pay.club/release. UPI refund.help@ybl",
     "DH-NOTICE", "sms", "Navalur", True),

    # --- Campaign C: "TNEB electricity disconnection" -----------------------
    (10, 7, "Dear consumer, your electricity will be disconnected tonight at 9:30 PM "
            "because last month bill was not updated. Contact TNEB officer 9994561230.",
     "+919994561230", "sms", "Pallikaranai", True),
    (4, 8, "Karandu disconnect aagum innaiku night. Rs.2,340 bill pending. "
           "Pay pannunga http://tneb-billpay.online/now la seekiram. Officer 9994561230.",
     "+919994561230", "whatsapp", "Madipakkam", True),
    (1, 3, "உங்கள் மின்சார இணைப்பு இன்று இரவு நிறுத்தப்படும். Rs.1,980 கட்டணத்தை "
           "http://tneb-billpay.online/now இல் செலுத்தவும். அதிகாரி 9994561230.",
     "TN-TNEB", "sms", "Thiruvanmiyur", True),

    # --- Standalone sightings (so the graph is not uniformly clustered) ------
    (6, 9, "Congratulations! You have won Rs.12,50,000 in the KBC lucky draw. "
           "Pay Rs.4,999 processing fee to winner2026@paytm to claim. Call 7845612390.",
     "+917845612390", "whatsapp", "Guindy", True),
    (3, 6, "Work from home opportunity! Earn Rs.3,500 daily with simple tasks. "
           "Join our Telegram group: http://task-earn-daily.xyz/join. Registration Rs.999 "
           "to claim.now@upi",
     "+916383452190", "social", "Tambaram", True),
    (2, 7, "To resolve your HDFC Bank complaint, install AnyDesk and share the 9 digit "
           "code with our executive on 6383452190.",
     "+916383452190", "call", "Alwarpet", False),
]

# Pending items so the moderator queue is not empty during the demo.
PENDING = [
    ("ICICI Bank alert: Aadhaar not updated, account freeze in 12 hrs. Link now "
     "http://icici-netbank.cam/verify", "AX-ICICI", "sms", "Besant Nagar"),
    ("Your Rs.4,999 refund for a failed transaction is pending. Approve the collect "
     "request from refund.help@ybl to receive it.", "+919123456780", "whatsapp", "Velachery"),
]

# A legitimate message, so the demo can show a LOW verdict too.
LEGIT = ("Rs.2,340.00 debited from A/c XX4521 on 14-02-26 to VPA grocery@okicici. "
         "Not you? Call 18001234. Do not share your OTP with anyone.", "AD-SBIBNK")


def wipe(session) -> None:
    for table in (m.AnalysisEntity, m.RiskFactor, m.Evidence, m.Relationship,
                  m.Report, m.Analysis, m.Entity, m.Campaign, m.User):
        session.query(table).delete()
    session.commit()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="do not wipe existing data")
    args = ap.parse_args()

    m.init_db()
    session = m.SessionLocal()
    try:
        if not args.keep:
            wipe(session)
            print("· cleared existing demo data")

        session.add(m.User(id="mod_demo", role="moderator", display_name="Demo Moderator"))
        session.commit()

        created = 0
        for days, hours, text, sender, channel, locality, public in SIGHTINGS:
            when = NOW - timedelta(days=days, hours=hours)
            result = analyzer.analyze(text, input_type="text", sender_id=sender,
                                      session=session, persist=True)
            row = session.get(m.Analysis, result["analysis_id"])
            if row:
                row.created_at = when
            out = reports.create_report(
                session, analysis_id=result["analysis_id"],
                category=result["scam_category"], channel=channel,
                narrative=text, locality=locality, occurred_at=when,
                consent=public, visibility="public" if public else "private",
                reporter_id=None, auto_approve=True)
            rep = session.get(m.Report, out["report"]["id"])
            if rep:
                rep.created_at = when
            session.commit()
            created += 1
            print(f"· seeded [{result['risk_score']:3d}/{result['verdict']:<8}] "
                  f"{result['scam_category']:<20} {locality}")

        for text, sender, channel, locality in PENDING:
            result = analyzer.analyze(text, input_type="text", sender_id=sender,
                                      session=session, persist=True)
            reports.create_report(
                session, analysis_id=result["analysis_id"],
                category=result["scam_category"], channel=channel, narrative=text,
                locality=locality, occurred_at=NOW - timedelta(hours=5),
                consent=True, visibility="public", reporter_id=None,
                auto_approve=False)
            print(f"· queued for moderation [{result['risk_score']:3d}] {locality}")

        legit = analyzer.analyze(LEGIT[0], input_type="text", sender_id=LEGIT[1],
                                 session=session, persist=True)
        print(f"· seeded legitimate control [{legit['risk_score']}/{legit['verdict']}]")

        campaigns = session.query(m.Campaign).all()
        print(f"\nSeed complete: {created} approved reports, "
              f"{len(PENDING)} pending, {len(campaigns)} campaigns.")
        for c in campaigns:
            print(f"   - {c.id}  {c.label}  ({c.report_count} reports, {c.status})")
        print(f"\nDatabase: {m.DATABASE_URL}")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
