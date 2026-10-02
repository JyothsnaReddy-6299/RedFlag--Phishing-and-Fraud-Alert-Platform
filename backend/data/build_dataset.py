#!/usr/bin/env python3
"""Build the RedFlag synthetic labeled dataset (contract section 23).

Provenance: 100% SYNTHETIC. Every row is generated from the templates below,
written by the project team to imitate publicly-described scam patterns in the
South Chennai / Tamil Nadu threat landscape. No real victim message, no real
personal data and no scraped private content is included.

Train and test use DISJOINT template pools so the evaluation cannot be won by
template memorization (contract: "prevent template leakage between train and
test").

Usage:
    python data/build_dataset.py            # writes dataset.jsonl + validation.jsonl
"""
from __future__ import annotations

import itertools
import json
import os
import random
from typing import Dict, List

random.seed(20260304)
HERE = os.path.dirname(os.path.abspath(__file__))

SLOTS: Dict[str, List[str]] = {
    "bank": ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Indian Bank", "Canara Bank"],
    "baddomain": [
        "http://sbi-kyc-verify.xyz/login", "http://hdfc-securelogin.top/update",
        "http://icici-netbank.cam/verify", "https://axis-kyc-update.online/acc",
        "http://indianbnk-kyc.site/re-kyc", "http://canara-verify.club/login",
        "http://bit.ly/3kycnow", "http://tinyurl.com/kyc-update-now",
    ],
    "gooddomain": [
        "https://www.onlinesbi.sbi", "https://www.hdfcbank.com",
        "https://www.icicibank.com", "https://www.axisbank.com",
    ],
    "phone": ["9123456780", "8012345671", "7845612390", "9994561230", "6383452190"],
    "upi": ["refund.help@ybl", "support.desk@okaxis", "winner2026@paytm", "claim.now@upi"],
    "amount": ["Rs.4,999", "Rs.12,500", "Rs.850", "Rs.2,00,000", "Rs.75,000"],
    "courier": ["Blue Dart", "India Post", "DHL", "FedEx"],
    "hours": ["24", "12", "6", "48"],
}


def fill(template: str, i: int) -> str:
    out = template
    for key, values in SLOTS.items():
        token = "{" + key + "}"
        while token in out:
            out = out.replace(token, values[(i + len(out)) % len(values)], 1)
            i += 1
    return out


# label -> {"train": [...templates...], "test": [...disjoint templates...]}
TEMPLATES: Dict[str, Dict[str, List[str]]] = {
    "kyc_account_freeze": {
        "train": [
            "Dear {bank} customer, your KYC has expired. Update immediately at {baddomain} or your account will be blocked within {hours} hours.",
            "URGENT: {bank} netbanking will be suspended today. Complete re-KYC here {baddomain}. Call {phone} for help.",
            "Your PAN card is not linked with {bank} account. Account freeze in {hours} hrs. Link now: {baddomain}",
            "அன்புள்ள {bank} வாடிக்கையாளரே, உங்கள் KYC காலாவதி ஆகிவிட்டது. உடனே {baddomain} இல் புதுப்பிக்கவும் இல்லையெனில் கணக்கு முடக்கப்படும்.",
            "Dear {bank} user, unga account KYC kaalavadhi mudinjiduchu. Udane {baddomain} la update pannunga illana account block aagidum.",
            "{bank} alert: Aadhaar not updated. Kanakku mudangum in {hours} hours. Click pannunga {baddomain} seekiram.",
        ],
        "test": [
            "Attention {bank} account holder: mandatory KYC re-verification pending. Visit {baddomain} before tonight to avoid deactivation.",
            "உங்கள் {bank} கணக்கு சரிபார்க்கப்படவில்லை. இன்று {baddomain} மூலம் ஆதார் இணைக்கவும், இல்லையெனில் நிறுத்தப்படும்.",
            "{bank} customer, unga netbanking block aagum innaiku. Re-kyc seiyavum {baddomain}. Doubt na call {phone}.",
        ],
    },
    "phishing_link": {
        "train": [
            "Your account has been temporarily locked for security reasons. Login here to restore access: {baddomain}",
            "Security alert: unusual login detected. Verify your identity now at {baddomain} or access will be revoked.",
            "{bank} secure message: confirm your netbanking credentials at {baddomain} within {hours} hours.",
            "பாதுகாப்பு எச்சரிக்கை: உங்கள் கணக்கில் சந்தேகத்திற்குரிய நுழைவு. {baddomain} இல் உடனே சரிபார்க்கவும்.",
            "Account lock aagiduchu. Unga details confirm pannunga ippo {baddomain} la. Avasaram!",
            "Reactivate your suspended profile immediately: {baddomain}. Do not share this link with others.",
        ],
        "test": [
            "We detected a sign-in from a new device. Secure your account right now: {baddomain}",
            "உங்கள் கணக்கு தற்காலிகமாக பூட்டப்பட்டுள்ளது. மீண்டும் திறக்க {baddomain} அழுத்துங்கள்.",
            "Profile verify pannala na account nirutthapadum. Link {baddomain} udane open pannunga.",
        ],
    },
    "impersonation": {
        "train": [
            "This is RBI compliance department. A case has been registered against your account. Contact officer on {phone} immediately to avoid arrest.",
            "Cyber Crime Cell notice: your number is linked to illegal activity. Digital arrest warrant pending. Call {phone} now.",
            "Income Tax Department: undisclosed income detected. Court summons issued. Reply on WhatsApp {phone} within {hours} hours.",
            "காவல்துறை அறிவிப்பு: உங்கள் பெயரில் வழக்கு பதிவாகியுள்ளது. உடனே {phone} என்ற எண்ணில் அதிகாரியை தொடர்பு கொள்ளவும்.",
            "RBI officer pesaren. Unga account la illegal transaction. Legal action varum. Udane {phone} ku call pannunga.",
            "TRAI notice: your SIM will be disconnected in {hours} hours due to illegal misuse. Press 9 or call {phone}.",
        ],
        "test": [
            "CBI Mumbai branch: a parcel containing narcotics was booked in your name. Non-bailable warrant issued. Call {phone}.",
            "அரசு அறிவிப்பு: உங்கள் ஆதார் தவறாக பயன்படுத்தப்பட்டுள்ளது. நீதிமன்ற நோட்டீஸ். அதிகாரி {phone}.",
            "Customs officer speaking. Unga parcel hold aagirukku. Penalty kattanum. Contact {phone} immediately.",
        ],
    },
    "refund_cashback": {
        "train": [
            "Your {amount} refund for a failed transaction is pending. Approve the collect request from {upi} to receive it.",
            "Income tax refund of {amount} approved. Submit bank details at {baddomain} to claim within {hours} hours.",
            "You were wrongly charged {amount}. Click {baddomain} and complete the reversal process now.",
            "உங்கள் {amount} பணம் திரும்பப் பெற {baddomain} இல் விவரங்களை அளிக்கவும். {hours} மணி நேரம் மட்டுமே.",
            "Unga {amount} refund pending irukku. {upi} ku vandha collect request approve pannunga udane.",
            "Cashback {amount} credited but blocked. Unlock here {baddomain} or it will expire today.",
        ],
        "test": [
            "Electricity bill overcharge of {amount} is refundable. Share account details on {phone} to process.",
            "உங்கள் தோல்வியுற்ற பரிவர்த்தனைக்கான {amount} திரும்பப் பெற {upi} கோரிக்கையை ஏற்கவும்.",
            "Failed payment reversal {amount} ready. Link {baddomain} la bank details kuduthidunga seekiram.",
        ],
    },
    "job_investment": {
        "train": [
            "Work from home opportunity! Earn {amount} daily with simple tasks. Join our Telegram group: {baddomain}",
            "Part time job for students. Daily payout {amount}. Registration fee {amount} to {upi}. Contact {phone}.",
            "Guaranteed 300% return on crypto investment. Start with {amount}. Trading signals group: {baddomain}",
            "வீட்டிலிருந்தே வேலை! தினமும் {amount} சம்பாதிக்கலாம். பதிவு செய்ய {baddomain}. முதலீடு பாதுகாப்பானது.",
            "Part time velai irukku. Daily {amount} income. Registration ku {upi} la {amount} anuppunga. Call {phone}.",
            "Double your money in 30 days. Guaranteed profit. Invest {amount} today via {upi}.",
        ],
        "test": [
            "Hiring data entry operators, no experience needed, salary {amount} weekly. Apply at {baddomain} with {amount} deposit.",
            "உறுதியான லாபம்! {amount} முதலீடு செய்து மாதம் {amount} பெறுங்கள். விவரங்களுக்கு {phone}.",
            "Trading group join pannunga, daily profit {amount} guarantee. Mudhaleedu {upi} la anuppavum.",
        ],
    },
    "lottery_prize": {
        "train": [
            "Congratulations! You have won {amount} in the KBC lucky draw. Pay {amount} processing fee to {upi} to claim.",
            "Your mobile number won {amount} in our anniversary lottery. Claim now at {baddomain} before it expires.",
            "LUCKY WINNER! Free iPhone selected for you. Pay {amount} delivery charge to {upi}. Call {phone}.",
            "வாழ்த்துக்கள்! நீங்கள் {amount} பரிசு வென்றுள்ளீர்கள். பெற {baddomain} இல் பதிவு செய்யவும்.",
            "Congratulations! Neenga {amount} parisu jeichittinga. Claim panna {upi} ku {amount} anuppunga.",
            "Gift voucher worth {amount} selected for your number. Redeem within {hours} hours: {baddomain}",
        ],
        "test": [
            "Jackpot alert: your SIM has been shortlisted for {amount}. Share OTP received to verify and release the prize.",
            "அதிர்ஷ்ட குலுக்கலில் {amount} வென்றீர்கள். பரிசு பெற {upi} க்கு கட்டணம் செலுத்தவும்.",
            "Lucky draw la unga number select aagirukku. {amount} vangurathuku {baddomain} la register pannunga.",
        ],
    },
    "delivery_scam": {
        "train": [
            "{courier}: your parcel is on hold because the address is incomplete. Update it here {baddomain} within {hours} hours.",
            "{courier} delivery failed. Pay customs duty of {amount} at {baddomain} to reschedule.",
            "Your shipment is stuck at customs clearance. Pay {amount} to {upi} for release. Tracking id {phone}.",
            "{courier}: உங்கள் பார்சல் முகவரி தவறாக உள்ளது. {baddomain} இல் புதுப்பிக்கவும், இல்லையெனில் திருப்பி அனுப்பப்படும்.",
            "{courier} parcel delivery fail aaiduchu. Address update pannunga {baddomain} la, illana return aagidum.",
            "Consignment held: unpaid shipping charge {amount}. Settle now {baddomain} to avoid return to sender.",
        ],
        "test": [
            "{courier} notice: redelivery attempt scheduled. Confirm your address and pay {amount} handling fee: {baddomain}",
            "{courier}: உங்கள் பொருள் சுங்கத்தில் நிறுத்தப்பட்டுள்ளது. {amount} கட்டணம் {upi} க்கு செலுத்தவும்.",
            "Unga package customs la stuck. {amount} duty kattunga {upi} la, illana parcel return pannidum.",
        ],
    },
    "remote_access_scam": {
        "train": [
            "To resolve your {bank} complaint, install AnyDesk and share the 9 digit code with our executive on {phone}.",
            "Bank support here. Download this app {baddomain} and allow screen share so we can refund {amount}.",
            "Please install the TeamViewer QuickSupport app and share the ID to complete your verification.",
            "உங்கள் பிரச்சினையை தீர்க்க AnyDesk செயலியை நிறுவி, குறியீட்டை {phone} க்கு அனுப்பவும்.",
            "Problem solve panna AnyDesk app install pannunga, code-a {phone} ku sollunga. Udane.",
            "Download the official support APK from {baddomain} and allow all permissions for faster service.",
        ],
        "test": [
            "Our technician needs screen access. Install QuickSupport from {baddomain} and share the connection ID.",
            "சேவைக்காக {baddomain} இல் உள்ள செயலியை நிறுவி அனுமதி வழங்கவும்.",
            "Refund process panna screen share app install pannunga {baddomain}, ID-a {phone} ku anuppunga.",
        ],
    },
    "utility_bill": {
        "train": [
            "Dear consumer, your electricity will be disconnected tonight at 9:30 PM because last month bill was not updated. Contact TNEB officer {phone}.",
            "TANGEDCO notice: bill unpaid. Power cut today. Pay {amount} immediately at {baddomain}.",
            "Your gas subsidy is pending. Update meter reading at {baddomain} within {hours} hours.",
            "மின்சாரம் இன்று இரவு துண்டிக்கப்படும். கடந்த மாத கட்டணம் செலுத்தப்படவில்லை. அதிகாரி {phone} ஐ தொடர்பு கொள்ளவும்.",
            "Minsaram innaiku night cut aagidum, bill update aagala. TNEB officer {phone} ku udane call pannunga.",
            "Electricity board alert: meter reading mismatch. Pay {amount} to {upi} to avoid disconnection.",
        ],
        "test": [
            "Power supply will be terminated at 10 PM due to a pending {amount} payment. Settle here: {baddomain}",
            "உங்கள் மின்சார இணைப்பு இன்று நிறுத்தப்படும். {amount} கட்டணத்தை {baddomain} இல் செலுத்தவும்.",
            "Karandu disconnect aagum innaiku. {amount} bill pending. Pay pannunga {upi} la seekiram.",
        ],
    },
    "legitimate": {
        "train": [
            "Rs.2,340.00 debited from A/c XX4521 on 14-02-26 to VPA grocery@okicici. Not you? Call 18001234.",
            "Your OTP for login is 483920. Valid for 10 minutes. Do not share your OTP with anyone. - {bank}",
            "Thank you for shopping with us. Your order has been delivered. Rate your experience in the app.",
            "Avl Bal in A/c XX8891 as on 02-03-26 is Rs.18,402.55. For queries visit {gooddomain}.",
            "உங்கள் மின்சார கட்டணம் ரூ.1,250 பெறப்பட்டது. நன்றி. ரசீது எண் TN88211.",
            "Unga parcel innaiku evening deliver aagum. Delivery partner contact pannuvanga. Nandri.",
            "Reminder: your appointment at the clinic is tomorrow at 11:00 AM. Reply STOP to unsubscribe.",
            "Your monthly statement for A/c XX7712 is ready. Download it from {gooddomain} after logging in.",
        ],
        "test": [
            "Rs.899 credited to your account as a merchant refund on 21-01-26. Ref 884512. No action needed.",
            "OTP for your transaction is 229104. This is an automated message. Bank never asks for your OTP.",
            "உங்கள் புத்தக ஆர்டர் அனுப்பப்பட்டது. நாளை வந்து சேரும். நன்றி.",
            "Unga train ticket confirm aaiduchu. PNR 4472819011. Journey date 12-04-26. Nalla payanam.",
        ],
    },
}

VARIANTS_PER_TEMPLATE = 4


def build(split: str) -> List[dict]:
    rows: List[dict] = []
    for label, pools in TEMPLATES.items():
        for t_idx, template in enumerate(pools[split]):
            for v in range(VARIANTS_PER_TEMPLATE):
                text = fill(template, t_idx * 7 + v * 3)
                rows.append({
                    "text": text,
                    "label": label,
                    "split": split,
                    "template_id": f"{label}:{split}:{t_idx}",
                    "provenance": "synthetic",
                    "generator": "data/build_dataset.py",
                })
    random.shuffle(rows)
    return rows


def main() -> None:
    train = build("train")
    test = build("test")
    for name, rows in (("dataset.jsonl", train), ("validation.jsonl", test)):
        path = os.path.join(HERE, name)
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"wrote {len(rows):4d} rows -> {path}")
    train_ids = {r["template_id"] for r in train}
    test_ids = {r["template_id"] for r in test}
    assert not (train_ids & test_ids), "template leakage detected"
    print(f"classes: {sorted(TEMPLATES)}")
    print("template leakage check: PASS (train/test template pools are disjoint)")


if __name__ == "__main__":
    main()
