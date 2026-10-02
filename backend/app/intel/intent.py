"""Intent + scam-class classification with evidence spans (contract s.11).

Hybrid design per section 24: a deterministic rule/feature backbone that always
works, plus an optional lightweight TF-IDF classifier (app.intel.classifier)
that refines the scam category. Rules are the safety net; the model only
generalizes. Every signal returns the exact fragment that produced it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Intent families (contract: urgency, authority impersonation, payment,
# credential request, reward bait, threat)
# ---------------------------------------------------------------------------
INTENT_PATTERNS: Dict[str, List[str]] = {
    "urgency": [
        r"\bimmediately\b", r"\burgent(ly)?\b", r"\bright now\b", r"\bwithin \d+\s?(hours?|hrs?|minutes?|mins?|days?)\b",
        r"\bbefore (today|tonight|midnight|\d)", r"\blast (reminder|chance|warning)\b",
        r"\bexpir(e|es|ed|ing|y)\b", r"\bact (now|fast|today)\b", r"\btoday itself\b",
        r"\bonly \d+ (hours?|minutes?) left\b", r"\bfinal notice\b", r"\bdo it now\b",
        r"\bbefore it expires\b", r"\bexpires? (today|tonight|soon)\b", r"\btoday only\b",
        r"\b(at|by) \d{1,2}(:\d{2})? ?(am|pm)\b", r"\bimmediate(ly)? action\b",
        r"\bpending\b", r"\bhurry\b", r"\bquickly\b", r"\bseekiram\b", r"\budane\b",
        r"\bavasaram\b", r"\binnaiku\b", r"\bippo\b", r"\bnow\b",
    ],
    "threat": [
        r"\bwill be (blocked|suspended|frozen|closed|deactivated|terminated|disconnected)\b",
        r"\b(account|card|sim|connection|service) (block|suspend|freeze|closure)\w*\b",
        r"\blegal action\b", r"\bfir\b", r"\barrest(ed)?\b", r"\bpenalty\b", r"\bfine of\b",
        r"\bcourt (notice|summons)\b", r"\bcyber cell\b", r"\bnon[- ]bailable\b",
        r"\bdigital arrest\b", r"\bcase (has been )?(filed|registered)\b",
    ],
    "credential_request": [
        r"\botp\b", r"\bone[- ]time password\b", r"\bcvv\b", r"\bpin\b", r"\bpassword\b",
        r"\bmpin\b", r"\bupi pin\b", r"\bnet ?banking (id|login|credentials)\b",
        r"\buser ?id and password\b", r"\bshare (your )?(otp|pin|cvv|password)\b",
        r"\blogin (here|now|to verify)\b", r"\benter your (card|account|aadhaar|pan)\b",
        r"\bverify (your )?(account|identity|kyc|details)\b", r"\bre[- ]?kyc\b",
        r"\bshare (your )?(account|bank|card) details\b", r"\bsubmit (your )?bank details\b",
        r"\bbank details (kuduthidunga|anuppunga|share)\b", r"\bconfirm your (credentials|details)\b",
        r"\bshare (the )?(otp|code|id) (received|with)\b", r"\baccount details\b",
        r"\bupdate (your )?(kyc|pan|aadhaar|details)\b", r"\blink (your )?(pan|aadhaar)\b",
        r"\bsecure your account\b", r"\brestore access\b", r"\bto unlock\b",
        r"\bconfirm your identity\b", r"\breactivate\b",
    ],
    "payment_request": [
        r"\bpay (rs|inr|₹|now|immediately)\b", r"\btransfer (rs|inr|₹|the amount|money)\b",
        r"\bsend (rs|inr|₹|money|payment)\b", r"\bupi\b", r"\bscan (the )?qr\b",
        r"\bprocessing fee\b", r"\bsecurity deposit\b", r"\bregistration (fee|charge)\b",
        r"\bgst (charge|fee|payment)\b", r"\bcustoms (duty|clearance|fee)\b",
        r"\brefundable (amount|deposit)\b", r"\bcollect request\b", r"\bapprove the request\b",
        r"\b(duty|fee|charge|penalty|bill|amount) (kattunga|kattanum|settle|pay)\b",
        r"\bsettle (now|the|your)\b", r"\bpay(ment)? (of )?rs\b", r"\bhandling fee\b",
        r"\bshipping charge\b", r"\bdelivery charge\b", r"\bdeposit\b",
        r"\b(anuppunga|anuppavum|kattunga|kattanum)\b", r"\bprocessing charge\b",
        r"\bpay .{0,20}(immediately|now|today|here)\b", r"\bmudhaleedu\b",
        r"\bfee payment\b", r"\bcustoms\b",
        r"\bpay\b.{0,18}\b(fee|duty|charge|customs|penalty|bill|amount)\b",
        r"\bapprove\b.{0,12}\brequest\b", r"\brequest approve\b",
    ],
    "reward_bait": [
        r"\bcongratulations?\b", r"\byou (have )?(won|win)\b", r"\blucky (draw|winner)\b",
        r"\blottery\b", r"\bprize\b", r"\bcashback\b", r"\bbonus\b", r"\bgift (card|voucher|hamper)\b",
        r"\bfree (recharge|gift|iphone|offer)\b", r"\breward points? (expir|redeem)\w*\b",
        r"\bclaim (your|now|the)\b", r"\bguaranteed (return|profit|income)\b",
        r"\bdaily (income|earning)\b", r"\bwork from home\b", r"\bpart[- ]time job\b",
        r"\bearn (rs|inr|₹|upto|up to)\b", r"\bdouble your (money|investment)\b",
        r"\bdaily (profit|payout)\b", r"\bweekly (salary|payout|income)\b",
        r"\bguarantee[d]?\b", r"\bno experience (needed|required)\b",
        r"\brefundable\b", r"\boverchar(ge|ged)\b", r"\bshortlisted\b",
        r"\bselected for (you|your)\b", r"\bjackpot\b", r"\bparisu\b",
        r"\bjeichit?t?inga\b", r"\bsambathikkalam\b", r"\bsampaathi\b",
        r"\b\d{2,3}% return\b", r"\bprofit\b",
    ],
    "authority_impersonation": [
        r"\brbi\b", r"\breserve bank\b", r"\bincome tax (department|dept)\b",
        r"\bcyber (crime|cell|police)\b", r"\bpolice\b", r"\bcbi\b", r"\bed\b(?= officer)",
        r"\btrai\b", r"\bcourier (company|department)\b", r"\bcustoms\b", r"\bnarcotics\b",
        r"\b(bank|government|govt) official\b", r"\bexecutive (calling|from)\b",
        r"\bhelpline\b", r"\bcustomer (care|support) (number|team)\b", r"\bofficer\b",
        r"\bcompliance department\b", r"\b(tangedco|tneb|electricity board)\b",
        r"\buidai\b", r"\bnpci\b", r"\bgovernment (notice|alert)\b",
        r"\bbank (support|executive) (here|speaking)\b", r"\bour (technician|executive)\b",
        r"\bpesaren\b", r"\bkaavalthurai\b", r"\bofficer speaking\b",
        r"\bgovernment notice\b", r"\bcourt notice\b", r"\bnotice\b(?= .{0,20}officer)",
    ],
    "remote_access": [
        r"\banydesk\b", r"\bteam ?viewer\b", r"\bquick ?support\b", r"\bairdroid\b",
        r"\bscreen (share|sharing)\b", r"\binstall (this|the) app\b",
        r"\bdownload (the )?apk\b", r"\b\.apk\b", r"\ballow access\b",
        r"\ballow all permissions\b", r"\bconnection id\b", r"\b9 digit code\b",
        r"\bscreen access\b", r"\bsupport app\b", r"\binstall .{0,24}(app|application|apk)\b",
    ],
    "contact_pivot": [
        r"\bwhatsapp (me|us|on|number)\b", r"\bcall (me|us|this number|immediately) (on|at)?\b",
        r"\bcontact (us|our) (executive|officer|team)\b", r"\breply (yes|stop|with)\b",
        r"\bdo not (tell|inform|discuss)\b", r"\bkeep (this )?confidential\b",
        r"\btelegram (group|channel)\b", r"\bjoin (our|the) group\b",
        r"\bdo not share this (link|message) with (others|anyone)\b",
        r"\bpress \d\b", r"\bcall (this |the )?(number|officer|executive)\b",
        r"\bcall \+?\d", r"\bcontact \+?\d", r"\bwhatsapp \+?\d",
    ],
}

# ---------------------------------------------------------------------------
# Scam classes (contract s.23)
# ---------------------------------------------------------------------------
SCAM_CLASSES: Dict[str, Dict] = {
    "kyc_account_freeze": {
        "label": "KYC / Account-freeze scam",
        "patterns": [r"\bkyc\b", r"\bre[- ]?kyc\b", r"\bpan (card )?(link|update|verif)", r"\baadhaar (link|update|verif)",
                     r"\baccount will be (blocked|frozen|suspended)", r"\bupdate your (kyc|details) to avoid",
                     r"\byono (app|account)", r"\bnet ?banking (block|suspend)"],
        "intents": ["threat", "urgency", "credential_request"],
    },
    "phishing_link": {
        "label": "Phishing link",
        "patterns": [r"\bclick (here|this|the link|below)", r"\blogin (here|now)", r"\bverify (here|now|your account)",
                     r"\bsecure(d)? link", r"\bupdate (here|now)", r"\bactivate (here|now)"],
        "intents": ["credential_request", "urgency"],
    },
    "impersonation": {
        "label": "Authority / brand impersonation",
        "patterns": [r"\brbi\b", r"\bcyber (crime|cell)", r"\bpolice\b", r"\bincome tax\b", r"\bcustoms\b",
                     r"\bdigital arrest\b", r"\bcourt (notice|summons)", r"\bofficer speaking\b", r"\btrai\b", r"\bcbi\b", r"\bnarcotics\b",
                     r"\bwarrant\b", r"\bcompliance department\b", r"\bcustoms officer\b",
                     r"\bpesaren\b", r"\bkaavalthurai\b", r"\bgovernment notice\b",
                     r"\bcourt\b", r"\bmisused\b"],
        "intents": ["authority_impersonation", "threat"],
    },
    "refund_cashback": {
        "label": "Refund / cashback scam",
        "patterns": [r"\brefund\b", r"\bcashback\b", r"\breversal\b", r"\bwrongly (debited|charged)",
                     r"\bclaim your refund\b", r"\bitr refund\b", r"\bincome tax refund\b", r"\bfailed transaction\b",
                     r"\boverchar(ge|ged)\b", r"\brefundable\b", r"\breversal process\b",
                     r"\bcollect request\b",
                     r"\bapprove\b.{0,12}\brequest\b", r"\brefund\b"],
        "intents": ["payment_request", "reward_bait"],
    },
    "job_investment": {
        "label": "Job / investment scam",
        "patterns": [r"\bwork from home\b", r"\bpart[- ]time job\b", r"\bdaily (income|earning|payout)",
                     r"\btask (based|complete)", r"\btelegram (group|channel)", r"\bguaranteed (return|profit)",
                     r"\btrading (account|signal|group)", r"\bcrypto (profit|doubling)", r"\binvest (rs|₹|now)",
                     r"\bearn (rs|₹)\s?\d",
                     r"\bno experience\b", r"\bdata entry\b", r"\bhiring\b",
                     r"\bdaily profit\b", r"\bweekly salary\b", r"\bvelai\b",
                     r"\b\d{2,3}% return\b", r"\bmudhaleedu\b",
                     r"\binvestment\b", r"\bcan earn\b", r"\bguaranteed\b",
                     r"\bprofit\b", r"\bmonthly (income|return)\b"],
        "intents": ["reward_bait", "payment_request"],
    },
    "lottery_prize": {
        "label": "Lottery / prize scam",
        "patterns": [r"\blottery\b", r"\blucky (draw|winner)", r"\byou (have )?won\b", r"\bprize money\b",
                     r"\bkbc\b", r"\bjackpot\b", r"\bgift (hamper|voucher) (won|selected)",
                     r"\bshortlisted\b", r"\blucky winner\b", r"\bfree iphone\b",
                     r"\bparisu\b", r"\bjeichit?t?inga\b", r"\bprize\b"],
        "intents": ["reward_bait", "payment_request"],
    },
    "delivery_scam": {
        "label": "Delivery / courier scam",
        "patterns": [r"\b(parcel|package|shipment|consignment)\b", r"\bdelivery (failed|attempt|address)",
                     r"\bcourier (held|stuck|pending)", r"\bcustoms (duty|clearance)", r"\btracking (id|number)",
                     r"\baddress (incomplete|incorrect)", r"\breschedule (your )?delivery",
                     r"\bredelivery\b", r"\bhandling fee\b", r"\bshipping charge\b",
                     r"\breturn to sender\b", r"\bconsignment held\b",
                     r"\bcustoms\b", r"\bis held\b", r"\bfee payment\b"],
        "intents": ["payment_request", "urgency"],
    },
    "remote_access_scam": {
        "label": "Remote-access / malicious app scam",
        "patterns": [r"\banydesk\b", r"\bteam ?viewer\b", r"\b\.apk\b", r"\binstall (this|our) app",
                     r"\bscreen shar", r"\bdownload (the )?application",
                     r"\bquicksupport\b", r"\bconnection id\b", r"\ballow all permissions\b",
                     r"\bscreen access\b"],
        "intents": ["remote_access"],
    },
    "utility_bill": {
        "label": "Utility / electricity-bill scam",
        "patterns": [r"\belectricity\b", r"\bpower (will be )?(cut|disconnect)", r"\btneb\b", r"\btangedco\b",
                     r"\bmeter (reading|update)", r"\bbill (not |un)?(paid|pending)", r"\bdisconnect(ed|ion)?\b",
                     r"\bgas (connection|subsidy)",
                     r"\bpower supply\b", r"\bkarandu\b", r"\bminsaram\b",
                     r"\bconsumer\b", r"\bmeter\b"],
        "intents": ["threat", "urgency", "payment_request"],
    },
    "legitimate": {"label": "No scam pattern detected", "patterns": [], "intents": []},
}

# Benign markers that argue AGAINST a scam verdict (false-positive control).
BENIGN_PATTERNS = [
    r"\bdo not share your otp with anyone\b",
    r"\bbank never asks\b", r"\bnever share your (otp|pin|cvv)\b",
    r"\bthis is an automated (message|notification)\b",
    r"\bthank you for (shopping|banking|your payment)\b",
    r"\bavl bal\b", r"\bavailable balance\b",
    r"\byour (order|parcel) .{0,30}\b(has been )?delivered\b",
    r"\botp for .{0,40} is \d{4,8}\b",
    r"\bcredited to your (a/c|account)\b",
    r"\bdebited from your (a/c|account)\b",
]


@dataclass
class Signal:
    name: str
    family: str
    evidence_span: str
    start: int
    end: int
    source: str = "rule"

    def to_dict(self) -> dict:
        return {
            "name": self.name, "family": self.family,
            "evidence_span": self.evidence_span,
            "start": self.start, "end": self.end, "source": self.source,
        }


@dataclass
class IntentResult:
    intents: Dict[str, List[Signal]] = field(default_factory=dict)
    signals: List[Signal] = field(default_factory=list)
    benign_signals: List[Signal] = field(default_factory=list)
    scam_category: str = "legitimate"
    scam_label: str = "No scam pattern detected"
    category_scores: Dict[str, float] = field(default_factory=dict)
    classifier_used: bool = False
    classifier_category: Optional[str] = None
    classifier_confidence: float = 0.0

    @property
    def intent_families(self) -> List[str]:
        return sorted(self.intents.keys())

    def to_dict(self) -> dict:
        return {
            "intent_families": self.intent_families,
            "signals": [s.to_dict() for s in self.signals],
            "benign_signals": [s.to_dict() for s in self.benign_signals],
            "scam_category": self.scam_category,
            "scam_label": self.scam_label,
            "category_scores": {k: round(v, 3) for k, v in sorted(
                self.category_scores.items(), key=lambda kv: -kv[1])[:5]},
            "classifier_used": self.classifier_used,
            "classifier_category": self.classifier_category,
            "classifier_confidence": round(self.classifier_confidence, 3),
        }


def _span(original: str, folded_match: re.Match, folded: str) -> Tuple[str, int, int]:
    """Map a match on the folded text back to a readable fragment.

    Tanglish folding changes offsets, so we widen to the surrounding words of
    the folded text and then try to locate a matching fragment in the original.
    """
    frag = folded_match.group(0)
    idx = original.lower().find(frag.lower())
    if idx >= 0:
        return original[idx:idx + len(frag)], idx, idx + len(frag)
    # Fall back: show the folded window, clearly derived from normalization.
    s = max(0, folded_match.start() - 24)
    e = min(len(folded), folded_match.end() + 24)
    return folded[s:e].strip(), -1, -1


def classify(original: str, folded: str,
             classifier_result: Optional[Tuple[str, float]] = None) -> IntentResult:
    """Rule backbone + optional classifier refinement."""
    res = IntentResult()
    hay = folded or original

    for family, patterns in INTENT_PATTERNS.items():
        for pat in patterns:
            for m in re.finditer(pat, hay, re.IGNORECASE):
                frag, s, e = _span(original, m, hay)
                sig = Signal(name=pat.strip("\\b"), family=family,
                             evidence_span=frag, start=s, end=e)
                res.intents.setdefault(family, []).append(sig)
                res.signals.append(sig)
                break   # one evidence span per pattern keeps the UI readable

    for pat in BENIGN_PATTERNS:
        m = re.search(pat, hay, re.IGNORECASE)
        if m:
            frag, s, e = _span(original, m, hay)
            res.benign_signals.append(Signal(name=pat.strip("\\b"), family="benign",
                                             evidence_span=frag, start=s, end=e))

    # Score each scam class: pattern hits + intent-family corroboration.
    scores: Dict[str, float] = {}
    for key, meta in SCAM_CLASSES.items():
        if key == "legitimate":
            continue
        hits = 0
        for pat in meta["patterns"]:
            if re.search(pat, hay, re.IGNORECASE):
                hits += 1
        if not hits:
            continue
        corroboration = sum(1 for fam in meta["intents"] if fam in res.intents)
        scores[key] = hits * 1.0 + corroboration * 0.75
    res.category_scores = scores

    if scores:
        best = max(scores, key=lambda k: scores[k])
        res.scam_category = best
        res.scam_label = str(SCAM_CLASSES[best]["label"])

    if classifier_result:
        cat, conf = classifier_result
        res.classifier_used = True
        res.classifier_category = cat
        res.classifier_confidence = conf
        # The model may only *promote* a category the rules did not see, and
        # only when it is confident. It can never silently clear a rule hit.
        if conf >= 0.50 and cat != "legitimate":
            res.category_scores[cat] = res.category_scores.get(cat, 0.0) + conf * 1.5
            best = max(res.category_scores, key=lambda k: res.category_scores[k])
            res.scam_category = best
            res.scam_label = str(SCAM_CLASSES[best]["label"])

    return res
