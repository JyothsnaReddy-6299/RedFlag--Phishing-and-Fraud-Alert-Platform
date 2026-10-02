"""Entity extraction & resolution (contract section 14).

Extract phone numbers, URLs/domains, email IDs, UPI/VPA patterns, social
handles, brands, locations, dates, amounts and transaction IDs.

Rules enforced here:
  * Normalize for matching, but ALWAYS retain the raw value for evidence.
  * Never infer ownership of an entity.
  * Every entity carries the exact character span it came from.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------
RE_URL = re.compile(
    r"\b(?:https?://|www\.)[^\s<>\"'()]+|"
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|in|co\.in|gov\.in|ac\.in|io|xyz|top|club|site|online|live|fun|shop|work|cam|zip|info|biz|link|app|page|icu|rest|cfd|sbs)"
    r"(?:/[^\s<>\"'()]*)?",
    re.IGNORECASE,
)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# UPI handles: name@psp where psp is a known VPA suffix (no dot after @).
UPI_PSPS = (
    "upi|ybl|ibl|axl|apl|paytm|okaxis|oksbi|okhdfcbank|okicici|okbizaxis|"
    "airtel|freecharge|jio|hdfcbank|icici|sbi|axisbank|yesbank|kotak|fbl|"
    "barodampay|cnrb|idfcbank|indus|pingpay|postbank|rmhdfc|timecosmos|waaxis|"
    "wahdfcbank|waicici|wasbi|abfspay|slc|dbs|federal|myicici|aubank"
)
RE_UPI = re.compile(rf"\b([A-Za-z0-9][A-Za-z0-9._-]{{1,48}})@({UPI_PSPS})\b", re.IGNORECASE)
# Indian mobile numbers, tolerating the separators people actually type:
# 9123456780 / +91 98765 43210 / +91-98765-43210 / 098765 43210
RE_PHONE_IN = re.compile(
    r"(?<![\d])(?:\+?91[\-\s.]?|0)?"
    r"([6-9]\d{4})[\-\s.]?(\d{5})"
    r"(?![\d])")
RE_SHORTCODE = re.compile(r"\b(?:[A-Z]{2}-)?([A-Z]{4,8})\b")  # SMS sender IDs like VM-SBIINB
RE_HANDLE = re.compile(r"(?<![\w@./])@([A-Za-z0-9_]{3,30})\b")
RE_AMOUNT = re.compile(
    r"(?:(?:rs|inr|₹)\.?\s?)([0-9][0-9,]*(?:\.\d{1,2})?)(?:\s?(lakh|lakhs|crore|crores|k))?",
    re.IGNORECASE,
)
RE_TXN = re.compile(
    r"\b(?:txn|transaction|ref|reference|utr|order|ticket|complaint)\s*(?:id|no|number|#)?\s*[:\-#]?\s*([A-Z0-9]{6,24})\b",
    re.IGNORECASE,
)
RE_DATE = re.compile(
    r"\b(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|"
    r"\d{1,2}\s?(?:st|nd|rd|th)?\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s?\d{0,4})\b",
    re.IGNORECASE,
)
RE_IFSC = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
RE_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# South-Chennai / Tamil Nadu locality lexicon (regional relevance, section 4).
LOCALITIES = [
    "adyar", "velachery", "thoraipakkam", "sholinganallur", "perungudi",
    "pallikaranai", "medavakkam", "madipakkam", "guindy", "saidapet",
    "besant nagar", "thiruvanmiyur", "kotturpuram", "alwarpet", "mylapore",
    "tambaram", "chromepet", "pallavaram", "navalur", "siruseri", "omr",
    "ecr", "porur", "taramani", "neelankarai", "injambakkam", "karapakkam",
    "chennai", "tamil nadu", "tamilnadu", "coimbatore", "madurai", "trichy",
]

# Brand lexicon with the official domains that legitimately represent them.
BRANDS: Dict[str, Dict[str, object]] = {
    "sbi": {"display": "State Bank of India", "domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbiyono.sbi"],
            "aliases": ["state bank", "yono", "sbi bank", "onlinesbi"]},
    "hdfc": {"display": "HDFC Bank", "domains": ["hdfcbank.com", "hdfc.com"], "aliases": ["hdfc bank"]},
    "icici": {"display": "ICICI Bank", "domains": ["icicibank.com"], "aliases": ["icici bank", "imobile"]},
    "axis": {"display": "Axis Bank", "domains": ["axisbank.com"], "aliases": ["axis bank"]},
    "kotak": {"display": "Kotak Mahindra Bank", "domains": ["kotak.com"], "aliases": ["kotak bank"]},
    "indianbank": {"display": "Indian Bank", "domains": ["indianbank.in", "indianbank.net.in"], "aliases": ["indian bank"]},
    "iob": {"display": "Indian Overseas Bank", "domains": ["iob.in"], "aliases": ["indian overseas bank"]},
    "canara": {"display": "Canara Bank", "domains": ["canarabank.com"], "aliases": ["canara bank"]},
    "rbi": {"display": "Reserve Bank of India", "domains": ["rbi.org.in"], "aliases": ["reserve bank"]},
    "paytm": {"display": "Paytm", "domains": ["paytm.com", "paytmbank.com"], "aliases": []},
    "phonepe": {"display": "PhonePe", "domains": ["phonepe.com"], "aliases": ["phone pe"]},
    "gpay": {"display": "Google Pay", "domains": ["pay.google.com", "google.com"], "aliases": ["google pay", "g pay"]},
    "upi": {"display": "UPI / NPCI", "domains": ["npci.org.in"], "aliases": ["npci", "bhim"]},
    "amazon": {"display": "Amazon", "domains": ["amazon.in", "amazon.com"], "aliases": []},
    "flipkart": {"display": "Flipkart", "domains": ["flipkart.com"], "aliases": []},
    "tneb": {"display": "TNEB / TANGEDCO", "domains": ["tnebnet.org", "tangedco.gov.in"], "aliases": ["tangedco", "eb bill", "electricity board"]},
    "incometax": {"display": "Income Tax Department", "domains": ["incometax.gov.in"], "aliases": ["income tax", "it department", "itr"]},
    "epfo": {"display": "EPFO", "domains": ["epfindia.gov.in"], "aliases": ["pf office", "provident fund"]},
    "aadhaar": {"display": "UIDAI / Aadhaar", "domains": ["uidai.gov.in"], "aliases": ["uidai"]},
    "irctc": {"display": "IRCTC", "domains": ["irctc.co.in"], "aliases": []},
    "bluedart": {"display": "Blue Dart", "domains": ["bluedart.com"], "aliases": ["blue dart"]},
    "indiapost": {"display": "India Post", "domains": ["indiapost.gov.in"], "aliases": ["india post", "speed post"]},
    "dhl": {"display": "DHL", "domains": ["dhl.com"], "aliases": []},
    "fedex": {"display": "FedEx", "domains": ["fedex.com"], "aliases": []},
    "whatsapp": {"display": "WhatsApp", "domains": ["whatsapp.com", "wa.me"], "aliases": []},
    "netflix": {"display": "Netflix", "domains": ["netflix.com"], "aliases": []},
    "jio": {"display": "Reliance Jio", "domains": ["jio.com"], "aliases": []},
    "airtel": {"display": "Airtel", "domains": ["airtel.in"], "aliases": []},
}

_ENTITY_TYPES = (
    "phone", "url", "domain", "email", "upi", "handle", "brand",
    "locality", "date", "amount", "txn_id", "ifsc", "sender_id",
)


@dataclass
class Entity:
    type: str
    raw_value: str          # exactly as it appeared — evidence
    display_value: str      # safe, human-readable
    canonical_value: str    # normalized for matching
    canonical_hash: str     # privacy-aware join key
    start: int
    end: int
    confidence: float = 0.9
    attributes: Optional[Dict[str, object]] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence_span"] = self.raw_value
        return d


def _h(entity_type: str, canonical: str) -> str:
    return hashlib.sha256(f"{entity_type}:{canonical}".encode()).hexdigest()[:32]


def _mk(etype: str, raw: str, canonical: str, start: int, end: int,
        display: Optional[str] = None, confidence: float = 0.9,
        attributes: Optional[dict] = None) -> Entity:
    canonical = canonical.strip().lower()
    return Entity(
        type=etype, raw_value=raw, display_value=display or raw,
        canonical_value=canonical, canonical_hash=_h(etype, canonical),
        start=start, end=end, confidence=confidence, attributes=attributes or {},
    )


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a network call."""
    host = host.lower().strip().strip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = ".".join(parts[-2:])
    multi = {"co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in", "co.uk",
             "org.uk", "com.au", "co.jp", "com.br", "com.sg"}
    if two in multi and len(parts) >= 3:
        return ".".join(parts[-3:])
    return two


def host_of(url: str) -> str:
    u = url.strip()
    u = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", u, flags=re.I)
    u = u.split("/")[0].split("?")[0].split("#")[0]
    if "@" in u:                      # strip misleading userinfo
        u = u.split("@")[-1]
    u = u.split(":")[0]
    return u.lower().strip(".")


def brand_mentions(text: str) -> List[Entity]:
    out: List[Entity] = []
    low = text.lower()
    for key, meta in BRANDS.items():
        needles = [key] + list(meta.get("aliases", []))  # type: ignore[arg-type]
        for needle in needles:
            for m in re.finditer(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", low):
                out.append(_mk(
                    "brand", text[m.start():m.end()], key, m.start(), m.end(),
                    display=str(meta["display"]), confidence=0.75,
                    attributes={"official_domains": meta["domains"]},
                ))
                break
    # de-duplicate by canonical brand, keep earliest mention
    seen: Dict[str, Entity] = {}
    for e in out:
        if e.canonical_value not in seen or e.start < seen[e.canonical_value].start:
            seen[e.canonical_value] = e
    return list(seen.values())


def extract(text: str, sender_id: Optional[str] = None) -> List[Entity]:
    """Run every extractor over `text`. Order of regexes matters: UPI and
    email overlap, so email is filtered against UPI matches."""
    if not text:
        return []
    ents: List[Entity] = []

    upi_spans: List[tuple] = []
    for m in RE_UPI.finditer(text):
        upi_spans.append((m.start(), m.end()))
        ents.append(_mk("upi", m.group(0), m.group(0), m.start(), m.end(),
                        confidence=0.9, attributes={"psp": m.group(2).lower()}))

    for m in RE_EMAIL.finditer(text):
        if any(m.start() >= s and m.end() <= e for s, e in upi_spans):
            continue
        ents.append(_mk("email", m.group(0), m.group(0), m.start(), m.end(), confidence=0.9))

    url_spans: List[tuple] = []
    for m in RE_URL.finditer(text):
        raw = m.group(0).rstrip(".,;:!?)'\"»")
        end = m.start() + len(raw)
        if any(raw.lower().startswith(p) for p in ("mailto:",)):
            continue
        url_spans.append((m.start(), end))
        host = host_of(raw)
        if not host or "." not in host:
            continue
        normalized = raw if re.match(r"^https?://", raw, re.I) else f"http://{raw}"
        ents.append(_mk("url", raw, normalized.lower(), m.start(), end, confidence=0.92))
        reg = registrable_domain(host)
        ents.append(_mk("domain", host, reg, m.start(), end,
                        display=host, confidence=0.9,
                        attributes={"full_host": host, "registrable_domain": reg}))

    for m in RE_PHONE_IN.finditer(text):
        if any(m.start() >= s and m.end() <= e for s, e in url_spans):
            continue
        digits = m.group(1) + m.group(2)
        ents.append(_mk("phone", m.group(0), "+91" + digits, m.start(), m.end(),
                        display="+91 " + digits, confidence=0.88,
                        attributes={"country": "IN"}))

    for m in RE_HANDLE.finditer(text):
        ents.append(_mk("handle", m.group(0), m.group(1), m.start(), m.end(), confidence=0.6))

    for m in RE_AMOUNT.finditer(text):
        num = m.group(1).replace(",", "")
        mult = {"lakh": 1e5, "lakhs": 1e5, "crore": 1e7, "crores": 1e7, "k": 1e3}
        factor = mult.get((m.group(2) or "").lower(), 1)
        try:
            value = float(num) * factor
        except ValueError:
            continue
        ents.append(_mk("amount", m.group(0), f"inr:{value:.0f}", m.start(), m.end(),
                        display=f"₹{value:,.0f}", confidence=0.8,
                        attributes={"currency": "INR", "value": value}))

    for m in RE_TXN.finditer(text):
        ents.append(_mk("txn_id", m.group(0), m.group(1), m.start(), m.end(),
                        display=m.group(1), confidence=0.7))

    for m in RE_IFSC.finditer(text):
        ents.append(_mk("ifsc", m.group(0), m.group(1), m.start(), m.end(), confidence=0.85))

    for m in RE_DATE.finditer(text):
        ents.append(_mk("date", m.group(0), m.group(0), m.start(), m.end(), confidence=0.6))

    low = text.lower()
    for loc in LOCALITIES:
        idx = low.find(loc)
        if idx >= 0:
            ents.append(_mk("locality", text[idx:idx + len(loc)], loc, idx, idx + len(loc),
                            confidence=0.65))

    ents.extend(brand_mentions(text))

    if sender_id:
        sid = sender_id.strip()
        match = RE_PHONE_IN.search(sid)
        if match:
            canon = "+91" + match.group(1) + match.group(2)
            ents.append(_mk("phone", sid, canon, -1, -1, display=sid,
                            confidence=0.95, attributes={"role": "sender"}))
        else:
            ents.append(_mk("sender_id", sid, sid.upper(), -1, -1,
                            confidence=0.9, attributes={"role": "sender"}))

    # Deduplicate on (type, canonical) keeping highest confidence.
    best: Dict[tuple, Entity] = {}
    for e in ents:
        k = (e.type, e.canonical_value)
        if k not in best or e.confidence > best[k].confidence:
            best[k] = e
    return sorted(best.values(), key=lambda e: (_ENTITY_TYPES.index(e.type) if e.type in _ENTITY_TYPES else 99, e.start))


def brand_domain_conflict(entities: List[Entity]) -> List[Dict[str, str]]:
    """Context anomaly: message names a brand but links to a domain that is
    not one of that brand's official domains. Evidence only — not proof."""
    brands = [e for e in entities if e.type == "brand"]
    domains = [e for e in entities if e.type == "domain"]
    conflicts: List[Dict[str, str]] = []
    for b in brands:
        official = [d.lower() for d in (b.attributes or {}).get("official_domains", [])]  # type: ignore[union-attr]
        for d in domains:
            host = str((d.attributes or {}).get("full_host", d.canonical_value))
            if any(host == o or host.endswith("." + o) for o in official):
                break
        else:
            if domains:
                conflicts.append({
                    "brand": b.display_value,
                    "brand_key": b.canonical_value,
                    "linked_domain": domains[0].display_value,
                    "official_domains": ", ".join(official),
                    "evidence_span": b.raw_value,
                })
    return conflicts
