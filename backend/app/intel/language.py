"""Language identification + normalization for Tamil / English / Tanglish.

Contract (section 11):
  - Detect Tamil script, Latin English, Tanglish / code-switching.
  - Unicode NFC, safe casing, repeated-character normalization, retain URLs/numbers.
  - Normalize common Tanglish while retaining original evidence.

Language is a ROUTING signal, never a verdict.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List

TAMIL_BLOCK = re.compile(r"[\u0B80-\u0BFF]")
LATIN_BLOCK = re.compile(r"[A-Za-z]")

# Placeholders protect URLs / numbers / emails / UPI from normalization damage.
_PROTECT_PATTERNS = [
    re.compile(r"https?://\S+", re.I),
    re.compile(r"\bwww\.\S+", re.I),
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"),
    re.compile(r"\b[\w.\-]{2,}@(?:upi|ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|apl|ibl|axl|fbl)\b", re.I),
    re.compile(r"\+?\d[\d\-\s]{6,}\d"),
]

# Tanglish lexicon: transliterated Tamil -> canonical English concept token.
# Kept small, auditable and extendable; every hit is recorded as evidence.
TANGLISH_LEXICON: Dict[str, str] = {
    # money / banking
    "panam": "money", "pannam": "money", "kaasu": "money", "roobai": "rupees",
    "vangi": "bank", "kanakku": "account", "account-u": "account",
    "pancard": "pan card", "aadhar": "aadhaar", "aadhaarkaarth": "aadhaar",
    "paisa": "money", "transfer pannunga": "transfer money",
    # urgency / threat
    "udane": "immediately", "seekiram": "immediately", "ippo": "now",
    "innaiku": "today", "naalaikku": "tomorrow", "ipovey": "right now",
    "block aagidum": "will be blocked", "block aagum": "will be blocked",
    "mudangum": "will be frozen", "mudakkapadum": "will be frozen",
    "nirutthapadum": "will be suspended", "ratthu": "cancelled",
    "kaalavadhi": "expired", "mudiyum": "will expire",
    "avasaram": "urgent", "avasara": "urgent", "eccharikkai": "warning",
    # action requests
    "click pannunga": "click", "click pannu": "click", "click seiyavum": "click",
    "அழுத்துங்கள்": "click", "share pannunga": "share", "anuppunga": "send",
    "anuppavum": "send", "sollunga": "tell", "update pannunga": "update",
    "seiyavum": "do", "pannunga": "do", "potta": "put",
    "varum": "will come", "kuduthidunga": "give", "kodunga": "give",
    "thaa": "give", "kekkuranga": "asking",
    # credentials
    "kadavuchol": "password", "ragasiya": "secret", "ragasiyam": "secret",
    "otp number": "otp", "pin number": "pin",
    # lures
    "parisu": "prize", "ilavasam": "free", "ilavasa": "free",
    "bahumathi": "reward", "vetri": "won", "jeichinga": "won", "jeichittinga": "won",
    "velai": "job", "velaivaaippu": "job opportunity", "sambalam": "salary",
    "laabam": "profit", "mudhaleedu": "investment",
    # authority
    "kaavalthurai": "police", "arasu": "government", "adhikari": "officer",
    "vanganga": "bank", "mintsaram": "electricity", "minsaram": "electricity",
    "karandu": "electricity", "pesaren": "speaking", "pesuren": "speaking",
    "kattunga": "pay", "kattanum": "must pay", "kattavum": "pay",
    "hold aagirukku": "is on hold", "stuck aagirukku": "is stuck",
    "return pannidum": "will be returned", "sambathikkalam": "can earn",
    "jeichinga": "won", "guarantee": "guaranteed", "velaivaippu": "job opportunity",
    "deposit pannunga": "deposit", "register pannunga": "register",
    "install pannunga": "install", "approve pannunga": "approve",
    "verify pannunga": "verify", "confirm pannunga": "confirm",
    "download pannunga": "download", "open pannunga": "open",
    "aagiduchu": "has happened", "aaiduchu": "has happened", "mudinjiduchu": "has expired",
    "irukku": "is there", "illana": "otherwise", "illaina": "otherwise",
    # misc
    "vaadikkaiyalar": "customer", "vaadikaiyaalare": "customer",
    "anbudan": "dear", "iniya": "dear", "nandri": "thanks",
    "ungal": "your", "unga": "your", "neengal": "you", "neenga": "you",
}

# Tamil-script trigger words mapped to concepts (used for intent on pure Tamil).
TAMIL_LEXICON: Dict[str, str] = {
    "உடனே": "immediately", "அவசரம்": "urgent", "இன்று": "today",
    "முடக்கப்படும்": "will be frozen", "நிறுத்தப்படும்": "will be suspended",
    "கணக்கு": "account", "வங்கி": "bank", "பணம்": "money", "ரூபாய்": "rupees",
    "கடவுச்சொல்": "password", "ரகசிய": "secret", "பரிசு": "prize",
    "இலவச": "free", "வேலை": "job", "முதலீடு": "investment",
    "காவல்துறை": "police", "அரசு": "government", "மின்சாரம்": "electricity",
    "சரிபார்": "verify", "புதுப்பி": "update", "அழுத்த": "click",
    "கிளிக்": "click", "இணைப்பு": "link", "காலாவதி": "expired",
    "வாடிக்கையாளர்": "customer", "ஆதார்": "aadhaar", "பான்": "pan card",
    # --- extended Tamil scam vocabulary -------------------------------------
    "உறுதியான": "guaranteed", "உறுதி": "guaranteed", "லாபம்": "profit",
    "செய்து": "do", "பெறுங்கள்": "receive", "மாதம்": "month", "தினமும்": "daily",
    "விவரங்கள்": "details", "விவரங்களுக்கு": "for details", "தொடர்பு": "contact",
    "அழைக்கவும்": "call", "அனுப்பவும்": "send", "அனுப்பு": "send",
    "செலுத்தவும்": "pay", "செலுத்த": "pay", "கட்டணம்": "fee payment",
    "பணம்": "money", "திரும்பப்": "refund", "திரும்ப": "refund",
    "பரிவர்த்தனை": "transaction", "தோல்வியுற்ற": "failed",
    "கோரிக்கை": "request", "கோரிக்கையை": "request", "ஏற்கவும்": "approve",
    "அறிவிப்பு": "notice", "அரசு அறிவிப்பு": "government notice",
    "நீதிமன்ற": "court", "நோட்டீஸ்": "notice", "அதிகாரி": "officer",
    "தவறாக": "wrongly", "பயன்படுத்தப்பட்டுள்ளது": "has been misused",
    "சுங்கம்": "customs", "சுங்கத்தில்": "customs", "பொருள்": "parcel",
    "நிறுத்தப்பட்டுள்ளது": "is held", "நிறுத்தப்படும்": "will be suspended",
    "துண்டிக்கப்படும்": "will be disconnected", "இணைப்பு": "connection link",
    "சேவை": "service", "சேவைக்காக": "for service", "செயலி": "app",
    "செயலியை": "app", "நிறுவி": "install", "நிறுவ": "install",
    "அனுமதி": "permission", "வழங்கவும்": "grant", "பதிவு": "register",
    "பதிவு செய்யவும்": "register", "சரிபார்க்கவும்": "verify",
    "சரிபார்க்கப்படவில்லை": "not verified", "புதுப்பிக்கவும்": "update",
    "இணைக்கவும்": "link", "அழுத்துங்கள்": "click", "அழுத்தவும்": "click",
    "பூட்டப்பட்டுள்ளது": "is locked", "மீண்டும் திறக்க": "to unlock",
    "சந்தேகத்திற்குரிய": "suspicious", "நுழைவு": "login",
    "பாதுகாப்பு": "security", "எச்சரிக்கை": "warning",
    "வென்றுள்ளீர்கள்": "you have won", "வென்றீர்கள்": "you have won",
    "வாழ்த்துக்கள்": "congratulations", "பரிசு": "prize", "அதிர்ஷ்ட": "lucky",
    "குலுக்கல்": "lucky draw", "குலுக்கலில்": "lucky draw",
    "முதலீடு": "investment", "சம்பாதிக்கலாம்": "can earn", "வேலை": "job",
    "வீட்டிலிருந்தே": "work from home", "சம்பளம்": "salary",
    "வழக்கு": "case", "பதிவாகியுள்ளது": "has been registered",
    "கைது": "arrest", "அபராதம்": "penalty", "காலாவதி": "expired",
    "முடக்கப்படும்": "will be frozen", "முடிந்துவிட்டது": "has expired",
    "இரவு": "tonight", "இன்று": "today", "மணி": "hours", "நேரம்": "time",
    "மட்டுமே": "only", "இல்லையெனில்": "otherwise", "உடனடியாக": "immediately",
    "மின்சார": "electricity", "மின்": "electricity", "நன்றி": "thanks",
    "கணக்கில்": "in account", "கணக்கு": "account", "வங்கி": "bank",
}

# Common English function words — used to measure the English share of a
# Latin-script message so we can separate "English" from "Tanglish".
_ENGLISH_STOPWORDS = {
    "the", "your", "you", "is", "are", "to", "and", "of", "for", "will", "be",
    "has", "have", "this", "that", "please", "click", "link", "account", "bank",
    "card", "verify", "update", "now", "today", "has", "been", "within", "hours",
    "dear", "customer", "sir", "madam", "number", "details", "payment", "amount",
    "received", "immediately", "urgent", "blocked", "expired", "complete", "a",
    "on", "in", "with", "from", "by", "we", "our", "us", "it", "if", "not", "do",
}


@dataclass
class LanguageResult:
    language: str                      # "ta" | "en" | "ta-en" (Tanglish) | "und"
    label: str                         # Human label
    scripts: List[str] = field(default_factory=list)
    is_code_switched: bool = False
    tamil_char_ratio: float = 0.0
    latin_char_ratio: float = 0.0
    tanglish_tokens: List[Dict[str, str]] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "label": self.label,
            "scripts": self.scripts,
            "is_code_switched": self.is_code_switched,
            "tamil_char_ratio": round(self.tamil_char_ratio, 3),
            "latin_char_ratio": round(self.latin_char_ratio, 3),
            "tanglish_tokens": self.tanglish_tokens,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class NormalizedText:
    original: str
    normalized: str
    folded: str                        # lowercase, analysis-friendly
    replacements: List[Dict[str, str]] = field(default_factory=list)


def _protect(text: str):
    tokens: List[str] = []

    def _sub(m: re.Match) -> str:
        tokens.append(m.group(0))
        return f"\x00{len(tokens) - 1}\x00"

    out = text
    for pat in _PROTECT_PATTERNS:
        out = pat.sub(_sub, out)
    return out, tokens


def _restore(text: str, tokens: List[str]) -> str:
    def _sub(m: re.Match) -> str:
        return tokens[int(m.group(1))]

    return re.sub(r"\x00(\d+)\x00", _sub, text)


def normalize(text: str) -> NormalizedText:
    """Unicode NFC + repeated-char collapse + Tanglish folding.

    URLs, emails, UPI handles and phone numbers are protected from any edit so
    downstream evidence stays byte-accurate.
    """
    original = text
    nfc = unicodedata.normalize("NFC", text)
    protected, tokens = _protect(nfc)

    # Collapse letter elongation only: "urgenttttt" -> "urgentt".
    # Digits are never collapsed, or amounts like 75,000 would be corrupted.
    protected = re.sub(r"([^\W\d_])\1{2,}", r"\1\1", protected)
    # Collapse whitespace but keep newlines meaningful.
    protected = re.sub(r"[ \t\u00a0]+", " ", protected)

    normalized = _restore(protected, tokens).strip()

    # Build the folded analysis string with Tanglish/Tamil concept expansion.
    folded_protected, tokens2 = _protect(normalized)
    folded = folded_protected.lower()
    replacements: List[Dict[str, str]] = []

    # Multi-word entries first so "click pannunga" wins over "pannunga".
    for src in sorted(TANGLISH_LEXICON, key=len, reverse=True):
        if " " in src:
            pat = re.compile(re.escape(src), re.I)
        else:
            pat = re.compile(rf"\b{re.escape(src)}\b", re.I)
        if pat.search(folded):
            target = TANGLISH_LEXICON[src]
            folded = pat.sub(f" {target} ", folded)
            replacements.append({"from": src, "to": target, "kind": "tanglish"})

    for src, target in TAMIL_LEXICON.items():
        if src in folded:
            folded = folded.replace(src, f" {src} {target} ")
            replacements.append({"from": src, "to": target, "kind": "tamil"})

    folded = re.sub(r"\s{2,}", " ", _restore(folded, tokens2)).strip()
    return NormalizedText(original=original, normalized=normalized,
                          folded=folded, replacements=replacements)


def detect(text: str) -> LanguageResult:
    """Detect script mix and decide ta / en / ta-en (Tanglish)."""
    if not text or not text.strip():
        return LanguageResult(language="und", label="Undetermined", confidence=0.0)

    letters = [c for c in text if c.isalpha()]
    total = len(letters) or 1
    tamil_n = len(TAMIL_BLOCK.findall(text))
    latin_n = len(LATIN_BLOCK.findall(text))
    tamil_ratio = tamil_n / total
    latin_ratio = latin_n / total

    scripts: List[str] = []
    if tamil_n:
        scripts.append("Tamil")
    if latin_n:
        scripts.append("Latin")

    # Tanglish detection on the Latin portion.
    words = re.findall(r"[a-z']+", text.lower())
    hits: List[Dict[str, str]] = []
    lowered = " " + text.lower() + " "
    for src in sorted(TANGLISH_LEXICON, key=len, reverse=True):
        pat = re.escape(src) if " " in src else rf"\b{re.escape(src)}\b"
        if re.search(pat, lowered):
            hits.append({"token": src, "maps_to": TANGLISH_LEXICON[src]})
    english_words = sum(1 for w in words if w in _ENGLISH_STOPWORDS)
    english_share = english_words / len(words) if words else 0.0

    if tamil_ratio >= 0.6 and latin_ratio < 0.15:
        lang, label, conf = "ta", "Tamil", 0.95
        code_switch = bool(hits) or latin_ratio > 0.05
    elif tamil_n and latin_n:
        lang, label, conf = "ta-en", "Tanglish (Tamil-English code-switch)", 0.9
        code_switch = True
    elif hits and (english_share < 0.55 or len(hits) >= 2):
        lang, label, conf = "ta-en", "Tanglish (romanized Tamil)", min(0.9, 0.55 + 0.1 * len(hits))
        code_switch = True
    elif latin_n:
        lang, label, conf = "en", "English", 0.8 if english_share > 0.2 else 0.6
        code_switch = False
    else:
        lang, label, conf = "und", "Undetermined", 0.3
        code_switch = False

    return LanguageResult(
        language=lang, label=label, scripts=scripts,
        is_code_switched=code_switch,
        tamil_char_ratio=tamil_ratio, latin_char_ratio=latin_ratio,
        tanglish_tokens=hits[:20], confidence=conf,
    )
