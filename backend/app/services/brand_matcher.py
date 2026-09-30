"""
Brand Matcher & Impersonation Engine
------------------------------------
Advanced typosquatting and deceptive brand mimicry detection operating on the
registered domain (stem/SLD), featuring:
  1. Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions)
  2. Normalized similarity score ([0.0, 1.0])
  3. Character substitutions (ASCII visual/phonetic lookalikes: rn <-> m, vv <-> w, cl <-> d)
  4. Missing/extra characters (omissions, insertions, duplications)
  5. Digit substitutions (leetspeak: 0 -> o, 1 -> l/i, 3 -> e, 4 -> a, 5 -> s, 8 -> b)
  6. Hyphen manipulation (hyphen insertion/stripping around brands)
  7. Brand-token similarity & deceptive token extraction (e.g. security, login, kyc)
  8. TLD mismatch evaluation against official brand TLDs
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------
# Official Brands and their Known Authentic Domains
# ---------------------------------------------------------
BRAND_REGISTRY: Dict[str, Dict[str, any]] = {
    "amazon": {
        "display_name": "Amazon",
        "official_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp"],
        "aliases": ["amzn"],
    },
    "paypal": {
        "display_name": "PayPal",
        "official_domains": ["paypal.com", "paypal.me"],
        "aliases": ["pp"],
    },
    "sbi": {
        "display_name": "State Bank of India (SBI)",
        "official_domains": [
            "onlinesbi.sbi", "sbi.co.in", "sbi.sbi", "bank.sbi",
            "statebankofindia.com", "sbi.bank.in", "onlinesbi.sbi.bank.in",
            "retail.sbi.bank.in", "corporate.sbi.bank.in", "sbi-card.com", "sbicard.com"
        ],
        "aliases": ["onlinesbi", "sbicard", "statebankofindia"],
    },
    "hdfc": {
        "display_name": "HDFC Bank",
        "official_domains": ["hdfcbank.com", "hdfc.com", "hdfc.bank.in", "hdfcbank.bank.in", "hdfcbank.net", "hdfcsec.com"],
        "aliases": ["hdfcbank", "hdfcsec"],
    },
    "icici": {
        "display_name": "ICICI Bank",
        "official_domains": ["icicibank.com", "icici.com", "icici.bank.in", "icicidirect.com"],
        "aliases": ["icicibank", "icicidirect"],
    },
    "axis": {
        "display_name": "Axis Bank",
        "official_domains": ["axisbank.com", "axis.bank.in"],
        "aliases": ["axisbank"],
    },
    "pnb": {
        "display_name": "Punjab National Bank (PNB)",
        "official_domains": ["pnbindia.in", "pnb.bank.in"],
        "aliases": ["pnbindia"],
    },
    "kotak": {
        "display_name": "Kotak Mahindra Bank",
        "official_domains": ["kotak.com", "kotak.bank.in", "kotakcherry.com"],
        "aliases": ["kotakbank", "kotakmahindra"],
    },
    "bankofbaroda": {
        "display_name": "Bank of Baroda",
        "official_domains": ["bankofbaroda.in", "bankofbaroda.com", "bob.bank.in"],
        "aliases": ["bob", "bobcards"],
    },
    "canara": {
        "display_name": "Canara Bank",
        "official_domains": ["canarabank.com", "canara.bank.in"],
        "aliases": ["canarabank"],
    },
    "paytm": {
        "display_name": "Paytm",
        "official_domains": ["paytm.com", "paytmbank.com", "paytm.bank.in"],
        "aliases": ["paytmbank"],
    },
    "phonepe": {
        "display_name": "PhonePe",
        "official_domains": ["phonepe.com"],
        "aliases": [],
    },
    "google": {
        "display_name": "Google",
        "official_domains": ["google.com", "google.co.in", "accounts.google.com", "myaccount.google.com", "gmail.com"],
        "aliases": ["gmail", "gpay"],
    },
    "apple": {
        "display_name": "Apple",
        "official_domains": ["apple.com", "icloud.com", "appleid.apple.com"],
        "aliases": ["icloud"],
    },
    "microsoft": {
        "display_name": "Microsoft",
        "official_domains": ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com", "outlook.com"],
        "aliases": ["office", "outlook", "msn", "onedrive"],
    },
    "netflix": {
        "display_name": "Netflix",
        "official_domains": ["netflix.com"],
        "aliases": [],
    },
    "facebook": {
        "display_name": "Facebook / Meta",
        "official_domains": ["facebook.com", "fb.com", "meta.com"],
        "aliases": ["meta", "fb"],
    },
    "instagram": {
        "display_name": "Instagram",
        "official_domains": ["instagram.com"],
        "aliases": ["insta", "ig"],
    },
    "whatsapp": {
        "display_name": "WhatsApp",
        "official_domains": ["whatsapp.com", "wa.me"],
        "aliases": [],
    },
    "telegram": {
        "display_name": "Telegram",
        "official_domains": ["telegram.org", "t.me"],
        "aliases": [],
    },
    "flipkart": {
        "display_name": "Flipkart",
        "official_domains": ["flipkart.com"],
        "aliases": [],
    },
    "ebay": {
        "display_name": "eBay",
        "official_domains": ["ebay.com", "ebay.in"],
        "aliases": [],
    },
    "rbi": {
        "display_name": "Reserve Bank of India (RBI)",
        "official_domains": ["rbi.org.in"],
        "aliases": [],
    },
    "indiapost": {
        "display_name": "India Post",
        "official_domains": ["indiapost.gov.in", "ippbonline.com", "ippb.bank.in"],
        "aliases": ["ippb"],
    }
}

# Deceptive/Phishing keywords commonly appended to brand tokens
DECEPTIVE_TOKENS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "security", "secure", "verification",
    "verify", "portal", "update", "auth", "authenticate", "wallet", "kyc", "pan",
    "aadhaar", "otp", "password", "support", "help", "helpdesk", "account",
    "banking", "ebank", "netbanking", "confirm", "confirmation", "service",
    "customer", "care", "center", "centre", "billing", "payment", "pay",
    "invoice", "alert", "notice", "recover", "recovery", "unlock", "reactivate",
    "restore", "suspend", "suspended", "online", "client", "access", "official",
    "manage", "management", "direct", "app", "mobile", "web"
}

# Digit Leetspeak Mapping (digits -> corresponding letters)
LEET_DIGIT_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",  # also checked for 'i'
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
}

# Multi-character visual lookalikes
CHAR_SUBSTITUTIONS: List[Tuple[str, str, str]] = [
    ("rn", "m", "'rn' -> 'm'"),
    ("vv", "w", "'vv' -> 'w'"),
    ("cl", "d", "'cl' -> 'd'"),
    ("nn", "m", "'nn' -> 'm'"),
]


# ---------------------------------------------------------
# Output Models
# ---------------------------------------------------------
class BrandMatchResult(BaseModel):
    is_official_domain: bool = False
    official_brand_name: Optional[str] = None
    brand_impersonated: Optional[str] = None
    brand_display_name: Optional[str] = None
    brand_similarity_score: float = 0.0
    brand_similarity_rating: str = "NONE"  # "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    matched_token: Optional[str] = None
    target_brand: Optional[str] = None
    candidate_stem: str = ""
    candidate_tld: str = ""
    official_tlds: List[str] = Field(default_factory=list)
    tld_mismatch: bool = False
    deceptive_tokens: List[str] = Field(default_factory=list)
    manipulation_types: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    summary: Optional[str] = None


# ---------------------------------------------------------
# Core Distance & Similarity Algorithms
# ---------------------------------------------------------
def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes true Damerau-Levenshtein distance between two strings,
    supporting:
      1. Insertions
      2. Deletions
      3. Substitutions
      4. Transposition of adjacent characters
    """
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    # Infinite distance bound
    inf = len1 + len2
    da: Dict[str, int] = {}

    d: Dict[Tuple[int, int], int] = {}
    d[(-1, -1)] = inf
    for i in range(-1, len1 + 1):
        d[(i, -1)] = inf
        d[(i, 0)] = i
    for j in range(-1, len2 + 1):
        d[(-1, j)] = inf
        d[(0, j)] = j

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            i1 = da.get(s2[j - 1], 0)
            j1 = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j

            d[(i, j)] = min(
                d[(i - 1, j - 1)] + cost,  # substitution or match
                d[(i, j - 1)] + 1,          # insertion
                d[(i - 1, j)] + 1,          # deletion
                d[(i1 - 1, j1 - 1)] + (i - i1 - 1) + 1 + (j - j1 - 1)  # transposition
            )
        da[s1[i - 1]] = i

    return d[(len1, len2)]


def normalized_similarity(s1: str, s2: str) -> float:
    """
    Returns a normalized similarity score in range [0.0, 1.0].
    1.0 means identical, 0.0 means completely disjoint.
    """
    if s1 == s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = damerau_levenshtein_distance(s1, s2)
    score = 1.0 - (dist / max_len)
    return max(0.0, min(1.0, round(score, 3)))


def similarity_to_rating(score: float) -> str:
    """Classifies a normalized similarity score into a human-readable threat rating."""
    if score >= 0.85:
        return "HIGH"
    elif score >= 0.70:
        return "MEDIUM"
    elif score >= 0.50:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------
# Leetspeak and Character Substitution Unmasking
# ---------------------------------------------------------
def unmask_digits(token: str) -> Tuple[str, List[str]]:
    """
    Replaces digit substitutions with letters (e.g. 'amaz0n' -> 'amazon', 'paypa1' -> 'paypal').
    Returns (unmasked_string, detected_substitutions).
    """
    substitutions: List[str] = []
    chars = list(token)
    for idx, char in enumerate(chars):
        if char in LEET_DIGIT_MAP:
            target_char = LEET_DIGIT_MAP[char]
            chars[idx] = target_char
            substitutions.append(f"digit substitution ('{char}' -> '{target_char}')")
        elif char == "@":
            chars[idx] = "a"
            substitutions.append("symbol substitution ('@' -> 'a')")
        elif char == "$":
            chars[idx] = "s"
            substitutions.append("symbol substitution ('$' -> 's')")
    return "".join(chars), substitutions


def unmask_char_substitutions(token: str) -> Tuple[str, List[str]]:
    """
    Detects and normalizes multi-character visual lookalikes like 'rn' -> 'm', 'vv' -> 'w'.
    """
    substitutions: List[str] = []
    result = token
    for visual, target, desc in CHAR_SUBSTITUTIONS:
        if visual in result:
            result = result.replace(visual, target)
            substitutions.append(f"character substitution ({desc})")
    return result, substitutions


def detect_character_differences(candidate: str, target: str) -> List[str]:
    """
    Detects missing characters (omissions), extra characters (additions),
    or transpositions between candidate and target strings.
    """
    diffs: List[str] = []
    len_c, len_t = len(candidate), len(target)

    # 1. Missing character (omission)
    if len_c == len_t - 1:
        # Check if candidate can be formed by dropping one char from target
        for i in range(len_t):
            if target[:i] + target[i + 1:] == candidate:
                diffs.append(f"missing character (omitted '{target[i]}')")
                break
        if not diffs and damerau_levenshtein_distance(candidate, target) == 1:
            diffs.append("missing character (omission)")

    # 2. Extra character (addition/insertion)
    elif len_c == len_t + 1:
        for i in range(len_c):
            if candidate[:i] + candidate[i + 1:] == target:
                diffs.append(f"extra character (added '{candidate[i]}')")
                break
        if not diffs and damerau_levenshtein_distance(candidate, target) == 1:
            diffs.append("extra character (addition)")

    # 3. Transposition of adjacent characters
    elif len_c == len_t:
        for i in range(len_c - 1):
            if (candidate[:i] + candidate[i + 1] + candidate[i] + candidate[i + 2:]) == target:
                diffs.append(f"adjacent transposition ('{candidate[i:i+2]}' <-> '{target[i:i+2]}')")
                break

    return diffs


# ---------------------------------------------------------
# Tokenization of Registered Domain Stem
# ---------------------------------------------------------
def extract_stem_and_tld(registered_domain: str, tld: Optional[str] = None) -> Tuple[str, str]:
    """
    Extracts the Second-Level Domain (SLD) stem and the TLD from a registered domain.
    E.g. 'amaz0n-security-login.xyz' -> ('amaz0n-security-login', 'xyz')
         'amazon.co.uk' -> ('amazon', 'co.uk')
    """
    rd_clean = registered_domain.lower().strip()
    if tld and rd_clean.endswith("." + tld.lower()):
        stem = rd_clean[:-len("." + tld)]
        return stem, tld.lower()

    parts = rd_clean.split(".")
    if len(parts) >= 2:
        return parts[0], ".".join(parts[1:])
    return rd_clean, ""


def tokenize_stem(stem: str) -> List[str]:
    """
    Tokenizes a domain stem by hyphens, underscores, or periods.
    E.g. 'amaz0n-security-login' -> ['amaz0n', 'security', 'login']
    """
    raw_tokens = re.split(r'[-_.]+', stem)
    return [t for t in raw_tokens if t]


def get_official_tlds(brand_key: str) -> List[str]:
    """Extracts known official TLDs for a given brand."""
    info = BRAND_REGISTRY.get(brand_key)
    if not info:
        return []
    tlds: Set[str] = set()
    for dom in info["official_domains"]:
        parts = dom.split(".", 1)
        if len(parts) > 1:
            tlds.add(parts[1])
    return sorted(list(tlds))


# ---------------------------------------------------------
# Main Brand Impersonation Matching Engine
# ---------------------------------------------------------
class BrandMatcher:
    def __init__(self):
        self.brand_registry = BRAND_REGISTRY
        self.deceptive_tokens = DECEPTIVE_TOKENS

    def is_official_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Checks if a domain exactly matches or is an authorized subdomain of an official brand."""
        d_lower = domain.lower().strip()
        for brand_key, data in self.brand_registry.items():
            for official in data["official_domains"]:
                if d_lower == official or d_lower.endswith("." + official):
                    return True, data["display_name"]
        return False, None

    def analyze_domain(self, registered_domain: str, tld: Optional[str] = None) -> BrandMatchResult:
        """
        Analyzes the registered domain (stem/SLD) for brand impersonation, typosquatting,
        TLD mismatch, and additional deceptive tokens.

        Example:
          Candidate: amaz0n-security-login.xyz
          Recognizes:
            - brand similarity = HIGH (Amazon)
            - TLD mismatch (.xyz vs official [.com, .in, ...])
            - additional deceptive tokens: ['security', 'login']
            - manipulation types: ['digit substitution ('0' -> 'o')', 'hyphen manipulation']
        """
        stem, extracted_tld = extract_stem_and_tld(registered_domain, tld)
        tld_actual = (tld or extracted_tld).lower().lstrip(".")

        # Check if the domain is legitimately official
        is_official, official_name = self.is_official_domain(registered_domain)
        if is_official:
            return BrandMatchResult(
                is_official_domain=True,
                official_brand_name=official_name,
                brand_similarity_score=1.0,
                brand_similarity_rating="NONE",
                candidate_stem=stem,
                candidate_tld=tld_actual,
                summary=f"Legitimate official portal of {official_name}."
            )

        tokens = tokenize_stem(stem)
        has_hyphen = "-" in stem or "_" in stem

        best_brand: Optional[str] = None
        best_brand_display: Optional[str] = None
        best_score: float = 0.0
        best_matched_token: Optional[str] = None
        best_target: Optional[str] = None
        best_manipulations: List[str] = []

        # Find deceptive tokens across all tokens
        found_deceptive_tokens: List[str] = [t for t in tokens if t in self.deceptive_tokens]

        # -------------------------------------------------------------
        # 1. Check each token and full stem against all brands/aliases
        # -------------------------------------------------------------
        # Tokens to test: individual tokens + full stem + pairwise joined tokens
        candidate_strings_to_test: List[Tuple[str, str]] = []  # (string, role)
        for t in tokens:
            candidate_strings_to_test.append((t, "token"))
        if len(tokens) > 1:
            candidate_strings_to_test.append((stem.replace("-", "").replace("_", ""), "joined_stem"))

        for cand_str, role in candidate_strings_to_test:
            cand_clean = cand_str.lower()
            if not cand_clean or len(cand_clean) < 2:
                continue

            # Unmask leetspeak digits and visual substitutions
            unleeted, digit_manipulations = unmask_digits(cand_clean)
            unsubbed, char_manipulations = unmask_char_substitutions(unleeted)

            for brand_key, brand_info in self.brand_registry.items():
                targets = [brand_key] + brand_info.get("aliases", [])

                for target in targets:
                    target_lower = target.lower()

                    # Exact match after unleeting or substitution
                    if cand_clean == target_lower:
                        # Exact brand name used in candidate token
                        score = 1.0
                        manips = []
                        if score > best_score:
                            best_score = score
                            best_brand = brand_key
                            best_brand_display = brand_info["display_name"]
                            best_matched_token = cand_clean
                            best_target = target
                            best_manipulations = manips

                    elif unleeted == target_lower or unsubbed == target_lower:
                        # Pure digit or character substitution impersonation (e.g. 'amaz0n' -> 'amazon', 'arnazon' -> 'amazon')
                        score = 0.95
                        manips = list(digit_manipulations) + list(char_manipulations)
                        if score > best_score:
                            best_score = score
                            best_brand = brand_key
                            best_brand_display = brand_info["display_name"]
                            best_matched_token = cand_clean
                            best_target = target
                            best_manipulations = manips

                    else:
                        # Try Damerau-Levenshtein distance on raw string, unleeted, and unsubbed
                        dist_raw = damerau_levenshtein_distance(cand_clean, target_lower)
                        dist_unleeted = damerau_levenshtein_distance(unsubbed, target_lower)
                        best_dist = min(dist_raw, dist_unleeted)

                        # Check if high similarity
                        sim_raw = normalized_similarity(cand_clean, target_lower)
                        sim_unleeted = normalized_similarity(unsubbed, target_lower)
                        sim = max(sim_raw, sim_unleeted)

                        # We consider it a typosquat if:
                        # 1. distance is 1 (omission, extra char, substitution, transposition)
                        # 2. Or normalized similarity >= 0.75 for words >= 4 chars
                        # 3. Or anagram permutation for short words
                        is_anagram = (
                            len(cand_clean) == len(target_lower)
                            and len(target_lower) in (3, 4)
                            and sorted(cand_clean) == sorted(target_lower)
                        )

                        if best_dist <= 1 or sim >= 0.75 or is_anagram:
                            manips = []
                            if digit_manipulations:
                                manips.extend(digit_manipulations)
                            if char_manipulations:
                                manips.extend(char_manipulations)

                            # Identify specific difference
                            char_diffs = detect_character_differences(cand_clean if best_dist == dist_raw else unsubbed, target_lower)
                            manips.extend(char_diffs)

                            if is_anagram and "adjacent transposition" not in "".join(manips):
                                manips.append(f"anagram permutation of '{target_lower}'")

                            # Calculate weighted score
                            if best_dist == 1:
                                effective_score = 0.90
                            elif is_anagram:
                                effective_score = 0.90
                            else:
                                effective_score = round(sim, 2)

                            if effective_score > best_score:
                                best_score = effective_score
                                best_brand = brand_key
                                best_brand_display = brand_info["display_name"]
                                best_matched_token = cand_clean
                                best_target = target
                                best_manipulations = manips

        # -------------------------------------------------------------
        # 2. Hyphen Manipulation Detection
        # -------------------------------------------------------------
        if best_brand and has_hyphen:
            # If the brand was paired with hyphens and other words
            if len(tokens) > 1:
                hyphen_desc = f"hyphen manipulation (brand combined with deceptive token(s): {', '.join(tokens)})"
                if hyphen_desc not in best_manipulations:
                    best_manipulations.append(hyphen_desc)

        # -------------------------------------------------------------
        # 3. TLD Mismatch Evaluation
        # -------------------------------------------------------------
        tld_mismatch = False
        official_tlds: List[str] = []
        if best_brand:
            official_tlds = get_official_tlds(best_brand)
            if tld_actual and official_tlds:
                # Check if candidate TLD matches any official TLD
                # e.g. candidate TLD 'xyz' vs official ['com', 'in']
                tld_mismatch = not any(
                    tld_actual == off_tld or tld_actual.endswith("." + off_tld) or off_tld.endswith("." + tld_actual)
                    for off_tld in official_tlds
                )

        # -------------------------------------------------------------
        # 4. Synthesize Threat Signals & Summary
        # -------------------------------------------------------------
        signals: List[str] = []
        similarity_rating = similarity_to_rating(best_score) if best_brand else "NONE"
        summary: Optional[str] = None

        if best_brand and similarity_rating in ["HIGH", "MEDIUM"]:
            is_typosquat = (best_score < 1.0 or any("transposition" in m or "substitution" in m or "character" in m or "anagram" in m for m in best_manipulations))

            # Explicit signal 1: Brand Impersonation
            signals.append(
                f"Brand impersonation detected: deceptive domain label/stem '{stem}' mimics authorized brand '{best_brand.upper()}' ({best_brand_display})"
            )
            if is_typosquat:
                signals.append(
                    f"Brand typosquatting detected: '{best_matched_token}' is a deceptive lookalike/transposition of '{best_target}' ({best_brand.upper()})"
                )

            # Explicit signal 2: Brand Similarity
            signals.append(
                f"Brand similarity = {similarity_rating.lower()} ({int(best_score * 100)}% match to {best_brand_display} via token '{best_matched_token}')"
            )

            # Explicit signal 2: TLD Mismatch
            if tld_mismatch:
                off_tlds_str = ", ".join(f".{t}" for t in official_tlds[:4])
                signals.append(
                    f"TLD mismatch: Candidate domain uses '.{tld_actual}' whereas official {best_brand_display} uses {off_tlds_str}"
                )

            # Explicit signal 3: Additional Deceptive Tokens
            if found_deceptive_tokens:
                dec_str = ", ".join(f"'{t}'" for t in found_deceptive_tokens)
                signals.append(
                    f"Additional deceptive token(s) detected: {dec_str} commonly weaponized for social engineering"
                )

            # Manipulations detected
            for manip in best_manipulations:
                if not manip.startswith("hyphen manipulation"):
                    signals.append(f"Deceptive manipulation detected: {manip}")
                else:
                    signals.append(f"Deceptive domain structure: {manip}")

            # Synthesize summary
            summary = (
                f"BRAND IMPERSONATION DETECTED: Target brand {best_brand_display} "
                f"(brand similarity = {similarity_rating.lower()}, TLD mismatch = {tld_mismatch}, "
                f"deceptive tokens = {found_deceptive_tokens or 'none'})."
            )

        return BrandMatchResult(
            is_official_domain=False,
            official_brand_name=None,
            brand_impersonated=best_brand.upper() if (best_brand and similarity_rating in ["HIGH", "MEDIUM"]) else None,
            brand_display_name=best_brand_display if (best_brand and similarity_rating in ["HIGH", "MEDIUM"]) else None,
            brand_similarity_score=round(best_score, 2),
            brand_similarity_rating=similarity_rating,
            matched_token=best_matched_token,
            target_brand=best_target,
            candidate_stem=stem,
            candidate_tld=tld_actual,
            official_tlds=official_tlds,
            tld_mismatch=tld_mismatch,
            deceptive_tokens=found_deceptive_tokens,
            manipulation_types=best_manipulations,
            signals=signals,
            summary=summary
        )


brand_matcher = BrandMatcher()
