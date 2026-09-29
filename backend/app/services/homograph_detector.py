import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any

# Confusable mapping for Latin lookalikes across foreign alphabets
# (Cyrillic, Greek, etc. per Unicode UTS #39 Confusables)
CONFUSABLE_MAP: Dict[str, Tuple[str, str]] = {
    # Cyrillic lowercase homoglyphs
    "\u0430": ("a", "Cyrillic"),
    "\u0441": ("c", "Cyrillic"),
    "\u0435": ("e", "Cyrillic"),
    "\u0456": ("i", "Cyrillic"),
    "\u0458": ("j", "Cyrillic"),
    "\u043e": ("o", "Cyrillic"),
    "\u0440": ("p", "Cyrillic"),
    "\u0445": ("x", "Cyrillic"),
    "\u0443": ("y", "Cyrillic"),
    "\u0455": ("s", "Cyrillic"),
    "\u0501": ("d", "Cyrillic"),
    "\u051b": ("q", "Cyrillic"),
    "\u051d": ("w", "Cyrillic"),
    # Cyrillic uppercase homoglyphs
    "\u0410": ("A", "Cyrillic"),
    "\u0412": ("B", "Cyrillic"),
    "\u0421": ("C", "Cyrillic"),
    "\u0415": ("E", "Cyrillic"),
    "\u041d": ("H", "Cyrillic"),
    "\u0406": ("I", "Cyrillic"),
    "\u0408": ("J", "Cyrillic"),
    "\u041a": ("K", "Cyrillic"),
    "\u041c": ("M", "Cyrillic"),
    "\u041e": ("O", "Cyrillic"),
    "\u0420": ("P", "Cyrillic"),
    "\u0422": ("T", "Cyrillic"),
    "\u0425": ("X", "Cyrillic"),
    "\u0423": ("Y", "Cyrillic"),
    "\u0405": ("S", "Cyrillic"),
    # Greek lowercase homoglyphs
    "\u03b1": ("a", "Greek"),
    "\u03bf": ("o", "Greek"),
    "\u03bd": ("v", "Greek"),
    "\u03c1": ("p", "Greek"),
    "\u03c4": ("t", "Greek"),
    "\u03c5": ("u", "Greek"),
    "\u03b9": ("i", "Greek"),
    "\u03ba": ("k", "Greek"),
    "\u03c7": ("x", "Greek"),
    # Greek uppercase homoglyphs
    "\u0391": ("A", "Greek"),
    "\u0392": ("B", "Greek"),
    "\u0395": ("E", "Greek"),
    "\u0396": ("Z", "Greek"),
    "\u0397": ("H", "Greek"),
    "\u0399": ("I", "Greek"),
    "\u039a": ("K", "Greek"),
    "\u039c": ("M", "Greek"),
    "\u039d": ("N", "Greek"),
    "\u039f": ("O", "Greek"),
    "\u03a1": ("P", "Greek"),
    "\u03a4": ("T", "Greek"),
    "\u03a7": ("X", "Greek"),
    "\u03a5": ("Y", "Greek"),
}


def get_character_script(char: str) -> str:
    """
    Identifies the script family of a character using Unicode properties.
    """
    if "a" <= char <= "z" or "A" <= char <= "Z":
        return "Latin"
    if "0" <= char <= "9" or char in "-_":
        return "Common"

    name = unicodedata.name(char, "")
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "GREEK" in name:
        return "Greek"
    if "LATIN" in name:
        return "Latin"
    if "ARABIC" in name:
        return "Arabic"
    if "HEBREW" in name:
        return "Hebrew"
    if "DEVANAGARI" in name:
        return "Devanagari"
    if any(k in name for k in ["CJK", "HIRAGANA", "KATAKANA", "HANGUL"]):
        return "EastAsian"
    return "Other"


@dataclass
class ConfusableDetail:
    char: str
    codepoint: str
    script: str
    target_char: str
    name: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "char": self.char,
            "codepoint": self.codepoint,
            "script": self.script,
            "target_char": self.target_char,
            "name": self.name,
        }


@dataclass
class HomographAnalysisResult:
    """Detailed result of IDN Homograph & Confusable character inspection."""
    has_punycode: bool
    has_unicode: bool
    is_mixed_script: bool
    detected_scripts: List[str]
    confusables_detected: List[Dict[str, str]] = field(default_factory=list)
    homograph_risk: str = "NONE"  # "NONE", "LOW", "SUSPICIOUS", "CRITICAL"
    summary_message: str = ""
    signals: List[str] = field(default_factory=list)
    base_risk_penalty: float = 0.0
    unicode_host: str = ""
    punycode_host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_punycode": self.has_punycode,
            "has_unicode": self.has_unicode,
            "is_mixed_script": self.is_mixed_script,
            "detected_scripts": self.detected_scripts,
            "confusables_detected": self.confusables_detected,
            "homograph_risk": self.homograph_risk,
            "summary_message": self.summary_message,
            "signals": self.signals,
            "base_risk_penalty": self.base_risk_penalty,
            "unicode_host": self.unicode_host,
            "punycode_host": self.punycode_host,
        }


class HomographDetector:
    """
    Advanced IDN Homograph, Confusable character, and Script-Mixing detector.
    
    Detects:
    1. xn-- Punycode representation
    2. Unicode hostname
    3. Mixed scripts (e.g. Latin + Cyrillic, Greek + Latin in the same domain label)
    4. Confusable characters (UTS #39 visual homoglyphs targeting ASCII brand lookalikes)
    
    Adheres strictly to RFC 5890 and Unicode UTS #39 security guidance:
    Legitimate single-script Unicode domains (e.g. 'münchen.de') generate an informational
    signal without false-positive malicious scoring, while mixed-script or confusable
    lookalikes generate critical homograph attack alerts.
    """

    def analyze(self, hostname: str) -> HomographAnalysisResult:
        if not hostname:
            return HomographAnalysisResult(
                has_punycode=False,
                has_unicode=False,
                is_mixed_script=False,
                detected_scripts=[],
                confusables_detected=[],
                homograph_risk="NONE",
                summary_message="Empty hostname",
                signals=[],
                base_risk_penalty=0.0
            )

        raw_host = hostname.lower().strip()
        has_punycode = "xn--" in raw_host

        # Resolve Unicode and Punycode dual forms
        try:
            if has_punycode:
                unicode_host = raw_host.encode("ascii").decode("idna")
                punycode_host = raw_host
            else:
                punycode_host = raw_host.encode("idna").decode("ascii")
                unicode_host = raw_host
                has_punycode = "xn--" in punycode_host
        except Exception:
            unicode_host = raw_host
            punycode_host = raw_host

        has_unicode = any(ord(c) > 127 for c in unicode_host)

        # Inspect each label for script mixing and confusable characters
        labels = unicode_host.split(".")
        all_scripts: Set[str] = set()
        is_mixed_script = False
        confusables: List[ConfusableDetail] = []
        mixed_script_labels: List[Tuple[str, List[str]]] = []

        for label in labels:
            label_scripts: Set[str] = set()
            for char in label:
                script = get_character_script(char)
                if script != "Common":
                    label_scripts.add(script)
                    all_scripts.add(script)

                if char in CONFUSABLE_MAP:
                    target_char, script_family = CONFUSABLE_MAP[char]
                    confusables.append(
                        ConfusableDetail(
                            char=char,
                            codepoint=f"U+{ord(char):04X}",
                            script=script_family,
                            target_char=target_char,
                            name=unicodedata.name(char, "UNKNOWN"),
                        )
                    )

            if len(label_scripts) > 1:
                is_mixed_script = True
                mixed_script_labels.append((label, sorted(list(label_scripts))))

        signals: List[str] = []
        confusables_dict = [c.to_dict() for c in confusables]
        scripts_list = sorted(list(all_scripts))

        # Risk Classification & Signal Generation
        if is_mixed_script or len(confusables) > 0:
            homograph_risk = "CRITICAL"
            summary_message = "HOMOGRAPH RISK: Mixed/Confusable characters detected"

            signals.append("HOMOGRAPH RISK: Mixed/Confusable characters detected in domain hostname")

            if is_mixed_script:
                for lbl, scripts in mixed_script_labels:
                    signals.append(
                        f"Mixed scripts detected: Label '{lbl}' combines characters from multiple scripts ({', '.join(scripts)})"
                    )

            if confusables:
                sample = confusables[0]
                signals.append(
                    f"Confusable character detected: '{sample.char}' ({sample.codepoint}, {sample.script}) visually mimics Latin '{sample.target_char}'"
                )

            base_risk_penalty = 60.0

        elif has_punycode or has_unicode:
            homograph_risk = "LOW"
            summary_message = f"Internationalized Domain Name (IDN): Standard single-script Unicode hostname ({', '.join(scripts_list) or 'Unicode'})"
            signals.append(
                f"Unicode hostname (IDN): Domain contains valid single-script international characters (Punycode: '{punycode_host}')"
            )
            base_risk_penalty = 5.0  # Mild signal, not marked malicious

        else:
            homograph_risk = "NONE"
            summary_message = "Standard ASCII domain hostname with no confusable characters"
            base_risk_penalty = 0.0

        return HomographAnalysisResult(
            has_punycode=has_punycode,
            has_unicode=has_unicode,
            is_mixed_script=is_mixed_script,
            detected_scripts=scripts_list,
            confusables_detected=confusables_dict,
            homograph_risk=homograph_risk,
            summary_message=summary_message,
            signals=signals,
            base_risk_penalty=base_risk_penalty,
            unicode_host=unicode_host,
            punycode_host=punycode_host
        )


homograph_detector = HomographDetector()
