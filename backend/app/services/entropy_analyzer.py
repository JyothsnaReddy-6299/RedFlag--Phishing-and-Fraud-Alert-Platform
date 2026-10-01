"""
Entropy Analysis Engine
-----------------------
Calculates Shannon entropy separately across distinct URL components:
  - domain_entropy
  - subdomain_entropy
  - path_entropy
  - query_entropy

Architectural Principle:
  Entropy is evaluated contextually.
  Static rule `entropy > X -> malicious` generates high false positives on CDNs,
  cloud buckets, and session hashes.

  Instead, compound threat combinations are detected:
    High Entropy + Untrusted / High-Abuse Domain + Brand Impersonation
  This combination indicates algorithmically generated phishing infrastructure (DGA/kit).
"""

import math
from typing import Optional, List, Tuple
from pydantic import BaseModel, Field, ConfigDict


class EntropyAnalysis(BaseModel):
    domain_entropy: float = 0.0
    subdomain_entropy: float = 0.0
    path_entropy: float = 0.0
    query_entropy: float = 0.0
    overall_entropy: float = 0.0
    is_high_domain_entropy: bool = False
    is_high_subdomain_entropy: bool = False
    is_high_path_entropy: bool = False
    is_high_query_entropy: bool = False
    has_compound_risk: bool = False
    compound_explanation: Optional[str] = None
    signals: List[str] = Field(default_factory=list)
    evaluation_note: str = (
        "Entropy is evaluated contextually (High Entropy + Untrusted Domain + Brand Impersonation), "
        "not as an isolated malicious verdict."
    )

    model_config = ConfigDict(from_attributes=True)


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy (bits per symbol) for a given string:
      H(X) = - sum(p(x) * log2(p(x)))
    Returns 0.0 for empty or single-character strings.
    """
    if not text or len(text) <= 1:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class EntropyAnalyzer:
    def __init__(self):
        # Entropy thresholds for anomaly detection
        # Natural English domains typically have entropy ~2.5 - 3.4
        self.domain_high_threshold = 3.8
        self.subdomain_high_threshold = 3.8
        self.path_high_threshold = 4.0
        self.query_high_threshold = 4.2

    def analyze(
        self,
        domain: str,
        subdomain: Optional[str] = None,
        path: Optional[str] = None,
        query: Optional[str] = None,
        is_untrusted_domain: bool = False,
        is_suspicious_tld: bool = False,
        brand_impersonated: Optional[str] = None,
        is_official_domain: bool = False
    ) -> EntropyAnalysis:
        """
        Calculates Shannon entropy separately for domain, subdomain, path, and query,
        and evaluates compound threat combinations:
          [High Entropy] + [Untrusted Domain / High-Abuse TLD] + [Brand Similarity]
        """
        # 1. Component calculations
        dom_clean = (domain or "").strip().lower()
        # Evaluate stem/SLD if domain contains dot
        dom_stem = dom_clean.split(".")[0] if "." in dom_clean else dom_clean
        domain_ent = calculate_shannon_entropy(dom_clean)

        sub_clean = (subdomain or "").strip().lower()
        subdomain_ent = calculate_shannon_entropy(sub_clean) if len(sub_clean) > 2 else 0.0

        path_clean = (path or "").strip().strip("/")
        path_ent = calculate_shannon_entropy(path_clean) if len(path_clean) > 3 else 0.0

        query_clean = (query or "").strip().lstrip("?")
        query_ent = calculate_shannon_entropy(query_clean) if len(query_clean) > 3 else 0.0

        # Overall entropy (hostname)
        overall_ent = domain_ent

        # 2. Anomaly flags (accounting for minimum length to avoid short-string noise)
        is_high_dom = domain_ent >= self.domain_high_threshold and len(dom_clean) >= 8
        is_high_sub = subdomain_ent >= self.subdomain_high_threshold and len(sub_clean) >= 8
        is_high_path = path_ent >= self.path_high_threshold and len(path_clean) >= 14
        is_high_query = query_ent >= self.query_high_threshold and len(query_clean) >= 20

        signals: List[str] = []
        has_compound = False
        compound_exp: Optional[str] = None

        # 3. Contextual Compound Evaluation (Immunity for verified official portals)
        if not is_official_domain:
            has_high_structural_entropy = is_high_dom or is_high_sub or is_high_path
            is_untrusted_or_abuse_tld = is_untrusted_domain or is_suspicious_tld
            has_brand_similarity = bool(brand_impersonated)

            # High Entropy + Untrusted Domain + Brand Impersonation
            if has_high_structural_entropy and is_untrusted_or_abuse_tld and has_brand_similarity:
                has_compound = True
                compound_exp = (
                    f"Compound threat detected: High algorithmic entropy ({domain_ent:.2f}) "
                    f"combined with untrusted namespace and brand impersonation ({brand_impersonated}) "
                    f"indicating automated phishing infrastructure / DGA kit."
                )
                signals.append(compound_exp)

            # High domain entropy on untrusted TLD without brand mimicry (potential DGA / throwaway)
            elif is_high_dom and is_suspicious_tld:
                signals.append(
                    f"Potential DGA throwaway domain: High domain entropy ({domain_ent:.2f}) "
                    f"on high-abuse TLD indicating algorithmically generated hostname."
                )

            # Isolated entropy observations (Evidence, not proof)
            elif is_high_dom and not is_official_domain:
                signals.append(
                    f"Elevated domain entropy ({domain_ent:.2f}); evaluated contextually as a structural indicator."
                )

            if is_high_sub and not is_official_domain and not has_compound:
                signals.append(
                    f"Elevated subdomain entropy ({subdomain_ent:.2f}) indicating randomized host routing."
                )

        return EntropyAnalysis(
            domain_entropy=domain_ent,
            subdomain_entropy=subdomain_ent,
            path_entropy=path_ent,
            query_entropy=query_ent,
            overall_entropy=overall_ent,
            is_high_domain_entropy=is_high_dom,
            is_high_subdomain_entropy=is_high_sub,
            is_high_path_entropy=is_high_path,
            is_high_query_entropy=is_high_query,
            has_compound_risk=has_compound,
            compound_explanation=compound_exp,
            signals=signals,
            evaluation_note=(
                "Entropy is evaluated contextually (High Entropy + Untrusted Domain + Brand Impersonation), "
                "not as an isolated malicious verdict."
            )
        )


entropy_analyzer = EntropyAnalyzer()
