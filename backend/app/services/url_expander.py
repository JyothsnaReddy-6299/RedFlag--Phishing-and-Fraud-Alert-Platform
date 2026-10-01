"""
URL Expander & Shortened Link Resolution Engine
------------------------------------------------
Identifies common shortened-link patterns and follows redirection chains:
  short URL
   ↓
  resolve destination (HTTP HEAD / GET headers)
   ↓
  analyze final URL
   ↓
  keep original + final URL in evidence

Features:
  - Known public shortener database (bit.ly, tinyurl.com, t.co, is.gd, etc.)
  - Heuristic detection of custom short-slug redirects
  - Multi-hop redirect tracking (hop count, full redirect chain)
  - Strict timeout and streaming protection against loops / large payloads
  - Safe fallback when offline or when redirection fails
"""

import re
from typing import Optional, List, Tuple, Set
from urllib.parse import urlparse
import httpx

from backend.app.models.schemas import ShortenerAnalysis


# Known common URL shortener domains
KNOWN_SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "shorte.st",
    "trib.al", "qr.net", "v.gd", "snip.ly", "bit.do", "t.ly", "dub.sh",
    "qr.ae", "clck.ru", "rotf.lol", "soo.gd", "s.id", "bl.ink", "lnkd.in",
    "fb.me", "wp.me", "amzn.to", "git.io", "ift.tt", "cur.lv", "bc.vc",
    "po.st", "u.to", "tiny.one", "short.io", "prettylink.com", "linktr.ee"
}

# Regex for typical shortener slug paths (e.g. /3xY7zQ, /aBc123)
SHORTENER_SLUG_PATTERN = re.compile(r"^/[a-zA-Z0-9_-]{2,12}$")


def extract_host_from_url(url: str) -> str:
    """Extracts lowercase hostname from a raw URL string."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower().strip()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def is_shortened_url_candidate(url: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a URL matches known shortened-link patterns or shortener domains.
    Returns: (is_shortener_candidate, detected_shortener_domain)
    """
    host = extract_host_from_url(url)
    if not host:
        return False, None

    # 1. Exact or suffix match in known shortener registry
    for short_dom in KNOWN_SHORTENER_DOMAINS:
        if host == short_dom or host.endswith(f".{short_dom}"):
            return True, host

    # 2. Heuristic check: very short domain (<= 7 chars) with short slug path
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        path = parsed.path or ""
        if len(host) <= 7 and "." in host and SHORTENER_SLUG_PATTERN.match(path):
            return True, host
    except Exception:
        pass

    return False, None


def resolve_redirect_chain(
    url: str,
    timeout: float = 2.5,
    max_redirects: int = 5
) -> Tuple[str, List[str], bool, Optional[str]]:
    """
    Follows HTTP redirects using HEAD (with fallback to stream GET).
    Returns: (final_url, redirect_chain, success, error_message)
    """
    target = url if "://" in url else f"http://{url}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, max_redirects=max_redirects, headers=headers) as client:
            # 1. Try HEAD request first (avoids fetching response body)
            try:
                resp = client.head(target)
                if resp.status_code in (200, 301, 302, 303, 307, 308) and str(resp.url) != target:
                    chain = [str(r.url) for r in resp.history]
                    final_url = str(resp.url)
                    if not chain or chain[-1] != final_url:
                        chain.append(final_url)
                    return final_url, chain, True, None
            except Exception:
                pass

            # 2. Stream GET fallback (only reading headers and immediately closing)
            with client.stream("GET", target) as resp:
                chain = [str(r.url) for r in resp.history]
                final_url = str(resp.url)
                if not chain or chain[-1] != final_url:
                    chain.append(final_url)
                return final_url, chain, True, None

    except httpx.TooManyRedirects:
        return target, [target], False, "Too many redirects (infinite loop detected)"
    except Exception as e:
        return target, [target], False, f"Redirect resolution failed: {e}"


class URLExpander:
    def __init__(self, timeout: float = 2.5, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    def expand(
        self,
        url: str,
        override_destination: Optional[str] = None,
        override_chain: Optional[List[str]] = None
    ) -> ShortenerAnalysis:
        """
        Detects if URL is shortened, resolves final destination, and compiles evidence.
        """
        clean_url = (url or "").strip()
        is_candidate, short_domain = is_shortened_url_candidate(clean_url)

        # Handle unit test or manual mock override
        if override_destination is not None:
            dest_domain = extract_host_from_url(override_destination)
            chain = override_chain or [clean_url, override_destination]
            sigs = [
                f"Shortened URL detected: Short link ({short_domain or 'shortener'}) redirects to "
                f"final destination '{override_destination}' ({dest_domain})"
            ]
            return ShortenerAnalysis(
                is_shortened=True,
                shortener_domain=short_domain or extract_host_from_url(clean_url),
                original_url=clean_url,
                destination_url=override_destination,
                destination_domain=dest_domain,
                redirect_chain=chain,
                hop_count=max(0, len(chain) - 1),
                resolved_successfully=True,
                signals=sigs
            )

        # If detected as shortened URL candidate, attempt resolution
        if is_candidate:
            final_url, chain, success, err = resolve_redirect_chain(
                clean_url,
                timeout=self.timeout,
                max_redirects=self.max_redirects
            )

            if success and final_url != clean_url:
                dest_domain = extract_host_from_url(final_url)
                sigs = [
                    f"Shortened URL detected: Short link ({short_domain}) redirects to "
                    f"final destination '{final_url}' ({dest_domain})"
                ]
                return ShortenerAnalysis(
                    is_shortened=True,
                    shortener_domain=short_domain,
                    original_url=clean_url,
                    destination_url=final_url,
                    destination_domain=dest_domain,
                    redirect_chain=chain,
                    hop_count=max(0, len(chain) - 1),
                    resolved_successfully=True,
                    signals=sigs
                )
            else:
                # Shortener detected but resolution failed/timed out
                sigs = [
                    f"Shortened URL detected: '{clean_url}' ({short_domain}) "
                    f"could not be resolved ({err or 'destination offline/unreachable'})"
                ]
                return ShortenerAnalysis(
                    is_shortened=True,
                    shortener_domain=short_domain,
                    original_url=clean_url,
                    destination_url=clean_url,
                    destination_domain=short_domain,
                    redirect_chain=[clean_url],
                    hop_count=0,
                    resolved_successfully=False,
                    error_message=err,
                    signals=sigs
                )

        # Standard non-shortened URL
        host = extract_host_from_url(clean_url)
        return ShortenerAnalysis(
            is_shortened=False,
            shortener_domain=None,
            original_url=clean_url,
            destination_url=clean_url,
            destination_domain=host,
            redirect_chain=[clean_url],
            hop_count=0,
            resolved_successfully=True,
            signals=[]
        )


url_expander = URLExpander()
