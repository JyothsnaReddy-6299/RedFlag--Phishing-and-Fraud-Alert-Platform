import re
from typing import List, Tuple
from urllib.parse import urlparse
from app.models.schemas import ExtractedEntities

KNOWN_ORGANIZATIONS = [
    # Banks & Financial
    "State Bank of India", "SBI", "HDFC Bank", "HDFC", "ICICI Bank", "ICICI",
    "Axis Bank", "Axis", "Punjab National Bank", "PNB", "Bank of Baroda",
    "Canara Bank", "Union Bank", "Kotak Mahindra", "Kotak", "IndusInd Bank",
    # UPI & Wallets
    "Paytm", "PhonePe", "Google Pay", "GPay", "BHIM", "Amazon Pay", "Cred",
    # Utilities & Government
    "TNEB", "Electricity Board", "India Post", "Post Office", "EPFO", "PF Office",
    "Income Tax Department", "IT Department", "Aadhaar", "UIDAI", "TRAI",
    "Police Department", "Cyber Crime",
    # E-Commerce & Tech
    "Amazon", "Flipkart", "WhatsApp", "Telegram", "Netflix", "Microsoft", "Google", "Apple"
]

# UPI Handles common in India
UPI_HANDLES = {
    "okhdfcbank", "okaxis", "okicici", "oksbi", "paytm", "ybl", "ibl", "axl",
    "apl", "upi", "postbank", "barodampay", "federal", "airtel", "pingpay",
    "kotak", "indus", "freecharge", "icici", "sbi", "hdfcbank"
}

class EntityExtractor:
    def __init__(self):
        # Indian phone number patterns (with or without +91 / 0 prefix)
        self.phone_pattern = re.compile(
            r'(?:(?:\+91|0091|91|0)?[\s-]?)?([6-9]\d{4}[\s-]?\d{5})\b'
        )
        # UPI pattern: username@bankhandle
        self.upi_pattern = re.compile(
            r'\b([a-zA-Z0-9.\-_]{2,64}@([a-zA-Z]{2,32}))\b', re.IGNORECASE
        )
        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        )
        # URL pattern
        self.url_pattern = re.compile(
            r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:\'\".,<>?«»“”‘’]))'
        )

    def extract_all(self, text: str) -> ExtractedEntities:
        if not text:
            return ExtractedEntities()

        urls = self.extract_urls(text)
        domains = self.extract_domains(urls)
        upis = self.extract_upi_ids(text)
        emails = self.extract_emails(text, upis)
        phones = self.extract_phone_numbers(text)
        orgs = self.extract_organizations(text)

        return ExtractedEntities(
            phone_numbers=phones,
            upi_ids=upis,
            urls=urls,
            domains=domains,
            organizations=orgs,
            emails=emails
        )

    def extract_urls(self, text: str) -> List[str]:
        raw_matches = self.url_pattern.findall(text)
        urls = []
        for match in raw_matches:
            url_str = match[0] if isinstance(match, tuple) else match
            if not url_str.startswith("http://") and not url_str.startswith("https://"):
                url_str = "http://" + url_str
            if url_str not in urls:
                urls.append(url_str)
        return urls

    def extract_domains(self, urls: List[str]) -> List[str]:
        domains = []
        for url in urls:
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc.split(":")[0].lower()
                if netloc.startswith("www."):
                    netloc = netloc[4:]
                if netloc and netloc not in domains:
                    domains.append(netloc)
            except Exception:
                continue
        return domains

    def extract_upi_ids(self, text: str) -> List[str]:
        candidates = self.upi_pattern.findall(text)
        upis = []
        for full_id, handle in candidates:
            # Check if handle matches known UPI handles or does not have standard email TLD
            h_lower = handle.lower()
            if h_lower in UPI_HANDLES or not re.search(r'\.(com|org|net|in|co|edu|gov)$', h_lower):
                clean_id = full_id.strip()
                if clean_id not in upis:
                    upis.append(clean_id)
        return upis

    def extract_emails(self, text: str, existing_upis: List[str]) -> List[str]:
        candidates = self.email_pattern.findall(text)
        emails = []
        upi_set = set(u.lower() for u in existing_upis)
        for email in candidates:
            clean_email = email.strip().lower()
            if clean_email not in upi_set and clean_email not in emails:
                emails.append(clean_email)
        return emails

    def extract_phone_numbers(self, text: str) -> List[str]:
        matches = self.phone_pattern.findall(text)
        phones = []
        for m in matches:
            cleaned = re.sub(r'[\s-]', '', m)
            if len(cleaned) == 10 and cleaned[0] in "6789":
                if cleaned not in phones:
                    phones.append(cleaned)
        return phones

    def extract_organizations(self, text: str) -> List[str]:
        found = []
        text_lower = text.lower()
        for org in KNOWN_ORGANIZATIONS:
            # Match word boundary for acronyms like SBI or words like Paytm
            pattern = rf'\b{re.escape(org.lower())}\b'
            if re.search(pattern, text_lower):
                if org not in found:
                    found.append(org)
        return found

entity_extractor = EntityExtractor()
