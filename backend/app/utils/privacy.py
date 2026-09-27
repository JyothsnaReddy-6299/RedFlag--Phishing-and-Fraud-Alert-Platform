import hashlib
import re

def hash_identifier(value: str, salt: str = "cybershield_salt") -> str:
    """Hashes sensitive data (like reporter IP address) with SHA-256."""
    if not value:
        return ""
    return hashlib.sha256(f"{salt}_{value}".encode()).hexdigest()[:16]

def mask_phone_number(phone: str) -> str:
    """
    Masks a phone number for public display.
    Example: 9840123456 -> 98****3456
    """
    if not phone:
        return ""
    cleaned = re.sub(r'[\s-]', '', phone)
    if len(cleaned) == 10:
        return f"{cleaned[:2]}****{cleaned[-4:]}"
    elif len(cleaned) > 10:
        return f"{cleaned[:3]}****{cleaned[-4:]}"
    return "****"

def mask_upi_id(upi: str) -> str:
    """
    Masks a UPI identifier while retaining bank handle for intelligence.
    Example: john.doe@okhdfcbank -> j******e@okhdfcbank
    """
    if not upi or "@" not in upi:
        return "****"
    user, handle = upi.split("@", 1)
    if len(user) <= 2:
        masked_user = f"{user[0]}*"
    else:
        masked_user = f"{user[0]}{'*' * (len(user) - 2)}{user[-1]}"
    return f"{masked_user}@{handle}"

def mask_url(url: str) -> str:
    """
    Sanitizes URL for safe viewing (defanging protocols).
    Example: http://evil.com/login -> hxxp://evil[.]com/login
    """
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return defanged
