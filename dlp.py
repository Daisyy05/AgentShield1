import re

# (pattern, label) for common sensitive data
SENSITIVE_PATTERNS = [
    (r"\b(?:\d[ -]?){13,16}\b", "possible credit card number"),
    (r"\b(?:sk|pk|ask)_[A-Za-z0-9_\-]{16,}\b", "possible API key"),
    (r"AKIA[0-9A-Z]{16}", "possible AWS access key"),
    (r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S+", "password in text"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"\b\d{4}\s\d{4}\s\d{4}\b", "possible Aadhaar number"),
]


def scan_sensitive(text: str) -> dict:
    found = []
    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, text):
            found.append(label)
    return {"flagged": len(found) > 0, "found": found}