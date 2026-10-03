import re

# Simple rule-based scanner: (pattern, why it's suspicious)
INJECTION_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
     "Tries to override previous instructions"),
    (r"disregard (all |any )?(previous|prior|above)",
     "Tries to override previous instructions"),
    (r"(reveal|show|print) (me )?(your )?(system prompt|hidden instructions)",
     "Tries to extract the system prompt"),
    (r"you are now",
     "Tries to change the agent's role"),
    (r"(developer|jailbreak|dan) mode",
     "Tries to unlock restricted behavior"),
    (r"(send|email|upload|post).*(password|api key|secret|token)",
     "Tries to exfiltrate sensitive data"),
]


def scan_prompt(text: str) -> dict:
    reasons = []
    for pattern, reason in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(reason)
    return {"flagged": len(reasons) > 0, "reasons": reasons}