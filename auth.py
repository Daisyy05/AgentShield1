import hashlib
import hmac
import json

KEYS_FILE = "agent_keys.json"


def load_hashes():
    try:
        with open(KEYS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def authenticate(api_key):
    """Return the agent_id for a valid key, or None."""
    if not api_key:
        return None
    given = hashlib.sha256(api_key.encode()).hexdigest()
    for stored_hash, agent_id in load_hashes().items():
        if hmac.compare_digest(given, stored_hash):
            return agent_id
    return None