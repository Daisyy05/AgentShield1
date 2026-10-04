import hashlib
import json
import secrets

from policy import AGENTS

keys = {}
hashes = {}

for agent_id in [*AGENTS, "admin"]:
    key = "ask_" + secrets.token_urlsafe(32)
    keys[agent_id] = key
    hashes[hashlib.sha256(key.encode()).hexdigest()] = agent_id

# What the server checks: hashes only
with open("agent_keys.json", "w") as f:
    json.dump(hashes, f, indent=2)

# DEV ONLY: plaintext copy so you never copy-paste keys from the terminal
with open("dev_keys.json", "w") as f:
    json.dump(keys, f, indent=2)

print("Keys generated. Dev copy saved in dev_keys.json (never commit it).")