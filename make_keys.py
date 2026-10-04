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

with open("agent_keys.json", "w") as f:
    json.dump(hashes, f, indent=2)

print("Save these keys now. They are shown only once:\n")
for agent_id, key in keys.items():
    print(f"{agent_id}: {key}")