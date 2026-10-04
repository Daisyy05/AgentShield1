import os

import requests
import json

SHIELD_URL = "http://127.0.0.1:8000/check"
def load_key():
    key = os.environ.get("AGENT_KEY")
    if key:
        return key
    try:
        with open("dev_keys.json") as f:
            return json.load(f)["agent-001"]
    except (FileNotFoundError, KeyError):
        return None


API_KEY = load_key()

# Fake tools the agent can actually "run"
TOOLS = {
    "search_docs": lambda: "Found 3 docs about password resets.",
    "read_ticket": lambda: "Ticket 42: customer cannot log in.",
    "delete_ticket": lambda: "Ticket 42 deleted.",
    "read_invoice": lambda: "Invoice 7: 500 INR.",
}


def pick_tool(message: str) -> str:
    text = message.lower()
    if "delete" in text:
        return "delete_ticket"
    if "invoice" in text:
        return "read_invoice"
    if "ticket" in text:
        return "read_ticket"
    return "search_docs"


def ask_shield(tool: str, prompt: str) -> dict:
    response = requests.post(
        SHIELD_URL,
        json={"tool": tool, "prompt": prompt},
        headers={"x-api-key": API_KEY},
        timeout=10,
    )
    if response.status_code != 200:
        detail = response.json().get("detail", "unknown error")
        return {"decision": "BLOCK", "reason": f"AgentShield said {response.status_code}: {detail}"}
    return response.json()


def run_agent(message: str):
    tool = pick_tool(message)
    print(f"  agent wants to use: {tool}")

    verdict = ask_shield(tool, message)

    if verdict["decision"] == "ALLOW":
        print(f"  ALLOWED -> {TOOLS[tool]()}")
    elif verdict["decision"] == "PENDING_APPROVAL":
        print(f"  WAITING for admin approval (id: {verdict['approval_id']})")
    else:
        print(f"  BLOCKED -> {verdict['reason']}")


if __name__ == "__main__":
    if not API_KEY:
        raise SystemExit("Set AGENT_KEY first (see instructions).")
    print("Demo agent ready. Type a request, or 'quit' to stop.")
    while True:
        user_message = input("\nYou: ")
        if user_message.strip().lower() == "quit":
            break
        run_agent(user_message)