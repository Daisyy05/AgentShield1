# Who each agent is, and what it is allowed to do.
# Zero trust: anything not listed here is denied.

AGENTS = {
    "agent-001": {
        "name": "support-bot",
        "allowed_tools": ["search_docs", "read_ticket", "delete_ticket"],
    },
    "agent-002": {
        "name": "finance-bot",
        "allowed_tools": ["read_invoice", "transfer_money"],
    },
}

HIGH_RISK_TOOLS = ["delete_ticket", "transfer_money"]


def check_permission(agent_id: str, tool: str) -> dict:
    agent = AGENTS.get(agent_id)

    if agent is None:
        return {"decision": "BLOCK", "reason": "Unknown agent identity"}

    if tool not in agent["allowed_tools"]:
        return {"decision": "BLOCK", "reason": f"{agent['name']} is not allowed to use {tool}"}

    return {"decision": "ALLOW", "reason": f"{agent['name']} is allowed to use {tool}"}