import uuid

PENDING = {}


def create(agent_id: str, tool: str) -> str:
    approval_id = uuid.uuid4().hex[:8]
    PENDING[approval_id] = {"agent_id": agent_id, "tool": tool, "status": "PENDING"}
    return approval_id


def get(approval_id: str):
    return PENDING.get(approval_id)


def list_all():
    return PENDING


def resolve(approval_id: str, status: str):
    item = PENDING.get(approval_id)
    if item and item["status"] == "PENDING":
        item["status"] = status
        return item
    return None