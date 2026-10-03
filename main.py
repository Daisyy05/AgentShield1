from fastapi import FastAPI
from pydantic import BaseModel

from audit import get_logs, init_db, log_decision
from injection import scan_prompt
from policy import check_permission

app = FastAPI(title="AgentShield")

init_db()


class ToolRequest(BaseModel):
    agent_id: str
    tool: str
    prompt: str = ""


@app.get("/")
def home():
    return {"project": "AgentShield", "status": "running"}


@app.post("/check")
def check(request: ToolRequest):
    # Layer 1: identity and permission
    result = check_permission(request.agent_id, request.tool)

    # Layer 2: prompt injection scan (only if permission passed)
    if result["decision"] == "ALLOW" and request.prompt:
        scan = scan_prompt(request.prompt)
        if scan["flagged"]:
            result = {
                "decision": "BLOCK",
                "reason": "Prompt injection suspected: " + "; ".join(scan["reasons"]),
            }

    log_decision(request.agent_id, request.tool, result["decision"], result["reason"])
    return result


@app.get("/logs")
def logs(limit: int = 50):
    return get_logs(limit)