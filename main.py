from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from audit import get_logs, init_db, log_decision
from auth import authenticate
from dlp import scan_sensitive
from injection import scan_prompt
from policy import check_permission

app = FastAPI(title="AgentShield")

init_db()


class ToolRequest(BaseModel):
    tool: str
    prompt: str = ""


@app.get("/")
def home():
    return {"project": "AgentShield", "status": "running"}


@app.post("/check")
def check(request: ToolRequest, x_api_key: str = Header(default=None)):
    # Layer 0: authentication
    agent_id = authenticate(x_api_key)
    if agent_id is None:
        log_decision("unauthenticated", request.tool, "BLOCK", "Missing or invalid API key")
        raise HTTPException(status_code=401, detail="Missing or invalid API key")

    # Layer 1: permission
    result = check_permission(agent_id, request.tool)

    if result["decision"] == "ALLOW" and request.prompt:
        # Layer 2: prompt injection scan
        scan = scan_prompt(request.prompt)
        if scan["flagged"]:
            result = {
                "decision": "BLOCK",
                "reason": "Prompt injection suspected: " + "; ".join(scan["reasons"]),
            }
        else:
            # Layer 3: sensitive data scan
            dlp = scan_sensitive(request.prompt)
            if dlp["flagged"]:
                result = {
                    "decision": "BLOCK",
                    "reason": "Sensitive data detected: " + "; ".join(dlp["found"]),
                }

    log_decision(agent_id, request.tool, result["decision"], result["reason"])
    return result


@app.get("/logs")
def logs(limit: int = 50, x_api_key: str = Header(default=None)):
    if authenticate(x_api_key) != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_logs(limit)