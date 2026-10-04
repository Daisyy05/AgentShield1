from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

import approvals
import ratelimit
from audit import get_logs, init_db, log_decision
from auth import authenticate
from dlp import scan_sensitive
from injection import scan_prompt
from policy import HIGH_RISK_TOOLS, check_permission

app = FastAPI(title="AgentShield")

init_db()


class ToolRequest(BaseModel):
    tool: str
    prompt: str = ""


def require_admin(api_key):
    if authenticate(api_key) != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


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

    # Layer 0.5: rate limit
    if not ratelimit.allow(agent_id):
        log_decision(agent_id, request.tool, "BLOCK", "Rate limit exceeded")
        raise HTTPException(status_code=429, detail="Too many requests")

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

    # Layer 4: human approval for high-risk tools
    if result["decision"] == "ALLOW" and request.tool in HIGH_RISK_TOOLS:
        approval_id = approvals.create(agent_id, request.tool)
        result = {
            "decision": "PENDING_APPROVAL",
            "reason": f"{request.tool} is high-risk and needs admin approval",
            "approval_id": approval_id,
        }

    log_decision(agent_id, request.tool, result["decision"], result["reason"])
    return result


@app.get("/approvals")
def list_approvals(x_api_key: str = Header(default=None)):
    require_admin(x_api_key)
    return approvals.list_all()


@app.get("/approvals/{approval_id}")
def approval_status(approval_id: str, x_api_key: str = Header(default=None)):
    caller = authenticate(x_api_key)
    item = approvals.get(approval_id)
    if caller is None or item is None or caller not in (item["agent_id"], "admin"):
        raise HTTPException(status_code=404, detail="Approval not found")
    return item


@app.post("/approvals/{approval_id}/{action}")
def decide(approval_id: str, action: str, x_api_key: str = Header(default=None)):
    require_admin(x_api_key)
    if action not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="Action must be approve or deny")
    status = "APPROVED" if action == "approve" else "DENIED"
    item = approvals.resolve(approval_id, status)
    if item is None:
        raise HTTPException(status_code=404, detail="Approval not found or already decided")
    log_decision(item["agent_id"], item["tool"], status, f"Admin {action}d the request")
    return item


@app.get("/logs")
def logs(limit: int = 50, x_api_key: str = Header(default=None)):
    require_admin(x_api_key)
    return get_logs(limit)