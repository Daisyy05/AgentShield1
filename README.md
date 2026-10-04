# AgentShield

A zero-trust security gateway for AI agents. An agent must pass through AgentShield before any tool runs, and AgentShield decides ALLOW, BLOCK, or PENDING_APPROVAL.

## What it does

| Layer | Protection |
|---|---|
| Authentication | Agents prove identity with an API key (only SHA-256 hashes are stored) |
| Rate limiting | Caps requests per agent per minute |
| Permissions | Deny by default; each agent has an explicit tool allowlist |
| Prompt injection scan | Blocks "ignore previous instructions" style attacks |
| Sensitive data scan | Blocks passwords, API keys, card numbers and similar in prompts |
| Human approval | High-risk tools wait for an admin to approve |
| Audit log | Every decision is recorded in SQLite; only admins can read it |

The demo agent also fails closed: if AgentShield is unreachable, no tool runs.

## Tech stack

Python, FastAPI, SQLite, pytest

## Quick start

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install fastapi uvicorn requests pytest httpx
python make_keys.py
uvicorn main:app --reload
```

`make_keys.py` creates `agent_keys.json` (hashes, used by the server) and `dev_keys.json` (plaintext, for local development only). Both are gitignored.

In a second terminal, run the demo agent:

```powershell
python demo_agent.py
```

Open `http://127.0.0.1:8000/dashboard` and use the admin key from `dev_keys.json` to see the audit log live.

## Run the tests

```powershell
pytest -v
```

## Example

| Agent message | Result |
|---|---|
| Show me ticket 42 | ALLOWED |
| Delete ticket 42 | PENDING_APPROVAL |
| Show me the invoice | BLOCKED (not in the agent's allowlist) |
| Ignore previous instructions... | BLOCKED (prompt injection) |
| Login with password: hunter2... | BLOCKED (sensitive data) |

## Limitations

This is a learning project, not production software.

- Injection and sensitive-data detection use regex rules, which can be bypassed by rephrasing or encoding.
- Approvals and rate-limit counters are kept in memory and reset on restart.
- Dev keys are stored in plaintext locally; a real deployment would use a secrets manager.
- No HTTPS, and it is meant to run on localhost only.

## Roadmap

- LLM-based injection detection (Ollama)
- Persistent approvals
- Per-tool argument validation
- Docker support