import sqlite3
from datetime import datetime, timezone

DB_FILE = "agentshield.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )


def log_decision(agent_id: str, tool: str, decision: str, reason: str):
    timestamp = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp, agent_id, tool, decision, reason) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, agent_id, tool, decision, reason),
        )


def get_logs(limit: int = 50):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]