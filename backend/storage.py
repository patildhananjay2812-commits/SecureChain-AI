import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("SECURECHAIN_DATABASE", BASE_DIR / "data" / "securechain.db"))


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                project_name TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                dependency_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                typosquatting_json TEXT NOT NULL,
                package_data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS scans_workspace_created_idx
                ON scans (workspace_id, created_at DESC);
            """
        )


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def create_user(email, password_hash):
    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email.strip().lower(), password_hash, now_iso()),
        )
        user_id = cursor.lastrowid
        cursor = connection.execute(
            "INSERT INTO workspaces (owner_id, name, created_at) VALUES (?, ?, ?)",
            (user_id, "Default workspace", now_iso()),
        )
        return {"id": user_id, "email": email.strip().lower(), "workspace_id": cursor.lastrowid}


def find_user_by_email(email):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
        return dict(row) if row else None


def get_workspace(workspace_id, user_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, name FROM workspaces WHERE id = ? AND owner_id = ?",
            (workspace_id, user_id),
        ).fetchone()
        return dict(row) if row else None


def create_scan(workspace_id, project_name, source, risk_score, risk_level,
                dependency_count, findings, typosquatting_findings, package_data):
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                workspace_id, project_name, source, risk_score, risk_level,
                dependency_count, findings_json, typosquatting_json,
                package_data_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id,
                project_name,
                source,
                risk_score,
                risk_level,
                dependency_count,
                json.dumps(findings),
                json.dumps(typosquatting_findings),
                json.dumps(package_data),
                now_iso(),
            ),
        )
        return cursor.lastrowid


def list_scans(workspace_id, user_id, limit=50):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scans.id, scans.project_name, scans.source, scans.risk_score,
                   scans.risk_level, scans.dependency_count, scans.created_at
            FROM scans
            JOIN workspaces ON workspaces.id = scans.workspace_id
            WHERE scans.workspace_id = ? AND workspaces.owner_id = ?
            ORDER BY scans.created_at DESC
            LIMIT ?
            """,
            (workspace_id, user_id, limit),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan(scan_id, workspace_id, user_id):
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT scans.*
            FROM scans
            JOIN workspaces ON workspaces.id = scans.workspace_id
            WHERE scans.id = ? AND scans.workspace_id = ? AND workspaces.owner_id = ?
            """,
            (scan_id, workspace_id, user_id),
        ).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["findings"] = json.loads(scan.pop("findings_json"))
        scan["typosquatting_findings"] = json.loads(scan.pop("typosquatting_json"))
        scan["package_data"] = json.loads(scan.pop("package_data_json"))
        return scan


init_db()
