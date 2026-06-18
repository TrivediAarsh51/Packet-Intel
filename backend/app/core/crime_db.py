import sqlite3
import os
from typing import List, Dict, Any
import threading

_lock = threading.Lock()


def init_db(db_path: str):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with _lock:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            reporter TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cur.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            file_name TEXT,
            evidence_id TEXT,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        )
        ''')
        conn.commit()
        conn.close()


def create_case(db_path: str, title: str, description: str, reporter: str) -> int:
    with _lock:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute('INSERT INTO cases (title, description, reporter) VALUES (?, ?, ?)', (title, description, reporter))
        conn.commit()
        case_id = cur.lastrowid
        conn.close()
        return case_id


def get_cases(db_path: str) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT id, title, description, reporter, created_at FROM cases ORDER BY id DESC')
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_case(db_path: str, case_id: int) -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT id, title, description, reporter, created_at FROM cases WHERE id = ?', (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    case = dict(row)
    cur.execute('SELECT id, file_name, evidence_id, metadata, created_at FROM evidence WHERE case_id = ? ORDER BY id', (case_id,))
    ev = cur.fetchall()
    conn.close()
    case['evidence'] = [dict(r) for r in ev]
    return case


def add_evidence(db_path: str, case_id: int, file_name: str, evidence_id: str, metadata: dict) -> int:
    import json
    with _lock:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute('INSERT INTO evidence (case_id, file_name, evidence_id, metadata) VALUES (?, ?, ?, ?)',
                    (case_id, file_name, evidence_id, json.dumps(metadata)))
        conn.commit()
        ev_id = cur.lastrowid
        conn.close()
        return ev_id


def get_evidence_by_evidence_id(db_path: str, evidence_id: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT id, case_id, file_name, evidence_id, metadata, created_at FROM evidence WHERE evidence_id = ?', (evidence_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    import json
    out = dict(row)
    try:
        out['metadata'] = json.loads(out.get('metadata') or '{}')
    except Exception:
        out['metadata'] = {}
    return out
