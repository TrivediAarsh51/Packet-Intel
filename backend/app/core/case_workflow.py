import json
import os
import time
from typing import Optional

from .crime_db import init_db, create_case, add_evidence
from .evidence import seal_evidence


def auto_create_case_for_alert(
    session_id: int,
    alert: dict,
    session_file_path: Optional[str] = None,
    upload_dir: Optional[str] = None,
    db_path: Optional[str] = None,
) -> tuple[int, str]:
    """Create a mock crime case and seal alert evidence to the chain."""
    if db_path is None:
        db_path = os.getenv(
            'CRIME_DB_PATH',
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'storage', 'mock_crime.db'))
        )
    if upload_dir is None:
        upload_dir = os.getenv(
            'UPLOAD_DIR',
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'uploads'))
        )

    os.makedirs(upload_dir, exist_ok=True)
    init_db(db_path)

    severity = str(alert.get('severity', 'medium')).lower()
    alert_type = alert.get('alert_type', 'unknown')
    title = f"Auto Alert Case: {alert_type}"
    description = (
        f"Auto-generated case for alert '{alert_type}' in session {session_id}. "
        f"Severity={severity}. {alert.get('description', '')}"
    )
    case_id = create_case(db_path, title, description, reporter='auto-detector')

    evidence_payload = {
        'session_id': session_id,
        'alert_type': alert_type,
        'severity': severity,
        'description': alert.get('description'),
        'src_ip': alert.get('src_ip'),
        'dst_ip': alert.get('dst_ip'),
        'evidence': alert.get('evidence'),
        'created_at': int(time.time()),
        'source_file': session_file_path,
    }

    evidence_file_name = f"alert-{session_id}-{alert_type}-{int(time.time())}.json"
    evidence_path = os.path.join(upload_dir, evidence_file_name)
    with open(evidence_path, 'w', encoding='utf-8') as fh:
        json.dump(evidence_payload, fh, indent=2)

    entry = seal_evidence(evidence_path, evidence_payload)
    evidence_row_id = add_evidence(db_path, case_id, evidence_file_name, entry['evidence_id'], entry)
    return case_id, entry['evidence_id']
