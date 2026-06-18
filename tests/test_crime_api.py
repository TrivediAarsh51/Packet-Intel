import os
import tempfile
from fastapi.testclient import TestClient
from backend.app.main import app


def test_create_and_get_case(tmp_path):
    # Use a temporary DB path
    db_file = tmp_path / "mock_crime.db"
    os.environ['CRIME_DB_PATH'] = str(db_file)

    client = TestClient(app)

    # Create case
    resp = client.post('/api/crime/cases', json={
        'title': 'Test Case',
        'description': 'Unit test case',
        'reporter': 'tester'
    })
    assert resp.status_code == 201
    body = resp.json()
    assert 'case_id' in body
    case_id = body['case_id']

    # List cases
    resp = client.get('/api/crime/cases')
    assert resp.status_code == 200
    cases = resp.json().get('cases', [])
    assert any(c['id'] == case_id for c in cases)

    # Get case detail
    resp = client.get(f'/api/crime/cases/{case_id}')
    assert resp.status_code == 200
    detail = resp.json()
    assert detail['id'] == case_id

    # Add evidence
    resp = client.post(f'/api/crime/cases/{case_id}/evidence', json={
        'file_name': 'sample.pcap',
        'evidence_id': 'ev-123',
        'metadata': {'source': 'unit-test'}
    })
    assert resp.status_code == 201
    body = resp.json()
    assert 'evidence_row_id' in body
    assert 'evidence_id' in body
    evidence_id = body['evidence_id']

    # Verify evidence via chain
    resp = client.get(f'/api/crime/evidence/{evidence_id}/verify')
    assert resp.status_code == 200
    verify = resp.json()
    assert verify.get('found') is True
