import os
import tempfile
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.anomaly import IsolationForestAnomalyDetector


def test_anomaly_detector_basic():
    """Test basic anomaly detection on synthetic data."""
    detector = IsolationForestAnomalyDetector(contamination=0.1)
    
    # Normal packets
    normal_packets = [
        {'id': i, 'length': 64 + i*10, 'src_port': 1000 + i, 'dst_port': 80, 'protocol': 'TCP', 'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 'payload_preview': 'GET / HTTP/1.1'}
        for i in range(20)
    ]
    
    # Add anomalies (very large packets)
    anomalies = [
        {'id': 100, 'length': 10000, 'src_port': 5000, 'dst_port': 443, 'protocol': 'HTTPS', 'src_ip': '10.0.0.50', 'dst_ip': '1.1.1.1', 'payload_preview': 'LARGE'},
        {'id': 101, 'length': 15000, 'src_port': 5001, 'dst_port': 443, 'protocol': 'HTTPS', 'src_ip': '10.0.0.51', 'dst_ip': '1.1.1.1', 'payload_preview': 'LARGE'},
    ]
    
    packets = normal_packets + anomalies
    result = detector.detect_packets(packets)
    
    assert result['total_packets'] == 22
    assert result['anomaly_count'] >= 1, "Should detect at least one anomaly"
    assert len(result['anomalies']) > 0


def test_anomaly_api_minimal_packets():
    """Test anomaly endpoint with too few packets."""
    db_file = tempfile.mktemp(suffix='.db')
    os.environ['CRIME_DB_PATH'] = db_file
    
    client = TestClient(app)
    
    # Try to detect on non-existent session
    resp = client.post('/api/anomaly/sessions/999/detect')
    assert resp.status_code == 404


def test_crime_case_anomaly_integration(tmp_path):
    """Test full flow: create case, add evidence, verify chain."""
    db_file = tmp_path / "test_anomaly.db"
    os.environ['CRIME_DB_PATH'] = str(db_file)
    
    client = TestClient(app)
    
    # Create case
    resp = client.post('/api/crime/cases', json={
        'title': 'High Severity Anomaly Case',
        'description': 'Created from anomaly detection workflow',
        'reporter': 'auto-detector'
    })
    assert resp.status_code == 201
    case_id = resp.json()['case_id']
    
    # Add evidence from anomaly
    resp = client.post(f'/api/crime/cases/{case_id}/evidence', json={
        'file_name': f'anomaly-session-1-high-severity.json',
        'metadata': {
            'detection_type': 'isolation_forest',
            'contamination': 0.05,
            'anomaly_count': 3,
            'alert_severity': 'HIGH'
        }
    })
    assert resp.status_code == 201
    body = resp.json()
    assert 'evidence_id' in body
    evidence_id = body['evidence_id']
    
    # Verify evidence chain
    resp = client.get(f'/api/crime/evidence/{evidence_id}/verify')
    assert resp.status_code == 200
    verify = resp.json()
    assert verify['found'] is True
    assert verify['entry']['evidence_id'] == evidence_id


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
