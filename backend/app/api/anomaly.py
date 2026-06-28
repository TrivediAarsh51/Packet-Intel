from fastapi import APIRouter, HTTPException, Query, Depends
from ..core.anomaly import IsolationForestAnomalyDetector
from ..core.auth import require_permission

router = APIRouter()


@router.post('/sessions/{session_id}/detect')
def detect_session(session_id: int, contamination: float = Query(0.05, ge=0.001, le=0.5), current_user = Depends(require_permission("manage_cases"))):
    detector = IsolationForestAnomalyDetector(contamination=contamination)
    result = detector.detect_session(session_id, contamination=contamination)
    if result.get('total_packets', 0) == 0:
        raise HTTPException(status_code=404, detail='No packets found for session or session does not exist')
    return result
