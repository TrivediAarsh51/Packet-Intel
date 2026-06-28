from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from ..core import crime_db
from ..core import evidence as evidence_core
from ..core.auth import require_permission
import os

router = APIRouter()


class CaseCreate(BaseModel):
    title: str
    description: str
    reporter: str


class EvidenceCreate(BaseModel):
    file_name: str
    metadata: dict = None


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(case: CaseCreate, current_user = Depends(require_permission("manage_cases"))):
    db_path = os.getenv('CRIME_DB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', 'storage', 'mock_crime.db'))
    crime_db.init_db(db_path)
    case_id = crime_db.create_case(db_path, case.title, case.description, case.reporter)
    return {"case_id": case_id}


@router.get("/cases")
def list_cases():
    db_path = os.getenv('CRIME_DB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', 'storage', 'mock_crime.db'))
    crime_db.init_db(db_path)
    cases = crime_db.get_cases(db_path)
    return {"cases": cases}


@router.get("/cases/{case_id}")
def get_case(case_id: int):
    db_path = os.getenv('CRIME_DB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', 'storage', 'mock_crime.db'))
    crime_db.init_db(db_path)
    c = crime_db.get_case(db_path, case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c


@router.post("/cases/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def add_evidence(case_id: int, evidence: EvidenceCreate, current_user = Depends(require_permission("manage_cases"))):
    db_path = os.getenv('CRIME_DB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', '..', 'storage', 'mock_crime.db'))
    crime_db.init_db(db_path)
    if not crime_db.get_case(db_path, case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    uploads_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'uploads'))
    file_path = os.path.join(uploads_dir, evidence.file_name)
    metadata = evidence.metadata or {}
    entry = evidence_core.seal_evidence(file_path, metadata)
    ev_id = crime_db.add_evidence(db_path, case_id, evidence.file_name, entry['evidence_id'], entry)
    return {"evidence_row_id": ev_id, "evidence_id": entry['evidence_id']}



@router.get('/evidence/{evidence_id}/verify')
def verify_evidence(evidence_id: str):
    result = evidence_core.verify_evidence(evidence_id)
    if not result.get('found'):
        raise HTTPException(status_code=404, detail='Evidence not found in chain')
    return result
