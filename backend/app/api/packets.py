from fastapi import APIRouter, Depends, UploadFile, File, BackgroundTasks, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import Optional, List
import shutil
import os
import uuid
from ..database import get_db
from ..models import CaptureSession, Packet, TrafficFlow, Alert
from ..core.parser import PacketProcessor
from ..core.capture import LiveCaptureManager
from ..core.auth import require_permission
from ..schemas.packet import SessionResponse, PacketResponse, FlowResponse, AlertResponse, DashboardStats

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/upload", response_model=SessionResponse)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are accepted")
    
    file_id = str(uuid.uuid4())
    ext = file.filename.rsplit('.', 1)[-1]
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}.{ext}")
    
    from ..core.encryption import encrypt_data
    file_data = file.file.read()
    encrypted_data = encrypt_data(file_data)

    with open(file_path, "wb") as buffer:
        buffer.write(encrypted_data)
    
    session = CaptureSession(
        name=file.filename,
        source_type="upload",
        file_path=file_path,
        status="processing"
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    processor = PacketProcessor(db, session.id)
    background_tasks.add_task(processor.process_pcap, file_path)
    
    return session


@router.get("/sessions", response_model=List[SessionResponse])
async def list_sessions(db: Session = Depends(get_db)):
    return db.query(CaptureSession).order_by(desc(CaptureSession.created_at)).all()


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: int, db: Session = Depends(get_db)):
    session = db.query(CaptureSession).filter(CaptureSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: int, 
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("delete_session"))
):
    session = db.query(CaptureSession).filter(CaptureSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.file_path and os.path.exists(session.file_path):
        try:
            os.remove(session.file_path)
        except Exception:
            pass
    db.delete(session)
    db.commit()
    return {"message": "Session deleted"}


@router.get("/packets/{session_id}", response_model=List[PacketResponse])
async def list_packets(
    session_id: int,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=500),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
):
    q = db.query(Packet).filter(Packet.session_id == session_id)
    if src_ip:
        q = q.filter(Packet.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:
        q = q.filter(Packet.dst_ip.ilike(f"%{dst_ip}%"))
    if protocol:
        q = q.filter(Packet.protocol.ilike(f"%{protocol}%"))
    return q.order_by(Packet.packet_number).offset(skip).limit(limit).all()


@router.get("/packets/{session_id}/count")
async def count_packets(
    session_id: int,
    db: Session = Depends(get_db),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
):
    q = db.query(func.count(Packet.id)).filter(Packet.session_id == session_id)
    if src_ip:
        q = q.filter(Packet.src_ip.ilike(f"%{src_ip}%"))
    if dst_ip:
        q = q.filter(Packet.dst_ip.ilike(f"%{dst_ip}%"))
    if protocol:
        q = q.filter(Packet.protocol.ilike(f"%{protocol}%"))
    return {"count": q.scalar()}


@router.get("/flows/{session_id}", response_model=List[FlowResponse])
async def list_flows(session_id: int, db: Session = Depends(get_db)):
    return db.query(TrafficFlow).filter(TrafficFlow.session_id == session_id)\
             .order_by(desc(TrafficFlow.byte_count)).all()


@router.get("/alerts", response_model=List[AlertResponse])
async def list_alerts(
    db: Session = Depends(get_db),
    session_id: Optional[int] = None,
    severity: Optional[str] = None,
    limit: int = 50
):
    q = db.query(Alert)
    if session_id:
        q = q.filter(Alert.session_id == session_id)
    if severity:
        q = q.filter(Alert.severity == severity)
    return q.order_by(desc(Alert.created_at)).limit(limit).all()


@router.patch("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    db.commit()
    return {"message": "Alert acknowledged"}


@router.get("/stats/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db), session_id: Optional[int] = None):
    # Total counts
    pkt_q = db.query(func.count(Packet.id))
    alert_q = db.query(func.count(Alert.id))
    if session_id:
        pkt_q = pkt_q.filter(Packet.session_id == session_id)
        alert_q = alert_q.filter(Alert.session_id == session_id)
    
    total_packets = pkt_q.scalar() or 0
    total_sessions = db.query(func.count(CaptureSession.id)).scalar() or 0
    total_alerts = alert_q.scalar() or 0

    # Protocol distribution
    proto_q = db.query(Packet.protocol, func.count(Packet.id).label('count'))
    if session_id:
        proto_q = proto_q.filter(Packet.session_id == session_id)
    proto_data = proto_q.group_by(Packet.protocol).order_by(desc('count')).limit(10).all()
    top_protocols = [{"name": p or "UNKNOWN", "count": c} for p, c in proto_data]

    # Top source IPs
    src_q = db.query(Packet.src_ip, func.count(Packet.id).label('count'))
    if session_id:
        src_q = src_q.filter(Packet.session_id == session_id)
    src_data = src_q.filter(Packet.src_ip != None).group_by(Packet.src_ip)\
                    .order_by(desc('count')).limit(10).all()
    top_src_ips = [{"ip": ip, "count": c} for ip, c in src_data]

    # Top destination IPs
    dst_q = db.query(Packet.dst_ip, func.count(Packet.id).label('count'))
    if session_id:
        dst_q = dst_q.filter(Packet.session_id == session_id)
    dst_data = dst_q.filter(Packet.dst_ip != None).group_by(Packet.dst_ip)\
                    .order_by(desc('count')).limit(10).all()
    top_dst_ips = [{"ip": ip, "count": c} for ip, c in dst_data]

    # Traffic over time (group by second/minute)
    # We can group by timestamp format
    # PostgreSQL group by date_trunc
    # Let's check database dialect to be safe, but since it is PostgreSQL:
    # If SQLite (for tests/fallback) we can use strftime. Let's do a safe string format or just get recent packets.
    time_data = []
    try:
        # Group by minute
        time_q = db.query(
            func.date_trunc('minute', Packet.timestamp).label('minute'),
            func.sum(Packet.length).label('bytes')
        )
        if session_id:
            time_q = time_q.filter(Packet.session_id == session_id)
        time_res = time_q.group_by('minute').order_by('minute').limit(50).all()
        time_data = [{"time": r[0].strftime("%H:%M") if r[0] else "", "bytes": int(r[1] or 0)} for r in time_res]
    except Exception:
        # Fallback if dialect doesn't support date_trunc
        db.rollback()
        # Simple list of recent packets
        time_data = []

    return {
        "total_packets": total_packets,
        "total_sessions": total_sessions,
        "total_alerts": total_alerts,
        "top_protocols": top_protocols,
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "traffic_over_time": time_data
    }


@router.get("/interfaces")
async def list_interfaces():
    return LiveCaptureManager.list_interfaces()


@router.post("/live/start", response_model=SessionResponse)
async def start_live_capture(
    interface: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("manage_capture"))
):
    session = CaptureSession(
        name=name or f"Live Capture - {interface}",
        description=description,
        source_type="live",
        interface=interface,
        status="processing"
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    success = LiveCaptureManager.start_capture(session.id, interface)
    if not success:
        session.status = "failed"
        session.description = "Failed to initiate sniffing on adapter"
        db.commit()
        raise HTTPException(status_code=500, detail="Sniffing session initiation failed")
        
    return session


@router.post("/live/stop/{session_id}")
async def stop_live_capture(
    session_id: int, 
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("manage_capture"))
):
    session = db.query(CaptureSession).filter(CaptureSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    success = LiveCaptureManager.stop_capture(session_id)
    if not success:
        # If sniffing wasn't active but status is still processing, mark completed anyway
        if session.status == "processing":
            session.status = "completed"
            db.commit()
            return {"message": "Sniffing was not active, but status reset to completed"}
        raise HTTPException(status_code=400, detail="Capture session is not active")
        
    return {"message": "Sniffing halted"}
