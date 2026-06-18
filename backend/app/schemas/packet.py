from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class PacketResponse(BaseModel):
    id: int
    session_id: int
    packet_number: int
    timestamp: Optional[datetime]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: Optional[int]
    ttl: Optional[int]
    flags: Optional[str]
    payload_preview: Optional[str]
    raw_summary: Optional[str]

    class Config:
        orm_mode = True


class SessionResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: str
    source_type: str
    packet_count: int
    file_size: int
    sha256_hash: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        orm_mode = True


class FlowResponse(BaseModel):
    id: int
    session_id: int
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    packet_count: int
    byte_count: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    duration_seconds: Optional[float]

    class Config:
        orm_mode = True


class AlertResponse(BaseModel):
    id: int
    session_id: int
    alert_type: str
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    description: str
    evidence: Optional[str]
    created_at: datetime
    is_acknowledged: bool

    class Config:
        orm_mode = True


class DashboardStats(BaseModel):
    total_packets: int
    total_sessions: int
    total_alerts: int
    top_protocols: List[Dict[str, Any]]
    top_src_ips: List[Dict[str, Any]]
    top_dst_ips: List[Dict[str, Any]]
    traffic_over_time: List[Dict[str, Any]]

