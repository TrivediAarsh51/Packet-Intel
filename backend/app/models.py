from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Text, Boolean, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default='user', nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    sessions = relationship('CaptureSession', back_populates='user')


class CaptureSession(Base):
    __tablename__ = 'capture_sessions'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default='pending')
    source_type = Column(String, nullable=False)
    file_path = Column(String, nullable=True)
    interface = Column(String, nullable=True)
    packet_count = Column(Integer, default=0)
    file_size = Column(BigInteger, default=0)
    sha256_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    user = relationship('User', back_populates='sessions')
    packets = relationship('Packet', back_populates='session', cascade='all, delete-orphan')
    flows = relationship('TrafficFlow', back_populates='session', cascade='all, delete-orphan')
    alerts = relationship('Alert', back_populates='session', cascade='all, delete-orphan')


class Packet(Base):
    __tablename__ = 'packets'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey('capture_sessions.id'), nullable=False)
    packet_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, index=True)
    length = Column(Integer)
    ttl = Column(Integer, nullable=True)
    flags = Column(String, nullable=True)
    payload_preview = Column(Text, nullable=True)
    raw_summary = Column(Text, nullable=True)
    session = relationship('CaptureSession', back_populates='packets')


class TrafficFlow(Base):
    __tablename__ = 'traffic_flows'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey('capture_sessions.id'), nullable=False)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Float, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    duration_seconds = Column(Float, nullable=True)
    session = relationship('CaptureSession', back_populates='flows')


class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey('capture_sessions.id'), nullable=False)
    alert_type = Column(String, index=True)
    severity = Column(String, index=True)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    description = Column(Text)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_acknowledged = Column(Boolean, default=False)
    session = relationship('CaptureSession', back_populates='alerts')
