import threading
import datetime
import json
import time
from typing import Dict, List, Optional
from sqlalchemy.orm import sessionmaker, Session
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, conf

from ..database import SessionLocal
from ..models import CaptureSession, Packet, TrafficFlow, Alert
from .parser import ThreatDetector


def clean_null_chars(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.replace('\x00', '')


# Store active capture sessions: session_id -> { "thread": Thread, "stop_event": Event, "packet_count": int }
active_captures: Dict[int, dict] = {}
active_captures_lock = threading.Lock()


class LiveCaptureThread(threading.Thread):
    def __init__(self, session_id: int, interface: str):
        super().__init__()
        self.session_id = session_id
        self.interface = interface
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.db: Session = SessionLocal()
        self.detector = ThreatDetector()
        self.flows = {}
        self.last_commit_time = time.time()
        self.pending_packets = []
        self.daemon = True

    def packet_callback(self, pkt):
        if IP not in pkt:
            return

        try:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            length = len(pkt)
            ttl = pkt[IP].ttl
            flags = None
            dns_query = None

            proto_name = 'IP'
            src_port = None
            dst_port = None

            if TCP in pkt:
                proto_name = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
                if dst_port in (80, 8080, 8000) or src_port in (80, 8080, 8000):
                    proto_name = 'HTTP'
                elif dst_port == 443 or src_port == 443:
                    proto_name = 'HTTPS'
                elif dst_port == 22 or src_port == 22:
                    proto_name = 'SSH'
                elif dst_port == 21 or src_port == 21:
                    proto_name = 'FTP'
            elif UDP in pkt:
                proto_name = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                if dst_port == 53 or src_port == 53:
                    proto_name = 'DNS'
                elif dst_port in (67, 68) or src_port in (67, 68):
                    proto_name = 'DHCP'
            elif ICMP in pkt:
                proto_name = 'ICMP'

            if DNS in pkt and pkt.haslayer(DNSQR):
                try:
                    dns_query = clean_null_chars(pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.'))
                except Exception:
                    pass

            payload_preview = None
            if Raw in pkt:
                try:
                    payload_preview = clean_null_chars(pkt[Raw].load[:150].decode('utf-8', errors='replace'))
                except Exception:
                    pass

            ts = datetime.datetime.utcnow()
            self.packet_count += 1

            # Prepare packet record
            db_packet = Packet(
                session_id=self.session_id,
                packet_number=self.packet_count,
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_name,
                length=length,
                ttl=ttl,
                flags=flags,
                payload_preview=payload_preview,
                raw_summary=clean_null_chars(pkt.summary()[:200])
            )
            self.db.add(db_packet)

            # Flow tracking
            flow_key = (min(src_ip, dst_ip), max(src_ip, dst_ip), proto_name)
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'protocol': proto_name, 'packet_count': 0,
                    'byte_count': 0, 'first_seen': ts, 'last_seen': ts
                }
            f = self.flows[flow_key]
            f['packet_count'] += 1
            f['byte_count'] += length
            f['last_seen'] = ts

            # Threat detection
            pkt_data = {
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': src_port, 'dst_port': dst_port,
                'protocol': proto_name, 'dns_query': dns_query,
                'length': length
            }
            alerts = self.detector.analyze_packet(pkt_data)
            for a in alerts:
                db_alert = Alert(
                    session_id=self.session_id,
                    alert_type=clean_null_chars(a['alert_type']),
                    severity=clean_null_chars(a['severity']),
                    src_ip=clean_null_chars(a.get('src_ip')),
                    dst_ip=clean_null_chars(a.get('dst_ip')),
                    description=clean_null_chars(a['description']),
                    evidence=clean_null_chars(a.get('evidence'))
                )
                self.db.add(db_alert)

            # Batch commit every 1 second or 50 packets for performance
            current_time = time.time()
            if self.packet_count % 50 == 0 or (current_time - self.last_commit_time) > 1.0:
                self.db.commit()
                self.last_commit_time = current_time

                # Update session packet count in DB
                session = self.db.query(CaptureSession).filter(CaptureSession.id == self.session_id).first()
                if session:
                    session.packet_count = self.packet_count
                    self.db.commit()

        except Exception as e:
            print(f"Error in capture packet callback: {e}")

    def run(self):
        try:
            # Update session status
            session = self.db.query(CaptureSession).filter(CaptureSession.id == self.session_id).first()
            if session:
                session.status = 'processing'
                self.db.commit()

            # Start sniffing
            # We use a stop_filter that returns True when we want to stop
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=False
            )

            # Save flows at the end of capture
            for f_data in self.flows.values():
                duration = (f_data['last_seen'] - f_data['first_seen']).total_seconds()
                db_flow = TrafficFlow(
                    session_id=self.session_id,
                    src_ip=f_data['src_ip'],
                    dst_ip=f_data['dst_ip'],
                    src_port=f_data['src_port'],
                    dst_port=f_data['dst_port'],
                    protocol=f_data['protocol'],
                    packet_count=f_data['packet_count'],
                    byte_count=f_data['byte_count'],
                    first_seen=f_data['first_seen'],
                    last_seen=f_data['last_seen'],
                    duration_seconds=duration
                )
                self.db.add(db_flow)

            # Mark session complete
            session = self.db.query(CaptureSession).filter(CaptureSession.id == self.session_id).first()
            if session:
                session.status = 'completed'
                session.packet_count = self.packet_count
                session.completed_at = datetime.datetime.utcnow()
            
            self.db.commit()

        except Exception as e:
            print(f"Capture thread crash: {e}")
            try:
                session = self.db.query(CaptureSession).filter(CaptureSession.id == self.session_id).first()
                if session:
                    session.status = 'failed'
                    session.description = str(e)
                self.db.commit()
            except Exception:
                pass
        finally:
            self.db.close()
            with active_captures_lock:
                if self.session_id in active_captures:
                    del active_captures[self.session_id]


class LiveCaptureManager:
    @staticmethod
    def list_interfaces() -> List[dict]:
        interfaces = []
        try:
            for iface_name, iface in conf.ifaces.items():
                interfaces.append({
                    "id": iface.network_name if hasattr(iface, 'network_name') else (iface.pcap_name if hasattr(iface, 'pcap_name') else iface_name),
                    "name": iface.name,
                    "description": iface.description if hasattr(iface, 'description') else iface.name
                })
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        return interfaces

    @staticmethod
    def start_capture(session_id: int, interface: str) -> bool:
        with active_captures_lock:
            if session_id in active_captures:
                return False

            thread = LiveCaptureThread(session_id, interface)
            active_captures[session_id] = {
                "thread": thread,
                "stop_event": thread.stop_event
            }
            thread.start()
            return True

    @staticmethod
    def stop_capture(session_id: int) -> bool:
        with active_captures_lock:
            if session_id not in active_captures:
                return False
            
            active_captures[session_id]["stop_event"].set()
            return True

    @staticmethod
    def is_active(session_id: int) -> bool:
        with active_captures_lock:
            return session_id in active_captures
