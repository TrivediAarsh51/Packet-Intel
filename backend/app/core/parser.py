import os
import hashlib
import datetime
import json
from typing import Optional, List
from sqlalchemy.orm import Session

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..models import Packet, CaptureSession, TrafficFlow, Alert
from .case_workflow import auto_create_case_for_alert


def clean_null_chars(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.replace('\x00', '')


def compute_sha256(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


class ThreatDetector:
    """Simple signature-based threat detection during packet parsing."""

    def __init__(self):
        self.dns_query_counts = {}
        self.port_scan_tracker = {}

    def analyze_packet(self, pkt_data: dict) -> List[dict]:
        alerts = []

        # DNS Tunneling: long queries
        if pkt_data.get('protocol') == 'DNS' and pkt_data.get('dns_query'):
            query = pkt_data['dns_query']
            src = pkt_data.get('src_ip', '')
            if len(query) > 50:
                alerts.append({
                    'alert_type': 'dns_tunneling',
                    'severity': 'high',
                    'src_ip': src,
                    'dst_ip': pkt_data.get('dst_ip'),
                    'description': f'Suspicious long DNS query detected ({len(query)} chars): {query[:80]}...',
                    'evidence': json.dumps({'query': query, 'length': len(query)})
                })

        # Port Scan Detection
        src = pkt_data.get('src_ip', '')
        dst_port = pkt_data.get('dst_port')
        if src and dst_port:
            if src not in self.port_scan_tracker:
                self.port_scan_tracker[src] = set()
            self.port_scan_tracker[src].add(dst_port)
            unique = len(self.port_scan_tracker[src])
            if unique > 20 and unique % 10 == 1:
                alerts.append({
                    'alert_type': 'port_scan',
                    'severity': 'medium',
                    'src_ip': src,
                    'dst_ip': pkt_data.get('dst_ip'),
                    'description': f'Possible port scan from {src}: {unique} unique destination ports probed',
                    'evidence': json.dumps({'unique_ports': unique})
                })

        # Large ICMP payload (potential ICMP tunnel)
        if pkt_data.get('protocol') == 'ICMP' and pkt_data.get('length', 0) > 200:
            alerts.append({
                'alert_type': 'icmp_tunnel',
                'severity': 'medium',
                'src_ip': pkt_data.get('src_ip'),
                'dst_ip': pkt_data.get('dst_ip'),
                'description': f'Unusually large ICMP packet ({pkt_data["length"]} bytes) — possible ICMP tunneling',
                'evidence': json.dumps({'length': pkt_data['length']})
            })

        return alerts


class PacketProcessor:
    def __init__(self, db: Session, session_id: int):
        self.db = db
        self.session_id = session_id
        self.detector = ThreatDetector()

    def process_pcap(self, file_path: str) -> int:
        if not SCAPY_AVAILABLE:
            raise RuntimeError('Scapy is not installed. Run: pip install scapy')

        try:
            file_hash = compute_sha256(file_path)
            file_size = os.path.getsize(file_path)

            packets = rdpcap(file_path)
            processed_count = 0
            flows = {}
            all_alerts: List[dict] = []

            for idx, pkt in enumerate(packets):
                if IP not in pkt:
                    continue

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
                    elif dst_port == 25 or src_port == 25:
                        proto_name = 'SMTP'
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

                # Extract DNS query
                if DNS in pkt and pkt.haslayer(DNSQR):
                    try:
                        dns_query = clean_null_chars(pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.'))
                    except Exception:
                        pass

                # Payload preview
                payload_preview = None
                if Raw in pkt:
                    raw = pkt[Raw].load
                    payload_preview = clean_null_chars(raw[:150].decode('utf-8', errors='replace'))

                # Timestamp
                try:
                    ts = datetime.datetime.fromtimestamp(float(pkt.time))
                except Exception:
                    ts = datetime.datetime.utcnow()

                # DB record
                db_packet = Packet(
                    session_id=self.session_id,
                    packet_number=idx + 1,
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
                if flow_key not in flows:
                    flows[flow_key] = {
                        'src_ip': src_ip, 'dst_ip': dst_ip,
                        'src_port': src_port, 'dst_port': dst_port,
                        'protocol': proto_name, 'packet_count': 0,
                        'byte_count': 0, 'first_seen': ts, 'last_seen': ts
                    }
                f = flows[flow_key]
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
                detected = self.detector.analyze_packet(pkt_data)
                all_alerts.extend(detected)

                processed_count += 1
                if processed_count % 500 == 0:
                    self.db.commit()

            # Save flows
            for f_data in flows.values():
                duration = None
                if f_data['first_seen'] and f_data['last_seen']:
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

            # Save alerts (deduplicate by type+src)
            seen_alerts = set()
            for a in all_alerts:
                key = (a['alert_type'], a.get('src_ip'))
                if key not in seen_alerts:
                    seen_alerts.add(key)
                    db_alert = Alert(
                        session_id=self.session_id,
                        alert_type=clean_null_chars(a['alert_type']),
                        severity=clean_null_chars(a['severity']),
                        src_ip=clean_null_chars(a.get('src_ip')),
                        dst_ip=clean_null_chars(a.get('dst_ip')),
                        description=clean_null_chars(a['description']),
                        evidence=clean_null_chars(a.get('evidence'))
                    )
                    self.db.add(db_alert)                    if a.get('severity', '').lower() == 'high' or a.get('alert_type') in ('dns_tunneling', 'port_scan', 'icmp_tunnel'):
                        try:
                            auto_create_case_for_alert(self.session_id, a, session_file_path=file_path)
                        except Exception as exc:
                            print(f"Auto case workflow failed: {exc}")
            # Update session
            session = self.db.query(CaptureSession).filter(
                CaptureSession.id == self.session_id
            ).first()
            if session:
                session.status = 'completed'
                session.packet_count = processed_count
                session.sha256_hash = file_hash
                session.file_size = file_size
                session.completed_at = datetime.datetime.utcnow()

            self.db.commit()
            return processed_count

        except Exception as e:
            self.db.rollback()
            session = self.db.query(CaptureSession).filter(
                CaptureSession.id == self.session_id
            ).first()
            if session:
                session.status = 'failed'
                session.description = str(e)
            self.db.commit()
            raise e
