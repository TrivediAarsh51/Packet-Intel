import os
import re
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
from .threat_intel import (
    EXFILTRATION_SIGNATURES,
    BOTNET_IP_BLACKLIST,
    BOTNET_DOMAIN_BLACKLIST,
    calculate_entropy,
)


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


# ---------------------------------------------------------------------------
# TLS / HTTPS handshake detection helper
# ---------------------------------------------------------------------------

_TLS_CONTENT_TYPES = {20, 21, 22, 23}  # change_cipher_spec, alert, handshake, app_data
_TLS_VERSIONS = {
    b'\x03\x01',  # TLS 1.0
    b'\x03\x02',  # TLS 1.1
    b'\x03\x03',  # TLS 1.2 / 1.3 (negotiated as 1.3 in extension)
}


def _is_tls_record(payload: bytes) -> bool:
    """
    Return True if *payload* looks like a TLS record layer.

    Heuristic: first byte is a recognised TLS content type AND bytes 1-2 are
    a recognised TLS/SSL version.  This is far more reliable than checking
    dst_port == 443 alone, because:
      - Many non-TLS protocols also use port 443
      - Attackers often tunnel C2 over port 443 without TLS
    """
    if len(payload) < 5:
        return False
    return (
        payload[0] in _TLS_CONTENT_TYPES
        and payload[1:3] in _TLS_VERSIONS
    )


class ThreatDetector:
    """Multi-engine threat detector used during PCAP packet parsing.

    Engines
    -------
    1. DNS tunneling heuristic (long queries)
    2. Port-scan tracker (unique destination port count)
    3. Oversized ICMP payload (ICMP tunneling)
    4. Payload signature engine — regex DPI for data exfiltration patterns
       (credit cards with Luhn validation, SSNs, credentials, API keys …)
    5. Shannon entropy analysis — detects encrypted / obfuscated payloads,
       suppressed only when the payload is confirmed as a TLS record (not
       merely because dst_port == 443).
    6. Botnet / C2 blacklist — IP and domain IOC matching.
    """

    def __init__(self):
        self.dns_query_counts = {}
        self.port_scan_tracker = {}

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def analyze_packet(
        self,
        pkt_data: dict,
        raw_payload: Optional[bytes] = None,
    ) -> List[dict]:
        """Run all detection engines against one packet.

        Parameters
        ----------
        pkt_data:
            Dict of parsed packet metadata (src/dst IP, ports, protocol, …).
        raw_payload:
            Raw bytes of the packet payload layer (``scapy.Raw.load``), or
            ``None`` if the packet has no payload.

        Returns
        -------
        List of alert dicts ready for DB persistence.
        """
        alerts = []

        # --- Engine 1: DNS Tunneling (long queries) -------------------------
        if pkt_data.get('protocol') == 'DNS' and pkt_data.get('dns_query'):
            query = pkt_data['dns_query']
            src = pkt_data.get('src_ip', '')
            if len(query) > 50:
                alerts.append({
                    'alert_type': 'dns_tunneling',
                    'severity': 'high',
                    'src_ip': src,
                    'dst_ip': pkt_data.get('dst_ip'),
                    'description': (
                        f'Suspicious long DNS query detected '
                        f'({len(query)} chars): {query[:80]}...'
                    ),
                    'evidence': json.dumps({'query': query, 'length': len(query)}),
                })

        # --- Engine 2: Port Scan Detection ----------------------------------
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
                    'description': (
                        f'Possible port scan from {src}: '
                        f'{unique} unique destination ports probed'
                    ),
                    'evidence': json.dumps({'unique_ports': unique}),
                })

        # --- Engine 3: Large ICMP payload (ICMP tunneling) ------------------
        if pkt_data.get('protocol') == 'ICMP' and pkt_data.get('length', 0) > 200:
            alerts.append({
                'alert_type': 'icmp_tunnel',
                'severity': 'medium',
                'src_ip': pkt_data.get('src_ip'),
                'dst_ip': pkt_data.get('dst_ip'),
                'description': (
                    f'Unusually large ICMP packet ({pkt_data["length"]} bytes) '
                    f'— possible ICMP tunneling'
                ),
                'evidence': json.dumps({'length': pkt_data['length']}),
            })

        # --- Engines 4-6: payload-dependent (skip if no payload) ------------
        if raw_payload:
            alerts.extend(self._check_payload_signatures(raw_payload, pkt_data))
            alerts.extend(self._check_entropy(raw_payload, pkt_data))

        alerts.extend(self._check_botnet_blacklist(pkt_data))

        return alerts

    # -----------------------------------------------------------------------
    # Engine 4: Payload signature / DPI
    # -----------------------------------------------------------------------

    def _check_payload_signatures(
        self,
        raw_payload: bytes,
        pkt_data: dict,
    ) -> List[dict]:
        """Scan *raw_payload* against all EXFILTRATION_SIGNATURES rules."""
        alerts = []
        try:
            # Decode payload to text; ignore non-UTF-8 bytes
            payload_text = raw_payload.decode('utf-8', errors='ignore')
        except Exception:
            return alerts

        for rule in EXFILTRATION_SIGNATURES:
            match = rule.pattern.search(payload_text)
            if match is None:
                continue

            matched_str = match.group() if hasattr(match, 'group') else str(match)
            # Redact the middle of sensitive values before logging
            display = self._redact(matched_str)

            alerts.append({
                'alert_type': rule.alert_type,
                'severity': rule.severity,
                'src_ip': pkt_data.get('src_ip'),
                'dst_ip': pkt_data.get('dst_ip'),
                'description': rule.description_tmpl.format(match=display),
                'evidence': json.dumps({
                    'signature_name': rule.name,
                    'protocol': pkt_data.get('protocol'),
                    'dst_port': pkt_data.get('dst_port'),
                    'payload_size': len(raw_payload),
                }),
            })

        return alerts

    @staticmethod
    def _redact(value: str, keep: int = 4) -> str:
        """Partially redact a sensitive string, keeping *keep* chars at each end."""
        if len(value) <= keep * 2 + 2:
            return '***'
        return value[:keep] + '*' * (len(value) - keep * 2) + value[-keep:]

    # -----------------------------------------------------------------------
    # Engine 5: Shannon entropy analysis
    # -----------------------------------------------------------------------

    _ENTROPY_MIN_BYTES = 64        # smaller payloads give unreliable entropy
    _ENTROPY_HIGH_THRESHOLD = 7.2  # strongly encrypted / packed
    _ENTROPY_MED_THRESHOLD = 5.0   # compressed / partially encrypted

    def _check_entropy(
        self,
        raw_payload: bytes,
        pkt_data: dict,
    ) -> List[dict]:
        """Detect unusually high-entropy payloads that may be encrypted or packed.

        Suppression policy
        ------------------
        The alert is suppressed only when the payload bytes match the TLS
        record-layer heuristic (content type + version magic).  Checking
        port 443 alone is insufficient — attackers frequently tunnel non-TLS
        C2 traffic over port 443 specifically to evade naïve port-based
        filters.
        """
        alerts = []

        if len(raw_payload) < self._ENTROPY_MIN_BYTES:
            return alerts

        # Suppress only confirmed TLS records, not merely port-443 traffic
        if _is_tls_record(raw_payload):
            return alerts

        entropy = calculate_entropy(raw_payload)

        if entropy >= self._ENTROPY_HIGH_THRESHOLD:
            alerts.append({
                'alert_type': 'encrypted_payload',
                'severity': 'medium',
                'src_ip': pkt_data.get('src_ip'),
                'dst_ip': pkt_data.get('dst_ip'),
                'description': (
                    f'High-entropy payload detected (entropy={entropy:.2f} bits/byte) '
                    f'on non-TLS {pkt_data.get("protocol", "")} flow — '
                    f'possible encrypted C2, packed malware, or covert channel'
                ),
                'evidence': json.dumps({
                    'entropy': round(entropy, 4),
                    'payload_size': len(raw_payload),
                    'protocol': pkt_data.get('protocol'),
                    'dst_port': pkt_data.get('dst_port'),
                    'threshold': self._ENTROPY_HIGH_THRESHOLD,
                }),
            })
        elif entropy >= self._ENTROPY_MED_THRESHOLD:
            alerts.append({
                'alert_type': 'compressed_payload',
                'severity': 'low',
                'src_ip': pkt_data.get('src_ip'),
                'dst_ip': pkt_data.get('dst_ip'),
                'description': (
                    f'Moderately high-entropy payload (entropy={entropy:.2f} bits/byte) '
                    f'— possibly compressed data or partial encryption'
                ),
                'evidence': json.dumps({
                    'entropy': round(entropy, 4),
                    'payload_size': len(raw_payload),
                    'protocol': pkt_data.get('protocol'),
                    'dst_port': pkt_data.get('dst_port'),
                }),
            })

        return alerts

    # -----------------------------------------------------------------------
    # Engine 6: Botnet / C2 blacklist
    # -----------------------------------------------------------------------

    def _check_botnet_blacklist(self, pkt_data: dict) -> List[dict]:
        """Flag traffic to/from known malicious IPs and domains."""
        alerts = []
        src_ip = pkt_data.get('src_ip', '')
        dst_ip = pkt_data.get('dst_ip', '')
        dns_query = pkt_data.get('dns_query', '')

        # IP checks
        for suspect_ip, role in [(src_ip, 'source'), (dst_ip, 'destination')]:
            if suspect_ip and suspect_ip in BOTNET_IP_BLACKLIST:
                alerts.append({
                    'alert_type': 'botnet_c2',
                    'severity': 'critical',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'description': (
                        f'Traffic {role} IP {suspect_ip} matches known botnet / '
                        f'C2 blacklist — possible malware command-and-control '
                        f'communication'
                    ),
                    'evidence': json.dumps({
                        'blacklisted_ip': suspect_ip,
                        'role': role,
                        'protocol': pkt_data.get('protocol'),
                        'dst_port': pkt_data.get('dst_port'),
                    }),
                })

        # Domain check (DNS queries)
        if dns_query:
            # Normalise: strip trailing dot, lowercase
            domain = dns_query.rstrip('.').lower()
            if domain in BOTNET_DOMAIN_BLACKLIST:
                alerts.append({
                    'alert_type': 'botnet_c2',
                    'severity': 'critical',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'description': (
                        f'DNS query for blacklisted domain "{domain}" — '
                        f'possible malware C2 / botnet beacon'
                    ),
                    'evidence': json.dumps({
                        'blacklisted_domain': domain,
                        'protocol': pkt_data.get('protocol'),
                    }),
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

        from .encryption import decrypt_data
        import io
        import hashlib

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            try:
                decrypted_data = decrypt_data(encrypted_data)
            except Exception as e:
                raise ValueError("Failed to decrypt PCAP file.") from e

            file_hash = hashlib.sha256(decrypted_data).hexdigest()
            file_size = len(decrypted_data)

            pcap_io = io.BytesIO(decrypted_data)
            pcap_io.name = file_path
            packets = rdpcap(pcap_io)
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

                # Extract raw payload bytes for DPI engines
                raw_payload: Optional[bytes] = None
                if Raw in pkt:
                    raw_payload = pkt[Raw].load

                # Threat detection (all engines)
                pkt_data = {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'protocol': proto_name, 'dns_query': dns_query,
                    'length': length,
                }
                detected = self.detector.analyze_packet(
                    pkt_data, raw_payload=raw_payload
                )
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
                    self.db.add(db_alert)

                    if a.get('severity', '').lower() in ('high', 'critical') or a.get('alert_type') in (
                        'dns_tunneling',
                        'port_scan',
                        'icmp_tunnel',
                        'botnet_c2',
                        'data_exfiltration',
                        'encrypted_payload',
                    ):
                        try:
                            auto_create_case_for_alert(
                                self.session_id,
                                a,
                                session_file_path=file_path
                            )
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
