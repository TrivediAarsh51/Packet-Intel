import argparse
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import Packet

PROTOCOL_MAP = {
    'TCP': 1,
    'UDP': 2,
    'HTTP': 3,
    'HTTPS': 4,
    'DNS': 5,
    'ICMP': 6,
    'FTP': 7,
    'SSH': 8,
    'SMTP': 9,
    'DHCP': 10,
    'UNKNOWN': 0,
}


def _protocol_value(protocol: Optional[str]) -> int:
    return PROTOCOL_MAP.get((protocol or 'UNKNOWN').upper(), 0)


def _feature_vector(packet: Packet) -> List[float]:
    return [
        float(packet.length or 0),
        float(packet.src_port or 0),
        float(packet.dst_port or 0),
        float(_protocol_value(packet.protocol)),
    ]


class IsolationForestAnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(contamination=self.contamination, random_state=self.random_state)

    def detect_packets(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        if len(packets) < 10:
            return {
                'total_packets': len(packets),
                'anomalies': [],
                'message': 'Not enough packets for anomaly detection (minimum 10).'
            }

        feature_matrix = []
        for pkt in packets:
            feature_matrix.append([
                float(pkt.get('length', 0)),
                float(pkt.get('src_port') or 0),
                float(pkt.get('dst_port') or 0),
                float(_protocol_value(pkt.get('protocol'))),
            ])

        X = np.array(feature_matrix, dtype=float)
        self.model.fit(X)
        labels = self.model.predict(X)
        scores = self.model.decision_function(X)

        anomalies = []
        for idx, (pkt, label, score) in enumerate(zip(packets, labels, scores)):
            if label == -1:
                anomalies.append({
                    'packet_index': idx,
                    'packet_id': pkt.get('id'),
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'protocol': pkt.get('protocol'),
                    'length': pkt.get('length'),
                    'score': float(score),
                    'description': pkt.get('payload_preview') or pkt.get('protocol')
                })

        return {
            'total_packets': len(packets),
            'anomaly_count': len(anomalies),
            'anomalies': anomalies,
            'contamination': self.contamination,
        }

    def detect_session(self, session_id: int, contamination: float = 0.05) -> Dict[str, Any]:
        db: Session = SessionLocal()
        try:
            packets = db.query(Packet).filter(Packet.session_id == session_id).all()
            items = [
                {
                    'id': pkt.id,
                    'src_ip': pkt.src_ip,
                    'dst_ip': pkt.dst_ip,
                    'protocol': pkt.protocol,
                    'length': pkt.length,
                    'src_port': pkt.src_port,
                    'dst_port': pkt.dst_port,
                    'payload_preview': pkt.payload_preview,
                }
                for pkt in packets
            ]
            detector = IsolationForestAnomalyDetector(contamination=contamination)
            return detector.detect_packets(items)
        finally:
            db.close()


def _get_default_db_url() -> str:
    return os.getenv('DATABASE_URL', 'sqlite:///./backend.db')


def _main():
    parser = argparse.ArgumentParser(description='Run the anomaly detection pipeline.')
    parser.add_argument('--session-id', type=int, help='Analyze a recorded capture session')
    parser.add_argument('--contamination', type=float, default=0.05, help='Contamination ratio for isolation forest')
    args = parser.parse_args()

    if not args.session_id:
        raise SystemExit('You must provide --session-id to analyze an existing session.')

    detector = IsolationForestAnomalyDetector(contamination=args.contamination)
    result = detector.detect_session(args.session_id, contamination=args.contamination)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    _main()
