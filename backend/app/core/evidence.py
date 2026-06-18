import os
import hashlib
import json
import uuid
import time
from typing import Optional


def _chain_log_path():
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'storage'))
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, 'evidence_chain.log')


def _last_hash(chain_path: str) -> Optional[str]:
    if not os.path.exists(chain_path):
        return None
    try:
        with open(chain_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            # read last line
            pos = size - 1
            while pos > 0 and f.read(1) != b"\n":
                pos -= 1
                f.seek(pos, os.SEEK_SET)
            if pos == 0:
                f.seek(0)
            last = f.readline().decode('utf-8').strip()
            if not last:
                return None
            entry = json.loads(last)
            return entry.get('entry_hash')
    except Exception:
        return None


def _hash_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def seal_evidence(file_path: str, metadata: dict) -> dict:
    """Create a chain entry for evidence. If file exists, use its SHA256; otherwise hash metadata+filename+timestamp."""
    chain_path = _chain_log_path()
    prev = _last_hash(chain_path)
    ts = int(time.time())
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            file_hash = _hash_bytes(f.read())
    else:
        file_hash = _hash_bytes((os.path.basename(file_path) + json.dumps(metadata, sort_keys=True) + str(ts)).encode('utf-8'))

    entry = {
        'evidence_id': str(uuid.uuid4()),
        'file_name': os.path.basename(file_path),
        'file_hash': file_hash,
        'metadata': metadata,
        'timestamp': ts,
        'prev_hash': prev,
    }
    # compute entry hash
    entry_serial = json.dumps(entry, sort_keys=True).encode('utf-8')
    entry_hash = _hash_bytes(entry_serial)
    entry['entry_hash'] = entry_hash

    # append to chain log as single JSON line
    with open(chain_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + "\n")

    return entry


def verify_evidence(evidence_id: str) -> dict:
    chain_path = _chain_log_path()
    if not os.path.exists(chain_path):
        return {'found': False, 'reason': 'no_chain'}
    with open(chain_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if entry.get('evidence_id') == evidence_id:
                # verify file hash if file still available
                file_name = entry.get('file_name')
                # search in uploads
                possible = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'uploads', file_name))
                if os.path.exists(possible):
                    with open(possible, 'rb') as fh:
                        current_hash = _hash_bytes(fh.read())
                    ok = current_hash == entry.get('file_hash')
                    return {'found': True, 'entry': entry, 'file_present': True, 'file_matches': ok}
                else:
                    return {'found': True, 'entry': entry, 'file_present': False, 'file_matches': False}
    return {'found': False}
