"""
threat_intel.py
===============
Centralised threat-intelligence data and helper functions for the
Packet-Intel DPI engine.

Design note
-----------
All data lives here so that parser.py stays focused on packet mechanics.
Future migration paths:
  - Load signatures from a YAML/JSON rule file
  - Pull blacklists from a SQLite threat-intel table
  - Consume live TAXII 2.1 / AlienVault OTX feeds

Nothing in this module imports from the rest of the application so it
can be tested and reused in isolation.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# 1.  Data-exfiltration / credential-leak signature rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureRule:
    """A single compiled DPI signature rule."""
    name: str                    # Alert sub-type identifier (machine-readable)
    pattern: re.Pattern          # Pre-compiled regex for performance
    severity: str                # 'critical' | 'high' | 'medium' | 'low'
    description_tmpl: str        # Human-readable description (may use {match})
    alert_type: str = "data_exfiltration"


# Credit card helper --------------------------------------------------------

def _luhn_check(number_str: str) -> bool:
    """
    Validate a digit string with the Luhn algorithm.
    Returns True if the number passes Luhn validation.
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13:
        return False
    # Double every second digit from the right (excluding the check digit)
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:          # odd position = double
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class _CreditCardPattern:
    """
    Wrapper around a regex that applies Luhn validation as a post-filter.
    Matches the interface of re.Pattern closely enough for our SignatureRule usage.
    """
    _RAW_PATTERN = re.compile(
        r'\b(?:'
        r'4[0-9]{12}(?:[0-9]{3})?'          # Visa (13 or 16 digits)
        r'|5[1-5][0-9]{14}'                  # Mastercard
        r'|3[47][0-9]{13}'                   # Amex (15 digits)
        r'|6011[0-9]{12}'                    # Discover
        r'|3(?:0[0-5]|[68][0-9])[0-9]{11}'  # Diners Club
        r'|(?:2131|1800|35\d{3})\d{11}'     # JCB
        r')\b',
        re.ASCII
    )

    def search(self, text: str) -> Optional[re.Match]:
        """Return the first Luhn-valid match, or None."""
        for m in self._RAW_PATTERN.finditer(text):
            digits_only = re.sub(r'\D', '', m.group())
            if _luhn_check(digits_only):
                return m
        return None

    def findall(self, text: str) -> List[str]:
        """Return all Luhn-valid matches."""
        return [
            m.group()
            for m in self._RAW_PATTERN.finditer(text)
            if _luhn_check(re.sub(r'\D', '', m.group()))
        ]


# Compiled signature rules --------------------------------------------------

EXFILTRATION_SIGNATURES: List[SignatureRule] = [
    SignatureRule(
        name="credit_card",
        pattern=_CreditCardPattern(),          # type: ignore[arg-type]
        severity="critical",
        description_tmpl="Credit card number detected in payload: {match}",
    ),
    SignatureRule(
        name="ssn",
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        severity="critical",
        description_tmpl="US Social Security Number detected in payload: {match}",
    ),
    SignatureRule(
        name="hardcoded_credential",
        pattern=re.compile(
            r'(?i)(?:password|passwd|pwd|pass|secret|credentials?)\s*[=:]\s*\S{4,}',
            re.IGNORECASE
        ),
        severity="high",
        description_tmpl="Hardcoded credential pattern detected in payload: {match}",
    ),
    SignatureRule(
        name="aws_access_key",
        pattern=re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        severity="critical",
        description_tmpl="AWS Access Key ID detected in payload: {match}",
    ),
    SignatureRule(
        name="bearer_token",
        pattern=re.compile(
            r'(?i)(?:bearer|token|api[_-]?key)\s*[=:\s]\s*[A-Za-z0-9\-_\.]{20,}',
            re.IGNORECASE
        ),
        severity="high",
        description_tmpl="Bearer / API token detected in payload: {match}",
    ),
    SignatureRule(
        name="basic_auth",
        pattern=re.compile(
            r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}',
            re.IGNORECASE
        ),
        severity="high",
        description_tmpl="HTTP Basic Auth header detected in cleartext payload: {match}",
    ),
    SignatureRule(
        name="private_key",
        pattern=re.compile(
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE
        ),
        severity="critical",
        description_tmpl="Private key material detected in payload: {match}",
    ),
]


# ---------------------------------------------------------------------------
# 2.  Shannon entropy
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy (bits per byte) of *data*.

    Returns a float in [0.0, 8.0].
    0.0  → all bytes identical (e.g., b'\\x00' * N)
    8.0  → uniform distribution of all 256 byte values (perfect randomness)

    Thresholds used by the ThreatDetector:
        entropy < 5.0   → normal structured/plaintext traffic
        5.0 ≤ entropy < 7.2  → compressed or partially encrypted
        entropy ≥ 7.2   → strongly encrypted, packed, or obfuscated payload
    """
    if not data:
        return 0.0
    length = len(data)
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# 3.  Botnet / C2 blacklists  (mock — for demonstration)
# ---------------------------------------------------------------------------

# NOTE: These are FICTITIOUS entries used only for demonstrating the detection
#       engine.  They do NOT represent actual threat intelligence at a specific
#       point in time.  Replace / augment with a live feed in production.

BOTNET_IP_BLACKLIST: frozenset[str] = frozenset({
    # --- Tor exit nodes (commonly abused) ---
    "185.220.101.45",
    "185.220.101.32",
    "185.220.101.58",
    # --- Emotet C2 infrastructure (mock) ---
    "194.165.16.78",
    "194.165.16.89",
    # --- Cobalt Strike beacon servers (mock) ---
    "45.142.212.100",
    "45.142.212.101",
    # --- Formbook / XLoader C2 (mock) ---
    "91.92.109.204",
    # --- Mirai-variant botnet (mock) ---
    "198.199.76.165",
    # --- QakBot / Qbot C2 (mock) ---
    "185.193.38.14",
    # --- RedLine Stealer panel (mock) ---
    "146.70.78.115",
    # --- Brute-force / mass-scanner node (mock) ---
    "141.98.10.183",
    # --- IcedID / Bokbot C2 (mock) ---
    "194.36.189.58",
    # --- AgentTesla exfil server (mock) ---
    "45.95.147.207",
    # --- BazarLoader C2 (mock) ---
    "194.31.98.124",
    # --- AsyncRAT / Remote-access trojan (mock) ---
    "77.91.68.238",
    # --- ZLoader banking trojan (mock) ---
    "185.234.218.222",
    # --- NanoCore / NetWire RAT (mock) ---
    "172.104.196.60",
    "185.162.235.100",
    # --- njRAT / Bladabindi C2 (mock) ---
    "176.97.75.85",
    # --- AZORult stealer (mock) ---
    "194.4.51.131",
})

BOTNET_DOMAIN_BLACKLIST: frozenset[str] = frozenset({
    # --- Dynamic-DNS C2 domains (mock) ---
    "update-service.ddns.net",
    "windowscheck.hopto.org",
    "c2panel.duckdns.org",
    "tracker.no-ip.biz",
    "keylogger.serveftp.com",
    "darknode.zapto.org",
    "remote-admin.link",
    # --- Typosquat / lookalike infra (mock) ---
    "ms-update-core.info",
    "telemetry-cdn.com",
    "cdn-analytics.ru",
    # --- Generic C2 TLDs (mock) ---
    "secure-gate.biz",
    "srv-control.xyz",
    "api-gateway.top",
    "bot-hub.live",
    "payload-server.me",
})
