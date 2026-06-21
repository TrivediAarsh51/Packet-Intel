"""
tests/test_dpi.py
=================
Unit tests for the Module 2 DPI engines:
  - Engine 4: Payload signature matching (regex + Luhn CC validation)
  - Engine 5: Shannon entropy analysis (with TLS suppression)
  - Engine 6: Botnet / C2 IP and domain blacklist

Tests are written to run without a live database or PCAP file.
All engines are exercised through ThreatDetector.analyze_packet() or
directly via the threat_intel helpers.
"""
from __future__ import annotations

import math
import os
import struct
import sys

import pytest

# ---------------------------------------------------------------------------
# Ensure the repo root is on the path when running from the project root.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app.core.threat_intel import (
    BOTNET_DOMAIN_BLACKLIST,
    BOTNET_IP_BLACKLIST,
    EXFILTRATION_SIGNATURES,
    calculate_entropy,
    _luhn_check,
)
from backend.app.core.parser import ThreatDetector, _is_tls_record


# ===========================================================================
# Helpers
# ===========================================================================

def _make_pkt(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "TCP",
    dns_query: str = "",
    length: int = 100,
) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "dns_query": dns_query,
        "length": length,
    }


def _alerts_of_type(alerts: list, alert_type: str) -> list:
    return [a for a in alerts if a["alert_type"] == alert_type]


def _run(pkt: dict, payload: bytes | None = None) -> list:
    """Run all ThreatDetector engines and return the full alert list."""
    detector = ThreatDetector()
    return detector.analyze_packet(pkt, raw_payload=payload)


# ===========================================================================
# Luhn validation tests
# ===========================================================================

class TestLuhnValidation:
    def test_valid_visa(self):
        assert _luhn_check("4532015112830366") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5425233430109903") is True

    def test_valid_amex(self):
        # 378282246310005 is the canonical AMEX test number from the Luhn spec
        assert _luhn_check("378282246310005") is True

    def test_valid_amex_2(self):
        assert _luhn_check("371449635398431") is True

    def test_invalid_number_fails(self):
        # One digit off the valid Visa above
        assert _luhn_check("4532015112830367") is False

    def test_too_short_fails(self):
        assert _luhn_check("123456789") is False

    def test_all_zeros_passes_luhn(self):
        # 0000...0 has a Luhn sum of 0 (0 mod 10 == 0) — mathematically valid.
        # The CC regex won't match this anyway (no IIN prefix match).
        assert _luhn_check("0000000000000000") is True


# ===========================================================================
# Engine 4: Payload signature tests
# ===========================================================================

class TestSignatureCreditCard:
    """Credit card detection with Luhn validation."""

    def test_valid_visa_in_payload(self):
        # 4532015112830366 — passes Luhn
        payload = b"user=alice&card=4532015112830366&cvv=123"
        alerts = _run(_make_pkt(), payload)
        cc_alerts = _alerts_of_type(alerts, "data_exfiltration")
        assert cc_alerts, "Expected data_exfiltration alert for valid Visa CC"
        assert any("credit_card" in a["evidence"] for a in cc_alerts)

    def test_invalid_luhn_no_alert(self):
        # 4532015112830367 — fails Luhn (last digit changed)
        payload = b"card=4532015112830367"
        alerts = _run(_make_pkt(), payload)
        cc_alerts = _alerts_of_type(alerts, "data_exfiltration")
        assert not any(
            "credit_card" in a.get("evidence", "") for a in cc_alerts
        ), "Invalid Luhn CC should NOT trigger an alert"

    def test_mastercard_in_payload(self):
        # 5425233430109903 — valid Mastercard
        payload = b"payment_card: 5425233430109903"
        alerts = _run(_make_pkt(), payload)
        cc_alerts = _alerts_of_type(alerts, "data_exfiltration")
        assert cc_alerts, "Expected data_exfiltration for valid Mastercard"

    def test_redaction_applied(self):
        """Sensitive matched values should be redacted in the alert description."""
        payload = b"card=4532015112830366"
        alerts = _run(_make_pkt(), payload)
        cc_alerts = _alerts_of_type(alerts, "data_exfiltration")
        for a in cc_alerts:
            if "credit_card" in a.get("evidence", ""):
                # Full card number must NOT appear verbatim in description
                assert "4532015112830366" not in a["description"]


class TestSignatureSSN:
    def test_ssn_in_payload(self):
        payload = b"ssn=123-45-6789 name=John Doe"
        alerts = _run(_make_pkt(), payload)
        ssn_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "ssn" in a.get("evidence", "")
        ]
        assert ssn_alerts, "Expected data_exfiltration alert for SSN"

    def test_non_ssn_format_no_alert(self):
        # Wrong format: missing hyphens
        payload = b"ref=123456789"
        alerts = _run(_make_pkt(), payload)
        ssn_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "ssn" in a.get("evidence", "")
        ]
        assert not ssn_alerts


class TestSignatureCredentials:
    def test_password_equals(self):
        payload = b"password=SuperSecret99!"
        alerts = _run(_make_pkt(), payload)
        cred_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "hardcoded_credential" in a.get("evidence", "")
        ]
        assert cred_alerts

    def test_passwd_colon(self):
        payload = b"passwd: mysecretpassword"
        alerts = _run(_make_pkt(), payload)
        cred_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "hardcoded_credential" in a.get("evidence", "")
        ]
        assert cred_alerts

    def test_no_false_positive_short_value(self):
        # "pwd=abc" — 3 chars is below the min 4-char threshold in the regex
        payload = b"pwd=abc"
        alerts = _run(_make_pkt(), payload)
        cred_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "hardcoded_credential" in a.get("evidence", "")
        ]
        assert not cred_alerts


class TestSignatureAWSKey:
    def test_aws_key_in_payload(self):
        payload = b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        alerts = _run(_make_pkt(), payload)
        aws_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "aws_access_key" in a.get("evidence", "")
        ]
        assert aws_alerts

    def test_non_akia_no_alert(self):
        payload = b"key_id=BKIAIOSFODNN7EXAMPLE"
        alerts = _run(_make_pkt(), payload)
        aws_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "aws_access_key" in a.get("evidence", "")
        ]
        assert not aws_alerts


class TestSignaturePrivateKey:
    def test_rsa_private_key_header(self):
        payload = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        alerts = _run(_make_pkt(), payload)
        pk_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "private_key" in a.get("evidence", "")
        ]
        assert pk_alerts

    def test_openssh_private_key_header(self):
        payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC..."
        alerts = _run(_make_pkt(), payload)
        pk_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "private_key" in a.get("evidence", "")
        ]
        assert pk_alerts


class TestSignatureBearerToken:
    def test_bearer_in_header(self):
        payload = b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        alerts = _run(_make_pkt(), payload)
        token_alerts = [
            a for a in _alerts_of_type(alerts, "data_exfiltration")
            if "bearer_token" in a.get("evidence", "")
        ]
        assert token_alerts


# ===========================================================================
# Shannon entropy tests
# ===========================================================================

class TestEntropyFunction:
    def test_all_same_bytes_zero_entropy(self):
        data = b"\x00" * 256
        assert calculate_entropy(data) == pytest.approx(0.0)

    def test_uniform_distribution_max_entropy(self):
        # One of every byte value — maximum entropy ≈ 8.0
        data = bytes(range(256))
        entropy = calculate_entropy(data)
        assert entropy == pytest.approx(8.0, abs=0.01)

    def test_plaintext_low_entropy(self):
        text = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" * 10
        entropy = calculate_entropy(text)
        assert entropy < 5.0, f"Plaintext entropy should be < 5.0, got {entropy:.2f}"

    def test_random_data_high_entropy(self):
        import os as _os
        data = _os.urandom(512)
        entropy = calculate_entropy(data)
        assert entropy >= 6.5, f"Random data entropy should be ≥ 6.5, got {entropy:.2f}"

    def test_empty_data_zero(self):
        assert calculate_entropy(b"") == 0.0


class TestEntropyAlerts:
    """Test engine 5 via ThreatDetector.analyze_packet()."""

    def test_high_entropy_fires_encrypted_payload(self):
        # Use a deterministic max-entropy payload: all 256 byte values exactly once,
        # repeated to reach 512 bytes.  Entropy = exactly 8.0 bits/byte, guaranteed
        # on every run -- no os.urandom() variance near the 7.2 threshold.
        # First byte is 0x00, which is NOT in _TLS_CONTENT_TYPES {20,21,22,23},
        # so _is_tls_record() always returns False.
        payload = bytes(range(256)) * 2   # 512 bytes, entropy == 8.0
        alerts = _run(_make_pkt(protocol="HTTP"), payload)
        enc_alerts = _alerts_of_type(alerts, "encrypted_payload")
        assert enc_alerts, "Max-entropy non-TLS payload should trigger encrypted_payload alert"

    def test_low_entropy_no_alert(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" * 5
        alerts = _run(_make_pkt(protocol="HTTP"), payload)
        enc_alerts = _alerts_of_type(alerts, "encrypted_payload")
        comp_alerts = _alerts_of_type(alerts, "compressed_payload")
        assert not enc_alerts and not comp_alerts

    def test_too_small_payload_no_alert(self):
        # 32 bytes -- below _ENTROPY_MIN_BYTES (64), must never fire regardless of entropy
        import os as _os
        payload = _os.urandom(32)
        alerts = _run(_make_pkt(), payload)
        enc_alerts = _alerts_of_type(alerts, "encrypted_payload")
        assert not enc_alerts

    def test_tls_handshake_suppressed(self):
        """Confirmed TLS record should NOT trigger entropy alert."""
        # Content type 22 (handshake), version 0x03 0x03 (TLS 1.2), followed by
        # a max-entropy body so the entropy check would otherwise fire.
        tls_header = bytes([22, 3, 3, 0, 255])
        body = bytes(range(256)) * 2  # deterministic high-entropy body
        tls_payload = tls_header + body
        alerts = _run(_make_pkt(dst_port=443, protocol="HTTPS"), tls_payload)
        enc_alerts = _alerts_of_type(alerts, "encrypted_payload")
        assert not enc_alerts, (
            "Confirmed TLS record should be suppressed, NOT trigger encrypted_payload"
        )

    def test_high_entropy_on_port_443_non_tls_fires(self):
        """High-entropy payload on port 443 that is NOT a TLS record SHOULD alert.

        Port 443 alone must not suppress the alert -- only a confirmed TLS
        record (content-type + version magic bytes) triggers suppression.
        """
        # Deterministic max-entropy payload; first byte 0x00 is definitively NOT
        # in _TLS_CONTENT_TYPES, so _is_tls_record() always returns False.
        payload = bytes(range(256)) * 2   # 512 bytes, entropy == 8.0
        alerts = _run(_make_pkt(dst_port=443, protocol="HTTPS"), payload)
        enc_alerts = _alerts_of_type(alerts, "encrypted_payload")
        assert enc_alerts, (
            "High-entropy non-TLS payload on port 443 should STILL trigger alert "
            "(port 443 != TLS)"
        )


class TestTLSRecordDetection:
    """Unit tests for the _is_tls_record() heuristic."""

    def test_tls_12_handshake(self):
        payload = bytes([22, 3, 3, 0, 200]) + b"\x00" * 200
        assert _is_tls_record(payload) is True

    def test_tls_10_handshake(self):
        payload = bytes([22, 3, 1, 0, 100]) + b"\x00" * 100
        assert _is_tls_record(payload) is True

    def test_tls_app_data(self):
        payload = bytes([23, 3, 3, 0, 100]) + b"\x00" * 100
        assert _is_tls_record(payload) is True

    def test_random_payload_not_tls(self):
        import os as _os
        payload = bytes([0x00]) + _os.urandom(50)
        assert _is_tls_record(payload) is False

    def test_http_payload_not_tls(self):
        payload = b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        assert _is_tls_record(payload) is False

    def test_too_short_not_tls(self):
        assert _is_tls_record(b"\x16\x03") is False


# ===========================================================================
# Engine 6: Botnet / C2 blacklist tests
# ===========================================================================

class TestBotnetIPBlacklist:
    def test_blacklisted_dst_ip(self):
        pkt = _make_pkt(dst_ip="185.220.101.45")
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert c2_alerts, "Blacklisted dst_ip should trigger botnet_c2 alert"
        assert any("destination" in a["description"] for a in c2_alerts)

    def test_blacklisted_src_ip(self):
        pkt = _make_pkt(src_ip="194.165.16.78", dst_ip="10.0.0.5")
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert c2_alerts, "Blacklisted src_ip should trigger botnet_c2 alert"
        assert any("source" in a["description"] for a in c2_alerts)

    def test_clean_ip_no_alert(self):
        pkt = _make_pkt(src_ip="192.168.1.1", dst_ip="8.8.8.8")
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert not c2_alerts, "Google DNS 8.8.8.8 should NOT trigger botnet alert"

    def test_localhost_no_alert(self):
        pkt = _make_pkt(src_ip="127.0.0.1", dst_ip="127.0.0.1")
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert not c2_alerts

    def test_cloudflare_dns_no_alert(self):
        pkt = _make_pkt(dst_ip="1.1.1.1")
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert not c2_alerts

    def test_all_blacklisted_ips_trigger(self):
        """Every IP in BOTNET_IP_BLACKLIST should fire an alert."""
        for ip in BOTNET_IP_BLACKLIST:
            pkt = _make_pkt(dst_ip=ip)
            alerts = _run(pkt)
            c2_alerts = _alerts_of_type(alerts, "botnet_c2")
            assert c2_alerts, f"{ip} should trigger botnet_c2 alert"


class TestBotnetDomainBlacklist:
    def test_blacklisted_dns_query(self):
        pkt = _make_pkt(
            protocol="DNS",
            dst_port=53,
            dns_query="update-service.ddns.net",
        )
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert c2_alerts, "Blacklisted DNS query should trigger botnet_c2 alert"

    def test_domain_with_trailing_dot(self):
        """DNS queries often have a trailing dot — normalisation must handle this."""
        pkt = _make_pkt(
            protocol="DNS",
            dns_query="c2panel.duckdns.org.",   # trailing dot
        )
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert c2_alerts, "Trailing dot in DNS query should still match blacklist"

    def test_domain_case_insensitive(self):
        pkt = _make_pkt(
            protocol="DNS",
            dns_query="UPDATE-SERVICE.DDNS.NET",
        )
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert c2_alerts, "Domain matching should be case-insensitive"

    def test_clean_domain_no_alert(self):
        pkt = _make_pkt(
            protocol="DNS",
            dns_query="www.google.com",
        )
        alerts = _run(pkt)
        c2_alerts = _alerts_of_type(alerts, "botnet_c2")
        assert not c2_alerts

    def test_all_blacklisted_domains_trigger(self):
        """Every domain in BOTNET_DOMAIN_BLACKLIST should fire an alert."""
        for domain in BOTNET_DOMAIN_BLACKLIST:
            pkt = _make_pkt(protocol="DNS", dns_query=domain)
            alerts = _run(pkt)
            c2_alerts = _alerts_of_type(alerts, "botnet_c2")
            assert c2_alerts, f"{domain} should trigger botnet_c2 alert"


# ===========================================================================
# Alert severity and structure tests
# ===========================================================================

class TestAlertStructure:
    """Ensure all new alert types produce well-formed dicts."""

    REQUIRED_KEYS = {"alert_type", "severity", "src_ip", "dst_ip", "description", "evidence"}

    def _assert_well_formed(self, alert: dict):
        for key in self.REQUIRED_KEYS:
            assert key in alert, f"Alert missing required key '{key}': {alert}"
        assert alert["severity"] in ("critical", "high", "medium", "low"), (
            f"Invalid severity: {alert['severity']}"
        )

    def test_data_exfiltration_alert_structure(self):
        payload = b"password=hunter2_is_my_pw"
        alerts = _run(_make_pkt(), payload)
        for a in _alerts_of_type(alerts, "data_exfiltration"):
            self._assert_well_formed(a)

    def test_botnet_c2_alert_structure(self):
        pkt = _make_pkt(dst_ip="185.220.101.45")
        alerts = _run(pkt)
        for a in _alerts_of_type(alerts, "botnet_c2"):
            self._assert_well_formed(a)
            assert a["severity"] == "critical"

    def test_encrypted_payload_alert_structure(self):
        import os as _os
        payload = _os.urandom(256)
        alerts = _run(_make_pkt(protocol="HTTP"), payload)
        for a in _alerts_of_type(alerts, "encrypted_payload"):
            self._assert_well_formed(a)
            assert a["severity"] == "medium"

    def test_compressed_payload_alert_structure(self):
        # Craft a moderately-entropy payload (e.g., zlib-compressed text)
        import zlib
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" * 20
        payload = zlib.compress(raw)
        if len(payload) >= 64:
            alerts = _run(_make_pkt(protocol="HTTP"), payload)
            for a in _alerts_of_type(alerts, "compressed_payload"):
                self._assert_well_formed(a)
                assert a["severity"] == "low"


if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
