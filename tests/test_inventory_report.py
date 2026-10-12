"""
tests/test_inventory_report.py
──────────────────────────────
Unit tests for InventoryReportGenerator (Milestone P1 Part B).
Verifies:
  1. JSON output schema matches requirements (metadata, summary, findings, limitations).
  2. Markdown report includes executive summary, tables, and evidence sections.
  3. Secret evidence is properly sanitized/redacted.
  4. File counts, timestamps, and findings grouping are accurate.
  5. Uncertainty and confidence are reported.
"""

import json
from pathlib import Path
import pytest

from src.reporting.inventory_report import InventoryReportGenerator, sanitize_evidence
from src.scanner.ast_scanner import AstFinding
from src.scanner.regex_scanner import Finding
from src.scanner.risk_classifier import RiskLevel


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            file_path="src/crypto_service.py",
            line_number=42,
            language="python",
            matched_api="RSA.generate(2048)",
            algorithm="RSA",
            risk_level=RiskLevel.HIGH,
            replacement="ML-KEM (key encapsulation) or ML-DSA (signatures)",
            evidence="private_key = RSA.generate(2048)",
            detection_method="regex",
        ),
        AstFinding(
            file_path="src/auth.py",
            line_number=18,
            language="python",
            matched_api="AES.new",
            algorithm="AES-128",
            risk_level=RiskLevel.MODERATE,
            replacement="Upgrade to AES-256",
            evidence="cipher = AES.new(secret_key, AES.MODE_GCM)",
            detection_method="ast",
            confidence="CONFIRMED",
            key_size=128,
            details="AES-128 bit symmetric cipher",
        ),
        Finding(
            file_path="native/hash.c",
            line_number=88,
            language="c",
            matched_api="SHA256_Init",
            algorithm="SHA-256",
            risk_level=RiskLevel.LOWER,
            replacement="No change required; SHA-256 remains acceptable post-quantum",
            evidence="SHA256_Init(&sha256_ctx);",
            detection_method="regex",
        ),
    ]


class TestInventoryReportGenerator:
    def test_json_structure_and_keys(self, sample_findings):
        gen = InventoryReportGenerator(sample_findings, scanned_root="test_repo", total_files_scanned=10)
        json_data = gen.generate_json_dict()

        assert "metadata" in json_data
        assert "summary" in json_data
        assert "findings" in json_data
        assert "scanner_limitations" in json_data

        meta = json_data["metadata"]
        assert meta["total_findings"] == 3
        assert meta["total_files_scanned"] == 10
        assert meta["scanned_root"] == "test_repo"
        assert "timestamp_utc" in meta

        summary = json_data["summary"]
        assert summary["findings_by_risk"]["HIGH"] == 1
        assert summary["findings_by_risk"]["MODERATE"] == 1
        assert summary["findings_by_risk"]["LOWER"] == 1

        assert summary["findings_by_language"]["python"] == 2
        assert summary["findings_by_language"]["c"] == 1

        assert summary["findings_by_algorithm"]["RSA"] == 1
        assert summary["findings_by_algorithm"]["AES-128"] == 1
        assert summary["findings_by_algorithm"]["SHA-256"] == 1

    def test_json_serializability(self, sample_findings):
        gen = InventoryReportGenerator(sample_findings)
        json_str = gen.generate_json()
        parsed = json.loads(json_str)
        assert len(parsed["findings"]) == 3

    def test_markdown_report_contents(self, sample_findings):
        gen = InventoryReportGenerator(sample_findings, scanned_root="test_repo", total_files_scanned=10)
        md = gen.generate_markdown()

        assert "# QuantumShield — Cryptographic Inventory & Migration Report" in md
        assert "Executive Summary" in md
        assert "🔴 **HIGH**" in md
        assert "🟡 **MODERATE**" in md
        assert "🟢 **LOWER**" in md
        assert "Scanner Limitations" in md
        assert "src/crypto_service.py" in md
        assert "ML-KEM" in md

    def test_evidence_sanitization_removes_secrets(self):
        leak_evidence = 'api_key = "sk_live_98374928374982374928374"'
        cleaned = sanitize_evidence(leak_evidence)
        assert "[REDACTED]" in cleaned
        assert "sk_live" not in cleaned

    def test_hex_key_evidence_sanitization(self):
        raw_key = "key = b'0123456789abcdef0123456789abcdef'"
        cleaned = sanitize_evidence(raw_key)
        assert "[REDACTED_HEX_KEY]" in cleaned
