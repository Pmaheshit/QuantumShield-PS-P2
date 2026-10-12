"""
src/reporting/inventory_report.py
─────────────────────────────────
Inventory report generator for QuantumShield PS-P2.

Generates machine-readable JSON and human-readable Markdown reports from scanner findings.
Meets all PS-P2 requirements:
  • Scan summary and scanned file counts
  • Findings grouped by language and algorithm
  • Risk categories and explanations
  • File path, line number, and evidence (sanitized, no secrets exposed)
  • Migration recommendations and uncertainty/confidence metrics
  • Scanner limitations and ISO 8601 timestamps
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..scanner.regex_scanner import Finding
from ..scanner.risk_classifier import RiskClassifier, RiskLevel


# Secret redaction patterns: sanitize potential secrets, keys, or tokens in source lines
_SECRET_REDACT_PATTERNS = [
    (re.compile(r"""(?i)(\b(?:api_key|secret|password|token|auth|private_key|secret_key)\s*=\s*['"])([^'"]+)(['"])"""), r"\1[REDACTED]\3"),
    (re.compile(r"""(?i)(['"](?:key|secret|password|token|auth)['"]?\s*[:=]\s*['"])([^'"]+)(['"])"""), r"\1[REDACTED]\3"),
    (re.compile(r"""b['"][0-9a-fA-F]{32,}['"]"""), r"b'[REDACTED_HEX_KEY]'"),
    (re.compile(r"""b['"][A-Za-z0-9+/=]{44,}['"]"""), r"b'[REDACTED_BASE64_KEY]'"),
]



def sanitize_evidence(evidence: str) -> str:
    """Sanitize source code line to ensure no sensitive secrets or keys are leaked."""
    sanitized = evidence.strip()
    for pattern, repl in _SECRET_REDACT_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized


class InventoryReportGenerator:
    """
    Generates structured JSON and comprehensive Markdown reports from static findings.
    """

    LIMITATIONS = [
        "Static analysis only: runtime-computed variables, dynamic class loaders, or network-retrieved keys cannot be evaluated statically.",
        "Regex detection on Java and C may flag cryptographic identifiers in inactive comments or string literals.",
        "AST scanning applies strictly to valid Python syntax; unparseable Python files report syntax error findings.",
        "Conservative estimation: unknown AES key lengths default to AES-128 (MODERATE risk) per PS-P2 guidance.",
    ]

    def __init__(self, findings: Sequence[Finding], scanned_root: str = ".", total_files_scanned: int = 0) -> None:
        self.findings = list(findings)
        self.scanned_root = scanned_root
        self.total_files_scanned = total_files_scanned
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.classifier = RiskClassifier()

    def generate_json_dict(self) -> dict[str, Any]:
        """Construct the complete, machine-readable inventory dictionary."""
        # Categorize findings
        by_risk: dict[str, int] = {RiskLevel.HIGH: 0, RiskLevel.MODERATE: 0, RiskLevel.LOWER: 0, RiskLevel.UNKNOWN: 0}
        by_language: dict[str, int] = {}
        by_algorithm: dict[str, int] = {}

        findings_list: list[dict[str, Any]] = []

        for f in self.findings:
            risk = getattr(f, "risk_level", RiskLevel.UNKNOWN)
            by_risk[risk] = by_risk.get(risk, 0) + 1

            lang = getattr(f, "language", "unknown")
            by_language[lang] = by_language.get(lang, 0) + 1

            algo = getattr(f, "algorithm", "UNKNOWN")
            by_algorithm[algo] = by_algorithm.get(algo, 0) + 1

            sanitized_ev = sanitize_evidence(getattr(f, "evidence", ""))

            f_dict: dict[str, Any] = {
                "file_path": getattr(f, "file_path", ""),
                "line_number": getattr(f, "line_number", 0),
                "language": lang,
                "matched_api": getattr(f, "matched_api", ""),
                "algorithm": algo,
                "risk_level": risk,
                "replacement": getattr(f, "replacement", ""),
                "evidence": sanitized_ev,
                "detection_method": getattr(f, "detection_method", "regex"),
                "confidence": getattr(f, "confidence", "INFERRED" if getattr(f, "detection_method", "") == "regex" else "CONFIRMED"),
            }

            # If AST specific fields exist
            if hasattr(f, "key_size") and f.key_size is not None:
                f_dict["key_size"] = f.key_size
            if hasattr(f, "curve") and f.curve is not None:
                f_dict["curve"] = f.curve
            if hasattr(f, "parameters") and f.parameters:
                f_dict["parameters"] = f.parameters
            if hasattr(f, "details") and f.details:
                f_dict["details"] = f.details

            findings_list.append(f_dict)

        return {
            "metadata": {
                "tool": "QuantumShield PS-P2 Cryptographic Inventory & Migration Planner",
                "version": "1.0.0",
                "timestamp_utc": self.timestamp,
                "scanned_root": self.scanned_root,
                "total_files_scanned": self.total_files_scanned,
                "total_findings": len(self.findings),
            },
            "summary": {
                "findings_by_risk": by_risk,
                "findings_by_language": by_language,
                "findings_by_algorithm": by_algorithm,
            },
            "findings": findings_list,
            "scanner_limitations": self.LIMITATIONS,
        }

    def generate_json(self, indent: int = 2) -> str:
        """Return stable, serialized JSON report."""
        return json.dumps(self.generate_json_dict(), indent=indent, ensure_ascii=False)

    def generate_markdown(self) -> str:
        """Return clean, professional Markdown report suitable for evaluation."""
        report = self.generate_json_dict()
        summary = report["summary"]
        meta = report["metadata"]

        lines: list[str] = []
        lines.append("# QuantumShield — Cryptographic Inventory & Migration Report")
        lines.append("")
        lines.append(f"**Generated:** `{meta['timestamp_utc']}`<br>")
        lines.append(f"**Target Directory:** `{meta['scanned_root']}`<br>")
        lines.append(f"**Files Scanned:** {meta['total_files_scanned']}<br>")
        lines.append(f"**Total Cryptographic Findings:** {meta['total_findings']}")
        lines.append("")

        # ── Executive Summary ──
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append("| Risk Level | Count | Threat Rationale | Migration Priority |")
        lines.append("| :--- | :---: | :--- | :--- |")
        lines.append(f"| 🔴 **HIGH** | {summary['findings_by_risk'].get('HIGH', 0)} | Vulnerable to Shor's Algorithm (RSA / ECC broken) | Immediate (Phase 1 Target) |")
        lines.append(f"| 🟡 **MODERATE** | {summary['findings_by_risk'].get('MODERATE', 0)} | Key space halved by Grover's Algorithm (AES-128) | Medium (Upgrade to AES-256) |")
        lines.append(f"| 🟢 **LOWER** | {summary['findings_by_risk'].get('LOWER', 0)} | Quantum-resistant symmetric baseline (AES-256, SHA-256) | Low / Retain current baseline |")
        lines.append(f"| ⚪ **UNKNOWN** | {summary['findings_by_risk'].get('UNKNOWN', 0)} | Unrecognized / Unparseable source element | Requires manual review |")
        lines.append("")

        # ── Language & Algorithm breakdown ──
        lines.append("## 2. Findings Breakdown")
        lines.append("")
        lines.append("### By Language")
        lines.append("")
        lines.append("| Language | Detected Findings |")
        lines.append("| :--- | :---: |")
        for lang, count in sorted(summary["findings_by_language"].items()):
            lines.append(f"| `{lang}` | {count} |")
        lines.append("")

        lines.append("### By Algorithm")
        lines.append("")
        lines.append("| Algorithm | Risk Level | Findings Count | Recommended Replacement |")
        lines.append("| :--- | :--- | :---: | :--- |")
        for algo, count in sorted(summary["findings_by_algorithm"].items()):
            profile = self.classifier.get_profile(algo)
            lines.append(f"| **{algo}** | `{profile.level}` | {count} | {profile.replacement} |")
        lines.append("")

        # ── Detailed Findings ──
        lines.append("## 3. Inventory Details")
        lines.append("")
        lines.append("| # | Location | Language | Algorithm | Risk | Detection | Confidence | Replacement / Action |")
        lines.append("| -: | :--- | :---: | :--- | :---: | :---: | :---: | :--- |")

        for idx, f in enumerate(report["findings"], 1):
            path_loc = f"`{f['file_path']}:{f['line_number']}`"
            method = f['detection_method']
            conf = f.get('confidence', 'INFERRED')
            lines.append(
                f"| {idx} | {path_loc} | `{f['language']}` | **{f['algorithm']}** | `{f['risk_level']}` | `{method}` | `{conf}` | {f['replacement']} |"
            )

        lines.append("")
        lines.append("### Evidence & Code Context")
        lines.append("")
        for idx, f in enumerate(report["findings"], 1):
            lines.append(f"#### Finding #{idx}: {f['algorithm']} in `{f['file_path']}:{f['line_number']}`")
            lines.append(f"- **Matched API:** `{f['matched_api']}`")
            lines.append(f"- **Detection Method:** `{f['detection_method']}` (Confidence: `{f['confidence']}`)")
            if "key_size" in f and f["key_size"]:
                lines.append(f"- **Static Key Size:** {f['key_size']} bits")
            if "curve" in f and f["curve"]:
                lines.append(f"- **Elliptic Curve:** `{f['curve']}`")
            if "details" in f and f["details"]:
                lines.append(f"- **Analysis Note:** {f['details']}")
            lines.append("- **Evidence Snippet:**")
            lines.append("```")
            lines.append(f"{f['evidence']}")
            lines.append("```")
            lines.append(f"- **Migration Recommendation:** {f['replacement']}")
            lines.append("")

        # ── Limitations ──
        lines.append("## 4. Scanner Limitations & Operational Assumptions")
        lines.append("")
        for item in self.LIMITATIONS:
            lines.append(f"- {item}")
        lines.append("")

        return "\n".join(lines)
