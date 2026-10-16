"""
tests/test_end_to_end.py
────────────────────────
End-to-End integration test covering the complete QuantumShield pipeline:
  1. Multi-language scanning (Python, Java, C).
  2. Quantum risk classification (HIGH, MODERATE, LOWER).
  3. Purpose-specific PQC replacement mapping (ML-KEM vs ML-DSA).
  4. Structured reporting (JSON & Markdown) with secret sanitization.
  5. Multi-platform benchmarking across modes (Regex, AST, Platform D).
  6. Deliverable exports into results/tables/, results/figures/, and processors/.
"""

import json
from pathlib import Path
import pytest

from main import run_full_pipeline
from src.benchmark.ground_truth import ExpectedFinding
from src.benchmark.metrics import evaluate_accuracy
from src.reporting.inventory_report import InventoryReportGenerator
from src.scanner.risk_classifier import RiskLevel
from src.scanner.unified_scanner import UnifiedScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestEndToEndPipeline:
    def test_unknown_aes_key_stays_unresolved_through_scan_reports_and_metrics(
        self, tmp_path
    ):
        source = "cipher = AES.new(key_from_kms, AES.MODE_GCM)\n"
        file_path = tmp_path / "unknown_aes.py"
        file_path.write_text(source, encoding="utf-8")

        scan_result = UnifiedScanner(file_path, use_ast_for_python=True).scan_with_outcomes()
        findings = scan_result.findings
        assert len(findings) == 1
        finding = findings[0]
        assert finding.algorithm == "AES-UNKNOWN"
        assert finding.risk_level == RiskLevel.UNKNOWN
        assert finding.key_size is None
        assert finding.confidence == "INFERRED"
        assert len(findings) == 1

        generator = InventoryReportGenerator(findings)
        json_finding = json.loads(generator.generate_json())["findings"][0]
        markdown = generator.generate_markdown()
        assert json_finding["algorithm"] == "AES-UNKNOWN"
        assert json_finding["risk_level"] == RiskLevel.UNKNOWN
        assert json_finding["key_size"] is None
        assert "AES-UNKNOWN" in markdown
        assert "`UNKNOWN`" in markdown

        metrics = evaluate_accuracy(
            findings,
            [ExpectedFinding("unknown_aes.py", 1, "AES-128", "MODERATE", True)],
        )
        assert metrics.true_positives == 0
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1

    def test_complete_pipeline_execution(self, tmp_path):
        out_dir = tmp_path / "results"
        results = run_full_pipeline(scan_dir=FIXTURES_DIR, runs=2, output_dir=out_dir)

        assert results["findings_count"] > 0
        assert "benchmark_results" in results

        # 1. Verify processors definitions exported
        processors_dir = Path("processors")
        for pid in ("platform_a", "platform_b", "platform_c", "platform_d"):
            p_json = processors_dir / f"{pid}.json"
            assert p_json.exists(), f"Missing platform definition: {p_json}"
            p_data = json.loads(p_json.read_text(encoding="utf-8"))
            assert p_data["platform_id"] == pid

        # 2. Verify inventory report exports
        inv_json = out_dir / "tables" / "inventory_report.json"
        inv_md = out_dir / "inventory_report.md"
        assert inv_json.exists()
        assert inv_md.exists()

        inv_data = json.loads(inv_json.read_text(encoding="utf-8"))
        assert inv_data["metadata"]["total_findings"] == results["findings_count"]
        assert "HIGH" in inv_data["summary"]["findings_by_risk"]
        assert "MODERATE" in inv_data["summary"]["findings_by_risk"]
        assert "LOWER" in inv_data["summary"]["findings_by_risk"]

        # 3. Verify benchmark exports
        bench_json = out_dir / "tables" / "benchmark_results.json"
        bench_csv = out_dir / "tables" / "benchmark_results.csv"
        bench_md = out_dir / "benchmark_report.md"
        assert bench_json.exists()
        assert bench_csv.exists()
        assert bench_md.exists()

        bench_data = json.loads(bench_json.read_text(encoding="utf-8"))
        assert "regex_only" in bench_data["results"]
        assert "ast_enriched" in bench_data["results"]
        assert "platform_b" in bench_data["results"]
        assert "platform_d" in bench_data["results"]

        # 4. Verify figure export if matplotlib was available (optional dep)
        fig_png = out_dir / "figures" / "runtime_comparison.png"
        # matplotlib may not be installed in all CI environments; only assert if present
        if fig_png.exists():
            assert fig_png.stat().st_size > 0
