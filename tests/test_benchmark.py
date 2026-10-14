"""
tests/test_benchmark.py
────────────────────────
Unit tests for the benchmark harness, metrics calculation, and edge cases (Milestone P2).

Tests cover:
  1. Correct metric calculations (Precision, Recall, F1, TP, FP, FN) with hand-crafted values.
  2. Edge case: empty ground truth and empty findings (zero division handling).
  3. Edge case: duplicate detections on identical lines.
  4. Edge case: invalid benchmark configuration (runs < 1, nonexistent target directory).
  5. End-to-end benchmark run execution producing valid JSON, CSV, and Markdown.
  6. Environment specification capture (OS, Python version, RAM, CPU).
"""

import json
from pathlib import Path
import pytest

from src.benchmark.ground_truth import ExpectedFinding
from src.benchmark.metrics import AccuracyMetrics, evaluate_accuracy
from src.benchmark.runner import BenchmarkHarness, EnvironmentSpec
from src.scanner.regex_scanner import Finding

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestMetricCalculations:
    def test_perfect_accuracy(self):
        expected = [
            ExpectedFinding("file.py", 10, "RSA", "HIGH", True),
            ExpectedFinding("file.py", 20, "AES-128", "MODERATE", True),
        ]
        detected = [
            Finding("file.py", 10, "python", "RSA", "RSA", "HIGH", "rep", "ev"),
            Finding("file.py", 20, "python", "AES", "AES-128", "MODERATE", "rep", "ev"),
        ]
        metrics = evaluate_accuracy(detected, expected)
        assert metrics.true_positives == 2
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0

    def test_false_positive_calculation(self):
        # 1 genuine expected, but 3 detected (2 are false positives in comments/strings)
        expected = [
            ExpectedFinding("file.py", 10, "RSA", "HIGH", True),
        ]
        detected = [
            Finding("file.py", 10, "python", "RSA", "RSA", "HIGH", "rep", "ev"),
            Finding("file.py", 12, "python", "AES", "AES-128", "MODERATE", "rep", "ev"),
            Finding("file.py", 15, "python", "SHA", "SHA-256", "LOWER", "rep", "ev"),
        ]
        metrics = evaluate_accuracy(detected, expected)
        assert metrics.true_positives == 1
        assert metrics.false_positives == 2
        assert metrics.false_negatives == 0
        assert metrics.precision == round(1.0 / 3.0, 4)
        assert metrics.recall == 1.0

    def test_false_negative_calculation(self):
        # 2 expected, but only 1 detected
        expected = [
            ExpectedFinding("file.py", 10, "RSA", "HIGH", True),
            ExpectedFinding("file.py", 20, "ECDSA", "HIGH", True),
        ]
        detected = [
            Finding("file.py", 10, "python", "RSA", "RSA", "HIGH", "rep", "ev"),
        ]
        metrics = evaluate_accuracy(detected, expected)
        assert metrics.true_positives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 1
        assert metrics.precision == 1.0
        assert metrics.recall == 0.5
        assert metrics.f1_score == round(2 * (1.0 * 0.5) / 1.5, 4)

    def test_empty_inputs_no_zero_division(self):
        metrics = evaluate_accuracy([], [])
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0

    def test_empty_detected_with_expected(self):
        expected = [ExpectedFinding("file.py", 10, "RSA", "HIGH", True)]
        metrics = evaluate_accuracy([], expected)
        assert metrics.true_positives == 0
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 1
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0

    def test_duplicate_detections_on_same_line_do_not_inflate_true_positives(self):
        expected = [ExpectedFinding("file.py", 10, "RSA", "HIGH", True)]
        detected = [
            Finding("file.py", 10, "python", "RSA.gen", "RSA", "HIGH", "rep", "ev1"),
            Finding("file.py", 10, "python", "RSA.key", "RSA", "HIGH", "rep", "ev2"),
        ]
        metrics = evaluate_accuracy(detected, expected)
        assert metrics.true_positives == 1
        assert metrics.false_positives == 1


class TestBenchmarkConfigurationAndErrors:
    def test_invalid_runs_count_raises_error(self):
        with pytest.raises(ValueError, match="at least 1"):
            BenchmarkHarness(target_dir=FIXTURES_DIR, runs=0)

    def test_nonexistent_directory_raises_error(self):
        with pytest.raises(FileNotFoundError):
            BenchmarkHarness(target_dir="nonexistent_folder_xyz_123", runs=1)

    def test_environment_spec_captures_host_info(self):
        env = EnvironmentSpec.capture()
        assert env.cpu_count_logical >= 1
        assert env.total_ram_mb > 0
        assert env.python_version != ""
        assert env.os_name != ""


class TestBenchmarkExecutionAndExports:
    def test_benchmark_runs_and_produces_valid_structure(self, tmp_path):
        harness = BenchmarkHarness(target_dir=FIXTURES_DIR, runs=2)
        results = harness.run_benchmark(include_platform_b=True)

        assert "metadata" in results
        assert "results" in results
        assert "comparison" in results

        reg = results["results"]["regex_only"]
        ast = results["results"]["ast_enriched"]
        pb = results["results"]["platform_b"]

        assert reg["runs"] == 2
        assert ast["runs"] == 2
        assert pb["runs"] == 2
        assert len(reg["run_times_ms"]) == 2
        assert len(ast["run_times_ms"]) == 2
        assert len(pb["run_times_ms"]) == 2
        assert reg["mean_time_ms"] > 0
        assert ast["mean_time_ms"] > 0
        assert pb["mean_time_ms"] > 0

        # Export test files
        json_file = tmp_path / "results.json"
        csv_file = tmp_path / "results.csv"
        md_file = tmp_path / "summary.md"

        harness.export_json(results, json_file)
        harness.export_csv(results, csv_file)
        harness.export_markdown_summary(results, md_file)

        assert json_file.exists()
        assert csv_file.exists()
        assert md_file.exists()

        # Validate JSON content
        parsed = json.loads(json_file.read_text(encoding="utf-8"))
        assert "regex_only" in parsed["results"]
        assert "platform_b" in parsed["results"]

        # Validate CSV content
        csv_content = csv_file.read_text(encoding="utf-8")
        assert "regex_only" in csv_content
        assert "ast_enriched" in csv_content
        assert "platform_b" in csv_content

        # Validate Markdown content
        md_content = md_file.read_text(encoding="utf-8")
        assert "QuantumShield" in md_content
        assert "Accuracy Comparison" in md_content

    def test_subset_scan_ground_truth_filtered_correctly(self, tmp_path):
        """Scanning only snippet_rsa.py should not produce FN from other fixture files."""
        import shutil
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", tmp_path / "snippet_rsa.py")

        from src.benchmark.ground_truth import MOCK_FIXTURE_GROUND_TRUTH
        rsa_expected = MOCK_FIXTURE_GROUND_TRUTH["snippet_rsa.py"]

        harness = BenchmarkHarness(target_dir=tmp_path, runs=2)
        results = harness.run_benchmark(include_platform_b=False, include_platform_d=False)

        ast_acc = results["results"]["ast_enriched"]["accuracy"]
        # total_expected should match only the RSA fixture expectations
        assert ast_acc["total_expected"] == len(rsa_expected)
        # False negatives cannot exceed the number of expected items in the file
        assert ast_acc["false_negatives"] <= len(rsa_expected)

    def test_unrelated_directory_ground_truth_empty_and_metrics_accurate(self, tmp_path):
        """Scanning a directory with unrelated files produces zero expected findings and valid metrics."""
        (tmp_path / "app.py").write_text("x = 10\nprint(x)\n", encoding="utf-8")

        harness = BenchmarkHarness(target_dir=tmp_path, runs=1)
        results = harness.run_benchmark(include_platform_b=False, include_platform_d=False)

        ast_acc = results["results"]["ast_enriched"]["accuracy"]
        assert ast_acc["total_expected"] == 0
        assert ast_acc["total_detected"] == 0
        assert ast_acc["true_positives"] == 0
        assert ast_acc["false_positives"] == 0
        assert ast_acc["false_negatives"] == 0
        assert ast_acc["precision"] == 1.0
        assert ast_acc["recall"] == 1.0
        assert ast_acc["f1_score"] == 1.0

    def test_duplicate_filenames_across_subdirectories_evaluated(self, tmp_path):
        """Duplicate fixture filenames in subdirectories each receive expected findings."""
        import shutil
        d1 = tmp_path / "module_a"
        d2 = tmp_path / "module_b"
        d1.mkdir()
        d2.mkdir()
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", d1 / "snippet_rsa.py")
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", d2 / "snippet_rsa.py")

        from src.benchmark.ground_truth import MOCK_FIXTURE_GROUND_TRUTH
        rsa_count = len(MOCK_FIXTURE_GROUND_TRUTH["snippet_rsa.py"])

        harness = BenchmarkHarness(target_dir=tmp_path, runs=1)
        results = harness.run_benchmark(include_platform_b=False, include_platform_d=False)

        ast_acc = results["results"]["ast_enriched"]["accuracy"]
        assert ast_acc["total_expected"] == rsa_count * 2
        assert ast_acc["true_positives"] == rsa_count * 2
        assert ast_acc["false_negatives"] == 0
