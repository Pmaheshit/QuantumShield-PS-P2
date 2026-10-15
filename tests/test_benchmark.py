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
from src.benchmark.metrics import (
    AccuracyMetrics,
    ScanCoverage,
    ScanCoverageError,
    evaluate_accuracy,
)
from src.benchmark.runner import BenchmarkHarness, EnvironmentSpec
from src.scanner.regex_scanner import Finding
from src.scanner.regex_scanner import RegexScanner
from src.scanner.scan_result import FileScanOutcome, ScanResult
from src.benchmark.runner import _scan_coverage

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
        assert metrics.coverage_status == "unverified"

    @pytest.mark.parametrize(
        ("detected_algorithm", "expected_algorithm"),
        [
            ("ECDSA", "ECDH"),
            ("ECDH", "ECC"),
            ("ECC", "ECDSA"),
        ],
    )
    def test_distinct_ecc_algorithms_do_not_match(
        self, detected_algorithm: str, expected_algorithm: str
    ):
        detected = [
            Finding(
                "file.py", 10, "python", "operation", detected_algorithm,
                "HIGH", "rep", "ev",
            )
        ]
        expected = [
            ExpectedFinding("file.py", 10, expected_algorithm, "HIGH", True)
        ]

        metrics = evaluate_accuracy(detected, expected)

        assert metrics.true_positives == 0
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1

    def test_family_match_mode_is_not_available_for_primary_metrics(self):
        with pytest.raises(ValueError, match="expected one of"):
            evaluate_accuracy([], [], match_mode="family")

    def test_empty_scan_coverage_is_rejected(self):
        with pytest.raises(ScanCoverageError, match="no source files were discovered"):
            evaluate_accuracy([], [], coverage=ScanCoverage(files_discovered=0, files_scanned=0))

    def test_scan_coverage_requires_one_explicit_outcome_per_discovered_file(self):
        with pytest.raises(ScanCoverageError, match="outcomes do not match"):
            evaluate_accuracy(
                [],
                [],
                coverage=ScanCoverage(
                    files_discovered=1,
                    files_scanned=1,
                ),
            )

    def test_duplicate_outcomes_are_rejected(self):
        findings = [Finding("same.py", 1, "python", "RSA", "RSA", "HIGH", "rep", "ev")]
        outcomes = [
            FileScanOutcome("same.py", "scanned"),
            FileScanOutcome("same.py", "scanned"),
        ]
        with pytest.raises(ScanCoverageError, match="duplicate"):
            _scan_coverage(ScanResult(findings, outcomes, ("same.py",)))

    def test_outcomes_must_match_discovered_file_paths(self):
        scan_result = ScanResult(
            findings=[],
            outcomes=[FileScanOutcome("other.py", "scanned")],
            discovered_files=("discovered.py",),
        )

        with pytest.raises(ScanCoverageError, match="exactly the discovered files"):
            _scan_coverage(scan_result)

    def test_same_basename_in_different_directories_does_not_match(self, tmp_path):
        module_a = tmp_path / "module_a"
        module_b = tmp_path / "module_b"
        module_a.mkdir()
        module_b.mkdir()
        (module_a / "snippet_rsa.py").write_text(
            "rsa.generate_private_key()\n",
            encoding="utf-8",
        )
        (module_b / "snippet_rsa.py").write_text("pass\n", encoding="utf-8")

        detected = [
            Finding(
                "module_a/snippet_rsa.py",
                1,
                "python",
                "RSA",
                "RSA",
                "HIGH",
                "rep",
                "ev",
            )
        ]
        expected = [
            ExpectedFinding(
                "module_b/snippet_rsa.py",
                1,
                "RSA",
                "HIGH",
                is_genuine_call=True,
            )
        ]
        coverage = ScanCoverage(
            files_discovered=2,
            files_scanned=2,
            outcomes=(
                FileScanOutcome("module_a/snippet_rsa.py", "scanned"),
                FileScanOutcome("module_b/snippet_rsa.py", "scanned"),
            ),
        )

        metrics = evaluate_accuracy(detected, expected, coverage=coverage)

        assert metrics.true_positives == 0
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1

    def test_basename_fallback_requires_unique_covered_file(self):
        detected = [
            Finding(
                "module_a/snippet_rsa.py",
                1,
                "python",
                "RSA",
                "RSA",
                "HIGH",
                "rep",
                "ev",
            )
        ]
        expected = [
            ExpectedFinding("snippet_rsa.py", 1, "RSA", "HIGH", is_genuine_call=True)
        ]
        coverage = ScanCoverage(
            files_discovered=1,
            files_scanned=1,
            outcomes=(FileScanOutcome("module_a/snippet_rsa.py", "scanned"),),
        )

        metrics = evaluate_accuracy(detected, expected, coverage=coverage)

        assert metrics.true_positives == 1
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0

    def test_dot_path_does_not_match_arbitrary_expected_filename(self):
        detected = [
            Finding(".", 1, "python", "RSA", "RSA", "HIGH", "rep", "ev")
        ]
        expected = [
            ExpectedFinding("snippet_rsa.py", 1, "RSA", "HIGH", is_genuine_call=True)
        ]
        coverage = ScanCoverage(
            files_discovered=1,
            files_scanned=1,
            outcomes=(FileScanOutcome("snippet_rsa.py", "scanned"),),
        )

        metrics = evaluate_accuracy(detected, expected, coverage=coverage)

        assert metrics.true_positives == 0
        assert metrics.false_positives == 1
        assert metrics.false_negatives == 1

    def test_multiple_findings_for_one_file_count_as_one_scanned_file(self):
        findings = [
            Finding("same.py", 1, "python", "RSA", "RSA", "HIGH", "rep", "ev1"),
            Finding("same.py", 2, "python", "ECDSA", "ECDSA", "HIGH", "rep", "ev2"),
        ]
        coverage = _scan_coverage(
            ScanResult(
                findings,
                [FileScanOutcome("same.py", "scanned")],
                ("same.py",),
            )
        )

        assert coverage.files_discovered == 1
        assert coverage.files_scanned == 1
        assert coverage.files_failed == 0
        assert coverage.files_skipped == 0

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
    def test_benchmark_rejects_empty_source_directory(self, tmp_path):
        harness = BenchmarkHarness(
            target_dir=tmp_path,
            ground_truth={},
            runs=1,
        )

        with pytest.raises(ScanCoverageError, match="no source files were discovered"):
            harness.run_benchmark(include_platform_b=False, include_platform_d=False)

    def test_regex_only_benchmark_ignores_python_comments_and_strings(self, tmp_path):
        (tmp_path / "documentation.py").write_text(
            "# AES-128 was used in an older implementation.\n"
            'message = "SHA256 is mentioned in this documentation."\n',
            encoding="utf-8",
        )
        harness = BenchmarkHarness(
            target_dir=tmp_path,
            ground_truth={},
            runs=1,
        )

        results = harness.run_benchmark(
            include_platform_b=False,
            include_platform_d=False,
        )
        regex_result = results["results"]["regex_only"]

        assert regex_result["findings_count"] == 0
        assert regex_result["accuracy"]["false_positives"] == 0
        assert regex_result["scan_coverage"]["files_discovered"] == 1
        assert regex_result["scan_coverage"]["files_scanned"] == 1
        assert regex_result["scan_coverage"]["files_failed"] == 0
        assert regex_result["scan_coverage"]["files_skipped"] == 0

    def test_read_failure_is_counted_without_consulting_findings(self, tmp_path, monkeypatch):
        file_paths = [tmp_path / f"module_{index}.py" for index in range(3)]
        for path in file_paths:
            path.write_text("value = 1\n", encoding="utf-8")

        scanner = RegexScanner(root=tmp_path)
        original_read = scanner._read_source

        def read_source(path: Path) -> str:
            if path == file_paths[1]:
                raise OSError("deterministic read failure")
            return original_read(path)

        monkeypatch.setattr(scanner, "_read_source", read_source)
        scan_result = scanner.scan_with_outcomes()
        coverage = _scan_coverage(
            ScanResult(
                findings=[],
                outcomes=scan_result.outcomes,
                discovered_files=scan_result.discovered_files,
            )
        )
        metrics = evaluate_accuracy([], [], coverage=coverage)

        assert coverage.files_discovered == 3
        assert coverage.files_scanned == 2
        assert coverage.files_failed == 1
        assert coverage.files_skipped == 0
        assert sum(
            (coverage.files_scanned, coverage.files_failed, coverage.files_skipped)
        ) == coverage.files_discovered
        assert metrics.coverage_status == "partial"
        failed = [outcome for outcome in coverage.outcomes if outcome.status == "failed"]
        assert len(failed) == 1
        assert failed[0].file_path == "module_1.py"
        assert "deterministic read failure" in failed[0].reason


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
        assert "files_discovered" in csv_content
        assert "coverage_status" in csv_content

        # Validate Markdown content
        md_content = md_file.read_text(encoding="utf-8")
        assert "QuantumShield" in md_content
        assert "Accuracy Comparison" in md_content
        assert "Files Scanned" in md_content

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
        assert ast_acc["coverage_status"] == "verified"

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
