"""
tests/test_platform_d.py
─────────────────────────
Unit tests for Milestone P3 (Platform D modular architecture and benchmarking).

Tests cover:
  1. Valid Platform D configuration initialization and execution.
  2. Invalid configuration validation (negative memory limit, workers < 1, invalid strategy).
  3. Boundary conditions: large file exceeding input-size limit triggers guard finding without crashing.
  4. Platform definitions export to JSON.
  5. Platform profile retrieval by ID.
  6. Integration with BenchmarkHarness (comparing regex, AST, Platform B, and Platform D).
  7. high_risk_priority selective strategy: asymmetric files use AST; symmetric-only use regex.
  8. Ground-truth filtering for subset scans, unrelated directories, and duplicate basenames.
"""

import json
import shutil
from pathlib import Path
import pytest

from src.benchmark.runner import BenchmarkHarness, _filter_ground_truth_for_dir
from src.benchmark.ground_truth import ExpectedFinding, get_all_ground_truth
from src.platforms.platform_config import (
    PLATFORM_D,
    PlatformProfile,
    export_platform_definitions,
    get_platform_profile,
)
from src.platforms.platform_d_scanner import (
    PlatformDScanner,
    _file_text_contains_high_risk,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestPlatformConfiguration:
    def test_platform_d_profile_validity(self):
        PLATFORM_D.validate()
        assert PLATFORM_D.platform_id == "platform_d"
        assert PLATFORM_D.memory_limit_mb == 64
        assert PLATFORM_D.scan_strategy == "high_risk_priority"

    def test_invalid_workers_raises_error(self):
        invalid_profile = PlatformProfile(
            platform_id="test_invalid",
            name="Invalid",
            category="custom",
            description="desc",
            max_workers=0,
        )
        with pytest.raises(ValueError, match="max_workers must be >= 1"):
            invalid_profile.validate()

    def test_invalid_memory_limit_raises_error(self):
        invalid_profile = PlatformProfile(
            platform_id="test_invalid",
            name="Invalid",
            category="custom",
            description="desc",
            memory_limit_mb=-10,
        )
        with pytest.raises(ValueError, match="memory_limit_mb must be > 0"):
            invalid_profile.validate()

    def test_invalid_strategy_raises_error(self):
        invalid_profile = PlatformProfile(
            platform_id="test_invalid",
            name="Invalid",
            category="custom",
            description="desc",
            scan_strategy="unknown_strategy_xyz",
        )
        with pytest.raises(ValueError, match="Unsupported scan_strategy"):
            invalid_profile.validate()

    def test_get_platform_profile_success_and_failure(self):
        prof = get_platform_profile("platform_d")
        assert prof.platform_id == "platform_d"

        with pytest.raises(KeyError, match="Unknown platform ID"):
            get_platform_profile("platform_nonexistent_xyz")

    def test_export_platform_definitions(self, tmp_path):
        export_platform_definitions(tmp_path)
        for pid in ("platform_a", "platform_b", "platform_c", "platform_d"):
            p_file = tmp_path / f"{pid}.json"
            assert p_file.exists()
            data = json.loads(p_file.read_text(encoding="utf-8"))
            assert data["platform_id"] == pid


class TestPlatformDScannerExecution:
    def test_platform_d_scan_runs_across_fixtures(self):
        scanner = PlatformDScanner(root=FIXTURES_DIR)
        findings = scanner.scan()
        assert len(findings) > 0
        algos = {f.algorithm for f in findings}
        assert "RSA" in algos

    def test_input_size_limit_exceeded_guard(self, tmp_path):
        """File exceeding the input-size limit emits a guard finding and is skipped."""
        strict_profile = PlatformProfile(
            platform_id="platform_d_micro",
            name="Micro Platform D",
            category="custom_innovation",
            description="Micro limit test",
            memory_limit_mb=1,
            scan_strategy="high_risk_priority",
        )

        # Create a large dummy file (1.5 MB)
        big_file = tmp_path / "giant_code.py"
        big_file.write_text("# padding\n" + "x = 1\n" * 200000, encoding="utf-8")
        (tmp_path / "normal.py").write_text("x = 1\n", encoding="utf-8")

        scanner = PlatformDScanner(root=tmp_path, profile=strict_profile)
        findings = scanner.scan()

        assert len(findings) == 1
        assert findings[0].matched_api == "<InputSizeLimitExceeded>"
        assert findings[0].detection_method == "platform_d_guard"
        assert "exceeds" in findings[0].evidence

        scan_result = scanner.scan_with_outcomes()
        outcomes = {outcome.file_path: outcome for outcome in scan_result.outcomes}
        assert len(outcomes) == 2
        assert outcomes["giant_code.py"].status == "skipped"
        assert outcomes["normal.py"].status == "scanned"
        assert len(scan_result.outcomes) == 2
        from src.benchmark.runner import _scan_coverage
        from src.benchmark.metrics import evaluate_accuracy

        coverage = _scan_coverage(scan_result)
        metrics = evaluate_accuracy([], [], coverage=coverage)
        assert coverage.files_discovered == (
            coverage.files_scanned + coverage.files_failed + coverage.files_skipped
        )
        assert metrics.coverage_status == "partial"

    def test_stat_oserror_is_recorded_as_failed_outcome(self, tmp_path, monkeypatch):
        failed_file = tmp_path / "unavailable.py"
        succeeded_file = tmp_path / "available.py"
        failed_file.write_text("x = 1\n", encoding="utf-8")
        succeeded_file.write_text("x = 2\n", encoding="utf-8")
        scanner = PlatformDScanner(root=tmp_path)
        monkeypatch.setattr(
            scanner,
            "_iter_source_files",
            lambda: iter([(failed_file, "python"), (succeeded_file, "python")]),
        )

        def file_size(path: Path) -> int:
            if path == failed_file:
                raise OSError("deterministic stat failure")
            return path.stat().st_size

        monkeypatch.setattr(scanner, "_file_size_bytes", file_size)
        scan_result = scanner.scan_with_outcomes()

        outcomes = {outcome.file_path: outcome for outcome in scan_result.outcomes}
        assert len(outcomes) == 2
        assert outcomes["unavailable.py"].status == "failed"
        assert "deterministic stat failure" in outcomes["unavailable.py"].reason
        assert outcomes["available.py"].status == "scanned"

    def test_unexpected_file_processing_exception_propagates(
        self, tmp_path, monkeypatch
    ):
        source_file = tmp_path / "source.py"
        source_file.write_text("x = 1\n", encoding="utf-8")
        scanner = PlatformDScanner(root=tmp_path)

        def fail_processing(file_path: Path):
            raise RuntimeError("unexpected scanner defect")

        monkeypatch.setattr(scanner, "_scan_python_file_with_outcome", fail_processing)

        with pytest.raises(RuntimeError, match="unexpected scanner defect"):
            scanner.scan_with_outcomes()

    def test_benchmark_harness_integration_with_platform_b_and_d(self, tmp_path):
        harness = BenchmarkHarness(target_dir=FIXTURES_DIR, runs=2)
        results = harness.run_benchmark(include_platform_d=True, include_platform_b=True)

        assert "platform_b" in results["results"], "Platform B result missing"
        assert "platform_d" in results["results"], "Platform D result missing"

        pb_result = results["results"]["platform_b"]
        assert pb_result["runs"] == 2
        assert pb_result["mean_time_ms"] > 0

        pd_result = results["results"]["platform_d"]
        assert pd_result["runs"] == 2
        assert pd_result["mean_time_ms"] > 0
        assert pd_result["accuracy"]["precision"] >= 0

        # Export test
        csv_file = tmp_path / "bench.csv"
        md_file = tmp_path / "bench.md"
        harness.export_csv(results, csv_file)
        harness.export_markdown_summary(results, md_file)

        csv_text = csv_file.read_text(encoding="utf-8")
        assert "platform_b" in csv_text
        assert "platform_d" in csv_text

        md_text = md_file.read_text(encoding="utf-8")
        assert "Platform B" in md_text
        assert "Platform D" in md_text

    def test_platform_b_config_disclosed_in_benchmark_metadata(self):
        harness = BenchmarkHarness(target_dir=FIXTURES_DIR, runs=2)
        results = harness.run_benchmark(include_platform_d=False, include_platform_b=True)
        status = results["platform_configurations_status"]["Platform_B"]
        # Verify the status note discloses that no OS virtualisation is applied
        assert "max_workers=1" in status
        assert "memory_limit_mb=512" in status
        assert "not" in status.lower() or "no" in status.lower()


class TestHighRiskPriorityStrategy:
    """Tests for the selective AST strategy in high_risk_priority mode."""

    def test_quick_pattern_detects_rsa(self):
        assert _file_text_contains_high_risk("key = RSA.generate(2048)")

    def test_quick_pattern_detects_ecdsa(self):
        assert _file_text_contains_high_risk("sig = ECDSA.sign()")

    def test_quick_pattern_detects_ec_generate(self):
        assert _file_text_contains_high_risk("ec.generate_private_key(ec.SECP256R1())")

    def test_quick_pattern_detects_asymmetric_import(self):
        assert _file_text_contains_high_risk(
            "from cryptography.hazmat.primitives.asymmetric import rsa"
        )

    def test_quick_pattern_not_triggered_by_symmetric_only(self):
        symmetric_only = (
            "from Crypto.Cipher import AES\n"
            "import hashlib\n"
            "cipher = AES.new(key, AES.MODE_GCM)\n"
            "h = hashlib.sha256()\n"
        )
        assert not _file_text_contains_high_risk(symmetric_only)

    def test_quick_pattern_ignores_comments_and_strings(self):
        text = (
            "# RSA.generate(2048) was used in an older implementation.\n"
            'message = "ECDSA is mentioned in this documentation."\n'
        )
        assert not _file_text_contains_high_risk(text)

    def test_asymmetric_file_gets_ast_findings(self, tmp_path):
        """Python file with RSA keyword must receive AST scan (detection_method='ast')."""
        rsa_file = tmp_path / "has_rsa.py"
        rsa_file.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "from cryptography.hazmat.backends import default_backend\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())\n",
            encoding="utf-8",
        )

        profile = PlatformProfile(
            platform_id="pd_test",
            name="Test",
            category="custom_innovation",
            description="test",
            memory_limit_mb=64,
            scan_strategy="high_risk_priority",
        )
        scanner = PlatformDScanner(root=tmp_path, profile=profile)
        findings = scanner.scan()

        # Should find RSA and detection_method should be 'ast'
        rsa_findings = [f for f in findings if f.algorithm == "RSA"]
        assert len(rsa_findings) >= 1
        assert all(f.detection_method == "ast" for f in rsa_findings)

    def test_symmetric_only_file_gets_regex_findings(self, tmp_path):
        """Python file with only AES/SHA must use regex fast path (detection_method='regex')."""
        aes_file = tmp_path / "only_aes.py"
        aes_file.write_text(
            "from Crypto.Cipher import AES\n"
            "cipher = AES.new(key, AES.MODE_GCM)\n",
            encoding="utf-8",
        )

        profile = PlatformProfile(
            platform_id="pd_test",
            name="Test",
            category="custom_innovation",
            description="test",
            memory_limit_mb=64,
            scan_strategy="high_risk_priority",
        )
        scanner = PlatformDScanner(root=tmp_path, profile=profile)
        findings = scanner.scan()

        aes_findings = [f for f in findings if "AES" in f.algorithm]
        assert len(aes_findings) >= 1
        assert all(f.detection_method == "regex" for f in aes_findings)

    def test_symmetric_fast_path_ignores_crypto_mentions_in_comments_and_strings(
        self, tmp_path
    ):
        source = (
            "# AES-128 was used in an older implementation.\n"
            'message = "SHA256 is mentioned in this documentation."\n'
        )
        (tmp_path / "documentation.py").write_text(source, encoding="utf-8")
        scanner = PlatformDScanner(root=tmp_path)

        assert scanner.scan() == []


class TestGroundTruthFiltering:
    """Tests for _filter_ground_truth_for_dir (subset scan, unrelated dir, duplicate basenames)."""

    def test_full_fixtures_dir_includes_all_known_files(self):
        gt = get_all_ground_truth()
        expected = _filter_ground_truth_for_dir(gt, FIXTURES_DIR)
        # All fixture files in MOCK_FIXTURE_GROUND_TRUTH are present in FIXTURES_DIR
        all_expected = [ef for file_findings in gt.values() for ef in file_findings]
        assert len(expected) == len(all_expected)

    def test_empty_dir_returns_no_expected_findings(self, tmp_path):
        gt = get_all_ground_truth()
        expected = _filter_ground_truth_for_dir(gt, tmp_path)
        assert expected == []

    def test_unrelated_dir_returns_no_expected_findings(self, tmp_path):
        """A directory with no fixture files produces zero expected findings."""
        (tmp_path / "unrelated.py").write_text("x = 1\n", encoding="utf-8")
        gt = get_all_ground_truth()
        expected = _filter_ground_truth_for_dir(gt, tmp_path)
        assert expected == []

    def test_subset_dir_returns_only_relevant_findings(self, tmp_path):
        """Copy only snippet_rsa.py; filter should return only RSA expected findings."""
        src = FIXTURES_DIR / "snippet_rsa.py"
        shutil.copy(src, tmp_path / "snippet_rsa.py")

        gt = get_all_ground_truth()
        expected = _filter_ground_truth_for_dir(gt, tmp_path)
        file_names = {e.file_name for e in expected}
        assert file_names == {"snippet_rsa.py"}
        assert expected == gt["snippet_rsa.py"]

    def test_unrelated_subdir_file_with_fixture_basename_is_not_labeled(self, tmp_path):
        """A basename match alone does not transfer fixture labels."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "snippet_rsa.py").write_text("pass\n", encoding="utf-8")

        gt = get_all_ground_truth()
        expected = _filter_ground_truth_for_dir(gt, tmp_path)
        assert expected == []

    def test_unrelated_root_file_with_fixture_basename_is_not_labeled(self, tmp_path):
        (tmp_path / "snippet_rsa.py").write_text("pass\n", encoding="utf-8")

        expected = _filter_ground_truth_for_dir(get_all_ground_truth(), tmp_path)

        assert expected == []

    def test_duplicate_nested_basenames_do_not_both_inherit_root_fixture_labels(
        self, tmp_path
    ):
        for directory in ("module_a", "module_b"):
            nested = tmp_path / directory
            nested.mkdir()
            shutil.copy(FIXTURES_DIR / "snippet_rsa.py", nested / "snippet_rsa.py")

        expected = _filter_ground_truth_for_dir(get_all_ground_truth(), tmp_path)

        assert expected == []

    def test_nested_relative_path_association_is_exact(self, tmp_path):
        module_a = tmp_path / "module_a"
        module_b = tmp_path / "module_b"
        module_a.mkdir()
        module_b.mkdir()
        (module_a / "snippet_rsa.py").write_text("pass\n", encoding="utf-8")
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", module_b / "snippet_rsa.py")
        ground_truth = {
            "module_a/snippet_rsa.py": [
                ExpectedFinding("module_a/snippet_rsa.py", 1, "RSA", "HIGH", True)
            ]
        }

        expected = _filter_ground_truth_for_dir(ground_truth, tmp_path)

        assert [(finding.file_name, finding.line_number) for finding in expected] == [
            ("module_a/snippet_rsa.py", 1)
        ]

    def test_duplicate_filenames_in_multiple_subdirs_evaluated_correctly(self, tmp_path):
        """When the same fixture filename exists in two subdirs, both are evaluated."""
        sub1 = tmp_path / "sub1"
        sub2 = tmp_path / "sub2"
        sub1.mkdir()
        sub2.mkdir()
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", sub1 / "snippet_rsa.py")
        shutil.copy(FIXTURES_DIR / "snippet_rsa.py", sub2 / "snippet_rsa.py")

        gt = get_all_ground_truth()
        expected_per_file = len(gt["snippet_rsa.py"])
        explicit_gt = {
            "sub1/snippet_rsa.py": gt["snippet_rsa.py"],
            "sub2/snippet_rsa.py": gt["snippet_rsa.py"],
        }
        expected = _filter_ground_truth_for_dir(explicit_gt, tmp_path)
        assert len(expected) == expected_per_file * 2
        file_names = {e.file_name for e in expected}
        assert file_names == {"sub1/snippet_rsa.py", "sub2/snippet_rsa.py"}

        # Now run benchmark harness on this duplicate directory
        harness = BenchmarkHarness(
            target_dir=tmp_path, ground_truth=explicit_gt, runs=1
        )
        results = harness.run_benchmark(include_platform_b=False, include_platform_d=False)
        ast_acc = results["results"]["ast_enriched"]["accuracy"]
        assert ast_acc["total_expected"] == expected_per_file * 2
        assert ast_acc["true_positives"] == expected_per_file * 2
        assert ast_acc["false_negatives"] == 0
