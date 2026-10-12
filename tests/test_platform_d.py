"""
tests/test_platform_d.py
─────────────────────────
Unit tests for Milestone P3 (Platform D modular architecture and benchmarking).

Tests cover:
  1. Valid Platform D configuration initialization and execution.
  2. Invalid configuration validation (negative memory limit, workers < 1, invalid strategy).
  3. Boundary conditions: large file exceeding memory ceiling triggers limitation finding without crashing.
  4. Platform definitions export to JSON.
  5. Platform profile retrieval by ID.
  6. Integration with BenchmarkHarness (comparing regex, AST, and Platform D).
"""

import json
from pathlib import Path
import pytest

from src.benchmark.runner import BenchmarkHarness
from src.platforms.platform_config import (
    PLATFORM_D,
    PlatformProfile,
    export_platform_definitions,
    get_platform_profile,
)
from src.platforms.platform_d_scanner import PlatformDScanner

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

    def test_memory_ceiling_exceeded_guard(self, tmp_path):
        # Create a tiny custom profile with a 1 MB memory limit
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

        scanner = PlatformDScanner(root=tmp_path, profile=strict_profile)
        findings = scanner.scan()

        assert len(findings) == 1
        assert findings[0].matched_api == "<MemoryCeilingExceeded>"
        assert findings[0].detection_method == "platform_d_guard"
        assert "exceeds" in findings[0].evidence

    def test_benchmark_harness_integration_with_platform_d(self, tmp_path):
        harness = BenchmarkHarness(target_dir=FIXTURES_DIR, runs=2)
        results = harness.run_benchmark(include_platform_d=True)

        assert "platform_d" in results["results"]
        pd_result = results["results"]["platform_d"]
        assert pd_result["runs"] == 2
        assert pd_result["mean_time_ms"] > 0
        assert pd_result["accuracy"]["precision"] > 0

        # Check export
        csv_file = tmp_path / "bench.csv"
        md_file = tmp_path / "bench.md"
        harness.export_csv(results, csv_file)
        harness.export_markdown_summary(results, md_file)

        assert "platform_d" in csv_file.read_text(encoding="utf-8")
        assert "Platform D" in md_file.read_text(encoding="utf-8")
