import json

import pytest

import main
from src.scanner.scan_result import FileScanOutcome, ScanResult


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("scanned", "scanned"), (2, 0, 0)),
        (("failed", "scanned"), (1, 1, 0)),
        (("skipped", "scanned"), (1, 0, 1)),
        (("scanned", "failed", "skipped"), (1, 1, 1)),
    ],
)
def test_inventory_counts_use_explicit_scan_outcomes(statuses, expected):
    paths = tuple(f"file_{index}.py" for index in range(len(statuses)))
    result = ScanResult(
        findings=[],
        outcomes=[
            FileScanOutcome(path, status)
            for path, status in zip(paths, statuses)
        ],
        discovered_files=paths,
    )

    counts = main._inventory_file_counts(result)

    assert counts == {
        "files_discovered": len(statuses),
        "files_scanned": expected[0],
        "files_failed": expected[1],
        "files_skipped": expected[2],
    }
    assert counts["files_discovered"] == (
        counts["files_scanned"] + counts["files_failed"] + counts["files_skipped"]
    )


def test_inventory_counts_reject_missing_or_duplicate_outcomes():
    with pytest.raises(ValueError, match="exactly the discovered files"):
        main._inventory_file_counts(
            ScanResult(
                findings=[],
                outcomes=[FileScanOutcome("read.py", "scanned")],
                discovered_files=("read.py", "unaccounted.py"),
            )
        )
    with pytest.raises(ValueError, match="duplicate file outcomes"):
        main._inventory_file_counts(
            ScanResult(
                findings=[],
                outcomes=[
                    FileScanOutcome("read.py", "scanned"),
                    FileScanOutcome("read.py", "failed"),
                ],
                discovered_files=("read.py",),
            )
        )


def test_pipeline_inventory_report_uses_outcome_counts(tmp_path, monkeypatch):
    paths = ("ok.py", "broken.py", "ignored.py")
    scan_result = ScanResult(
        findings=[],
        outcomes=[
            FileScanOutcome("ok.py", "scanned"),
            FileScanOutcome("broken.py", "failed", "read error"),
            FileScanOutcome("ignored.py", "skipped", "unsupported file"),
        ],
        discovered_files=paths,
    )

    class FakeScanner:
        def __init__(self, root, use_ast_for_python):
            pass

        def scan_with_outcomes(self):
            return scan_result

    class FakeBenchmark:
        def __init__(self, **kwargs):
            pass

        def run_benchmark(self, **kwargs):
            return {
                "results": {
                    "regex_only": {
                        "mean_time_ms": 1.0,
                    }
                }
            }

        def export_json(self, data, path):
            path.write_text("{}", encoding="utf-8")

        def export_csv(self, data, path):
            path.write_text("mode\n", encoding="utf-8")

        def export_markdown_summary(self, data, path):
            path.write_text("# Benchmark\n", encoding="utf-8")

    monkeypatch.setattr(main, "UnifiedScanner", FakeScanner)
    monkeypatch.setattr(main, "BenchmarkHarness", FakeBenchmark)
    monkeypatch.setattr(main, "export_platform_definitions", lambda path: None)

    main.run_full_pipeline(scan_dir=tmp_path, runs=1, output_dir=tmp_path / "out")

    report_path = tmp_path / "out" / "tables" / "inventory_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["metadata"]["total_files_scanned"] == 1
    assert report["metadata"]["files_discovered"] == 3
    assert report["metadata"]["files_failed"] == 1
    assert report["metadata"]["files_skipped"] == 1
    markdown = (tmp_path / "out" / "inventory_report.md").read_text(encoding="utf-8")
    assert "**Files Discovered:** 3" in markdown
    assert "**Files Scanned:** 1" in markdown
    assert "**Files Failed:** 1" in markdown
    assert "**Files Skipped:** 1" in markdown
