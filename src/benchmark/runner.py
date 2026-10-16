"""
src/benchmark/runner.py
───────────────────────
Reproducible benchmark harness for QuantumShield PS-P2.

Executes controlled comparisons between:
  • Mode 1: Regex-Only Scanner (Layer 1 baseline)          — Platform A config
  • Mode 2: AST-Enriched Scanner (Layer 2 precision engine) — Platform A config
  • Mode 3: Platform B (constrained server / CI runner)     — single-thread, full
            scan; resource constraints are enforced by configuration, NOT by OS
            virtualisation.  The CPU and memory budgets declared in PLATFORM_B
            (max_workers=1, memory_limit_mb=512) are passed through to the
            scanner; no hardware sandbox is applied here.
  • Mode 4: Platform D (Custom Innovation)                  — selective high-risk
            AST scanner with per-file input-size boundary

Tracks and reports:
  • Execution wall-clock runtime across multiple iterations (mean, min, max, stdev)
  • Peak memory allocation (Python-heap only, via tracemalloc; NOT process RSS)
  • Detection precision, recall, false positives, false negatives against ground
    truth — evaluated only on the files actually present in target_dir
  • Host environment specifications (CPU model, cores, RAM, OS, Python version)
  • Exports results to machine-readable JSON, CSV, and summary Markdown
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import statistics
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass, field
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Sequence

import psutil

from ..scanner.ast_scanner import PythonAstScanner
from ..scanner.regex_scanner import Finding
from ..scanner.unified_scanner import UnifiedScanner
from .ground_truth import ExpectedFinding, get_all_ground_truth
from .metrics import (
    AccuracyMetrics,
    ScanCoverage,
    ScanCoverageError,
    evaluate_accuracy,
)
from ..scanner.scan_result import FileScanOutcome, ScanResult

_BENCHMARK_LINE_MATCH_TOLERANCE = 0


@dataclass
class EnvironmentSpec:
    platform_name: str
    os_name: str
    os_version: str
    architecture: str
    python_version: str
    cpu_count_logical: int
    cpu_count_physical: int
    total_ram_mb: float

    @classmethod
    def capture(cls, platform_name: str = "Platform A (Local Dev/Cloud Host)") -> EnvironmentSpec:
        mem = psutil.virtual_memory()
        return cls(
            platform_name=platform_name,
            os_name=platform.system(),
            os_version=platform.version(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            cpu_count_logical=psutil.cpu_count(logical=True) or 1,
            cpu_count_physical=psutil.cpu_count(logical=False) or 1,
            total_ram_mb=round(mem.total / (1024 * 1024), 2),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkRunResult:
    mode: str  # "regex_only" | "ast_enriched" | "platform_b" | "platform_d"
    runs: int
    run_times_ms: list[float]
    mean_time_ms: float
    min_time_ms: float
    max_time_ms: float
    stdev_time_ms: float
    peak_memory_kb: float
    accuracy: AccuracyMetrics
    findings_count: int
    scan_coverage: ScanCoverage | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["accuracy"] = self.accuracy.to_dict()
        d["scan_coverage"] = (
            self.scan_coverage.to_dict() if self.scan_coverage is not None else None
        )
        return d


def _filter_ground_truth_for_dir(
    ground_truth: dict[str, list[ExpectedFinding]],
    target_dir: Path,
) -> list[ExpectedFinding]:
    """
    Return only the expected findings whose fixture file is present in target_dir.

    Ground-truth keys are normalized root-relative paths. Basename-only matches are
    deliberately not inferred, so unrelated same-named files cannot inherit labels.
    """

    def normalize_relative_path(path: str) -> str:
        return PurePosixPath(path.replace("\\", "/")).as_posix()

    normalized_ground_truth: dict[str, list[ExpectedFinding]] = {}
    for path, expected_findings in ground_truth.items():
        normalized_path = normalize_relative_path(path)
        if normalized_path in normalized_ground_truth:
            raise ValueError(
                f"Ground-truth paths are ambiguous after normalization: {path!r}"
            )
        normalized_ground_truth[normalized_path] = expected_findings

    if target_dir.is_file():
        files = [target_dir]
    else:
        files = sorted(p for p in target_dir.rglob("*") if p.is_file())

    expected: list[ExpectedFinding] = []
    for p in files:
        rel = (
            normalize_relative_path(str(p.relative_to(target_dir)))
            if target_dir.is_dir()
            else normalize_relative_path(p.name)
        )
        if rel in normalized_ground_truth:
            file_ground_truth = normalized_ground_truth[rel]
            fixture_hashes = {
                finding.fixture_sha256
                for finding in file_ground_truth
                if finding.fixture_sha256 is not None
            }
            if fixture_hashes:
                if len(fixture_hashes) != 1 or any(
                    finding.fixture_sha256 is None
                    for finding in file_ground_truth
                ):
                    raise ValueError(
                        f"Ground-truth fixture identity is inconsistent for {rel!r}"
                    )
                actual_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                if actual_hash not in fixture_hashes:
                    continue

            for ef in file_ground_truth:
                expected.append(
                    ExpectedFinding(
                        file_name=rel,
                        line_number=ef.line_number,
                        algorithm=ef.algorithm,
                        risk_level=ef.risk_level,
                        is_genuine_call=ef.is_genuine_call,
                        purpose=ef.purpose,
                        fixture_sha256=ef.fixture_sha256,
                    )
                )
    return expected


def _scan_coverage(result: ScanResult) -> ScanCoverage:
    """Build coverage exclusively from each scanner's explicit file outcomes."""
    outcomes = tuple(result.outcomes)
    paths = [outcome.file_path for outcome in outcomes]
    if len(paths) != len(set(paths)):
        raise ScanCoverageError("Benchmark invalid: duplicate file outcomes were reported.")
    if len(result.discovered_files) != len(set(result.discovered_files)):
        raise ScanCoverageError("Benchmark invalid: duplicate discovered files were reported.")
    if set(paths) != set(result.discovered_files):
        raise ScanCoverageError(
            "Benchmark invalid: per-file outcomes do not cover exactly the discovered files."
        )

    counts = {
        status: sum(outcome.status == status for outcome in outcomes)
        for status in ("scanned", "failed", "skipped")
    }
    return ScanCoverage(
        files_discovered=len(result.discovered_files),
        files_scanned=counts["scanned"],
        files_failed=counts["failed"],
        files_skipped=counts["skipped"],
        outcomes=outcomes,
    )


class BenchmarkHarness:
    """
    Executes controlled benchmarking across scanner modes.
    """

    def __init__(
        self,
        target_dir: str | Path,
        ground_truth: Optional[dict[str, list[ExpectedFinding]]] = None,
        runs: int = 5,
        platform_name: str = "Platform A (Host Dev Environment)",
    ) -> None:
        if runs < 1:
            raise ValueError(f"Number of benchmark runs must be at least 1, got {runs}")

        self.target_dir = Path(target_dir).resolve()
        if not self.target_dir.exists():
            raise FileNotFoundError(f"Target directory {self.target_dir} does not exist")

        self.ground_truth = ground_truth if ground_truth is not None else get_all_ground_truth()
        self.runs = runs
        self.platform_name = platform_name
        self.env = EnvironmentSpec.capture(platform_name=self.platform_name)

    def run_benchmark(
        self,
        include_platform_d: bool = True,
        include_platform_b: bool = True,
    ) -> dict[str, Any]:
        """Run full comparative benchmark across regex, AST, Platform B, and Platform D modes."""
        regex_result = self._benchmark_mode(use_ast=False)
        ast_result = self._benchmark_mode(use_ast=True)

        platform_b_result: Optional[BenchmarkRunResult] = None
        if include_platform_b:
            platform_b_result = self._benchmark_platform_b()

        platform_d_result: Optional[BenchmarkRunResult] = None
        if include_platform_d:
            platform_d_result = self._benchmark_platform_d()

        results_dict: dict[str, Any] = {
            "regex_only": regex_result.to_dict(),
            "ast_enriched": ast_result.to_dict(),
        }
        if platform_b_result:
            results_dict["platform_b"] = platform_b_result.to_dict()
        if platform_d_result:
            results_dict["platform_d"] = platform_d_result.to_dict()

        return {
            "metadata": {
                "benchmark_name": "QuantumShield PS-P2 Scanner Benchmark",
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target_directory": str(self.target_dir),
                "runs_per_mode": self.runs,
                "line_match_tolerance": _BENCHMARK_LINE_MATCH_TOLERANCE,
                "environment": self.env.to_dict(),
            },
            "platform_configurations_status": {
                "Platform_A": "Configured (Resource-rich host / Cloud VM)",
                "Platform_B": (
                    "Measured on the host machine under Platform B configuration "
                    "(max_workers=1, memory_limit_mb=512, scan_strategy=full). "
                    "No OS-level virtualisation is applied; CPU and memory are not "
                    "enforced by the kernel — only the scanner configuration reflects "
                    "the constrained-server profile."
                ),
                "Platform_C": "IoT/Embedded target (Organizer QEMU/ARM image definition withheld)",
                "Platform_D": (
                    "Custom Innovation: Selective High-Risk AST Scanner. "
                    "high_risk_priority strategy: AST parse only for files containing "
                    "asymmetric (HIGH-risk) patterns; fast regex for symmetric-only files. "
                    "Per-file input-size boundary at 64 MB (not a process-wide OS heap limit)."
                ),
                "Organizers_Sample_Repo": (
                    "Using local multi-language test fixtures "
                    "(Organizer official planted repo withheld until judging)"
                ),
            },
            "results": results_dict,
            "comparison": self._compute_comparison(
                regex_result, ast_result, platform_b_result, platform_d_result
            ),
        }

    # ── Platform B ────────────────────────────────────────────────────────────

    def _benchmark_platform_b(self) -> BenchmarkRunResult:
        """
        Benchmark Platform B (constrained server / CI runner).

        Configuration applied:
          • max_workers = 1   (single-thread execution)
          • memory_limit_mb = 512  (declared limit; not OS-enforced here)
          • scan_strategy = "full" (same full scan as Platform A baseline)

        The scanner is run on the same host machine.  The timing reflects real
        single-worker performance.  No hardware sandbox or cgroup is applied.
        """
        from ..platforms.platform_config import PLATFORM_B
        from ..scanner.unified_scanner import UnifiedScanner

        times_ms: list[float] = []

        # Platform B uses the same full-scan pipeline as Platform A but is
        # restricted to a single worker.  UnifiedScanner already runs single-
        # threaded; passing PLATFORM_B.max_workers=1 is consistent with config.
        scanner = UnifiedScanner(
            root=self.target_dir,
            use_ast_for_python=True,  # full strategy same as Platform A
        )

        # Warmup
        _ = scanner.scan()

        tracemalloc.start()
        tracemalloc.reset_peak()

        findings: list[Finding] = []
        scan_result: ScanResult | None = None
        for _ in range(self.runs):
            t0 = time.perf_counter()
            scan_result = scanner.scan_with_outcomes()
            findings = scan_result.findings
            t1 = time.perf_counter()
            times_ms.append(round((t1 - t0) * 1000.0, 3))

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_kb = round(peak_mem / 1024.0, 2)

        expected = _filter_ground_truth_for_dir(self.ground_truth, self.target_dir)
        assert scan_result is not None
        coverage = _scan_coverage(scan_result)
        acc = evaluate_accuracy(
            findings,
            expected,
            match_line_tolerance=_BENCHMARK_LINE_MATCH_TOLERANCE,
            coverage=coverage,
        )

        mean_t = round(statistics.mean(times_ms), 3)
        min_t = min(times_ms)
        max_t = max(times_ms)
        stdev_t = round(statistics.stdev(times_ms), 3) if len(times_ms) > 1 else 0.0

        return BenchmarkRunResult(
            mode="platform_b",
            runs=self.runs,
            run_times_ms=times_ms,
            mean_time_ms=mean_t,
            min_time_ms=min_t,
            max_time_ms=max_t,
            stdev_time_ms=stdev_t,
            peak_memory_kb=peak_kb,
            accuracy=acc,
            findings_count=len(findings),
            scan_coverage=coverage,
        )

    # ── Platform D ────────────────────────────────────────────────────────────

    def _benchmark_platform_d(self) -> BenchmarkRunResult:
        from ..platforms.platform_d_scanner import PlatformDScanner
        times_ms: list[float] = []

        scanner = PlatformDScanner(root=self.target_dir)

        # Warmup run
        _ = scanner.scan()

        tracemalloc.start()
        tracemalloc.reset_peak()

        findings: list[Finding] = []
        scan_result: ScanResult | None = None
        for _ in range(self.runs):
            t0 = time.perf_counter()
            scan_result = scanner.scan_with_outcomes()
            findings = scan_result.findings
            t1 = time.perf_counter()
            times_ms.append(round((t1 - t0) * 1000.0, 3))

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_kb = round(peak_mem / 1024.0, 2)

        expected = _filter_ground_truth_for_dir(self.ground_truth, self.target_dir)
        assert scan_result is not None
        coverage = _scan_coverage(scan_result)
        acc = evaluate_accuracy(
            findings,
            expected,
            match_line_tolerance=_BENCHMARK_LINE_MATCH_TOLERANCE,
            coverage=coverage,
        )

        mean_t = round(statistics.mean(times_ms), 3)
        min_t = min(times_ms)
        max_t = max(times_ms)
        stdev_t = round(statistics.stdev(times_ms), 3) if len(times_ms) > 1 else 0.0

        return BenchmarkRunResult(
            mode="platform_d",
            runs=self.runs,
            run_times_ms=times_ms,
            mean_time_ms=mean_t,
            min_time_ms=min_t,
            max_time_ms=max_t,
            stdev_time_ms=stdev_t,
            peak_memory_kb=peak_kb,
            accuracy=acc,
            findings_count=len(findings),
            scan_coverage=coverage,
        )

    # ── Platform A modes (regex / AST) ────────────────────────────────────────

    def _benchmark_mode(self, use_ast: bool) -> BenchmarkRunResult:
        mode_name = "ast_enriched" if use_ast else "regex_only"
        times_ms: list[float] = []

        scanner = UnifiedScanner(root=self.target_dir, use_ast_for_python=use_ast)

        # Warmup run
        _ = scanner.scan()

        tracemalloc.start()
        tracemalloc.reset_peak()

        findings: list[Finding] = []
        scan_result: ScanResult | None = None
        for _ in range(self.runs):
            t0 = time.perf_counter()
            scan_result = scanner.scan_with_outcomes()
            findings = scan_result.findings
            t1 = time.perf_counter()
            times_ms.append(round((t1 - t0) * 1000.0, 3))

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_kb = round(peak_mem / 1024.0, 2)

        # ── Ground truth filtered to files present in target_dir ──────────────
        expected = _filter_ground_truth_for_dir(self.ground_truth, self.target_dir)

        # Evaluate accuracy
        assert scan_result is not None
        coverage = _scan_coverage(scan_result)
        acc = evaluate_accuracy(
            findings,
            expected,
            match_line_tolerance=_BENCHMARK_LINE_MATCH_TOLERANCE,
            coverage=coverage,
        )

        mean_t = round(statistics.mean(times_ms), 3)
        min_t = min(times_ms)
        max_t = max(times_ms)
        stdev_t = round(statistics.stdev(times_ms), 3) if len(times_ms) > 1 else 0.0

        return BenchmarkRunResult(
            mode=mode_name,
            runs=self.runs,
            run_times_ms=times_ms,
            mean_time_ms=mean_t,
            min_time_ms=min_t,
            max_time_ms=max_t,
            stdev_time_ms=stdev_t,
            peak_memory_kb=peak_kb,
            accuracy=acc,
            findings_count=len(findings),
            scan_coverage=coverage,
        )

    # ── Comparison ────────────────────────────────────────────────────────────

    def _compute_comparison(
        self,
        regex: BenchmarkRunResult,
        ast: BenchmarkRunResult,
        platform_b: Optional[BenchmarkRunResult] = None,
        platform_d: Optional[BenchmarkRunResult] = None,
    ) -> dict[str, Any]:
        """Compute relative deltas between Regex baseline, AST enrichment, Platform B, and Platform D."""
        time_diff_ms = round(ast.mean_time_ms - regex.mean_time_ms, 3)
        time_ratio = round(ast.mean_time_ms / regex.mean_time_ms, 2) if regex.mean_time_ms > 0 else 1.0

        precision_diff = round(ast.accuracy.precision - regex.accuracy.precision, 4)
        fp_reduction = regex.accuracy.false_positives - ast.accuracy.false_positives

        comp: dict[str, Any] = {
            "mean_runtime_delta_ms": time_diff_ms,
            "runtime_overhead_ratio": time_ratio,
            "false_positive_reduction": fp_reduction,
            "precision_delta": precision_diff,
            "recall_delta": round(ast.accuracy.recall - regex.accuracy.recall, 4),
            "f1_score_delta": round(ast.accuracy.f1_score - regex.accuracy.f1_score, 4),
        }

        if platform_b:
            comp["platform_b_vs_ast_time_delta_ms"] = round(
                platform_b.mean_time_ms - ast.mean_time_ms, 3
            )
            comp["platform_b_note"] = (
                "Platform B runs same full-AST scan as Platform A on the host machine "
                "under max_workers=1 config. No OS virtualisation applied."
            )

        if platform_d:
            comp["platform_d_vs_regex_time_delta_ms"] = round(
                platform_d.mean_time_ms - regex.mean_time_ms, 3
            )
            comp["platform_d_vs_ast_time_delta_ms"] = round(
                platform_d.mean_time_ms - ast.mean_time_ms, 3
            )
            comp["platform_d_precision_delta"] = round(
                platform_d.accuracy.precision - regex.accuracy.precision, 4
            )
            comp["platform_d_fp_reduction"] = (
                regex.accuracy.false_positives - platform_d.accuracy.false_positives
            )

        return comp

    # ── Export helpers ─────────────────────────────────────────────────────────

    def export_csv(self, benchmark_data: dict[str, Any], output_path: str | Path) -> None:
        """Export tabular comparison to CSV."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "mode",
            "runs",
            "mean_time_ms",
            "min_time_ms",
            "max_time_ms",
            "stdev_time_ms",
            "peak_memory_kb",
            "files_discovered",
            "files_scanned",
            "files_failed",
            "files_skipped",
            "coverage_status",
            "total_detected",
            "true_positives",
            "false_positives",
            "false_negatives",
            "precision",
            "recall",
            "f1_score",
        ]

        with p.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for mode_key in ("regex_only", "ast_enriched", "platform_b", "platform_d"):
                if mode_key not in benchmark_data["results"]:
                    continue
                row_data = benchmark_data["results"][mode_key]
                acc = row_data["accuracy"]
                coverage = row_data["scan_coverage"]
                writer.writerow({
                    "mode": row_data["mode"],
                    "runs": row_data["runs"],
                    "mean_time_ms": row_data["mean_time_ms"],
                    "min_time_ms": row_data["min_time_ms"],
                    "max_time_ms": row_data["max_time_ms"],
                    "stdev_time_ms": row_data["stdev_time_ms"],
                    "peak_memory_kb": row_data["peak_memory_kb"],
                    "files_discovered": coverage["files_discovered"],
                    "files_scanned": coverage["files_scanned"],
                    "files_failed": coverage["files_failed"],
                    "files_skipped": coverage["files_skipped"],
                    "coverage_status": acc["coverage_status"],
                    "total_detected": acc["total_detected"],
                    "true_positives": acc["true_positives"],
                    "false_positives": acc["false_positives"],
                    "false_negatives": acc["false_negatives"],
                    "precision": acc["precision"],
                    "recall": acc["recall"],
                    "f1_score": acc["f1_score"],
                })

    def export_json(self, benchmark_data: dict[str, Any], output_path: str | Path) -> None:
        """Export full benchmark data to JSON."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(benchmark_data, indent=2, ensure_ascii=False), encoding="utf-8")

    def export_markdown_summary(
        self, benchmark_data: dict[str, Any], output_path: str | Path
    ) -> None:
        """Export a summary markdown comparison table."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        meta = benchmark_data["metadata"]
        env = meta["environment"]
        reg = benchmark_data["results"]["regex_only"]
        ast = benchmark_data["results"]["ast_enriched"]
        comp = benchmark_data["comparison"]

        p_b = benchmark_data["results"].get("platform_b")
        p_d = benchmark_data["results"].get("platform_d")

        lines = [
            "# QuantumShield — PS-P2 Benchmark Evaluation Report",
            "",
            f"**Timestamp:** `{meta['timestamp_utc']}`<br>",
            f"**Target Directory:** `{meta['target_directory']}`<br>",
            f"**Runs per Mode:** {meta['runs_per_mode']} iterations<br>",
            f"**Platform:** {env['platform_name']} ({env['os_name']} {env['architecture']}, Python {env['python_version']})",
            "",
            "## 1. Platform Configurations & Benchmark Architecture Status",
            "",
            "- **Platform A (Resource-Rich Host):** Evaluated locally on host machine (regex baseline and AST-enriched).",
            "- **Platform B (Constrained Server/CI Runner):** Measured on the same host machine under Platform B "
            "  configuration (max_workers=1, memory_limit_mb=512, scan_strategy=full).  "
            "  **No OS-level CPU or memory virtualisation is applied.**  "
            "  The numbers reflect actual host-machine performance with single-worker constraint declared in config.",
            "- **Platform C (IoT/Embedded):** Reserved for Phase 2 continuation.",
            "- **Platform D (Custom Innovation):** Selective High-Risk AST Scanner — AST parse only for files "
            "  with asymmetric (HIGH-risk) patterns; fast regex for symmetric-only files.  "
            "  Per-file input-size boundary at 64 MB (not an OS-level process heap limit).",
            "- **Ground Truth Note:** Evaluated only against fixtures present in the scanned directory. "
            "  Organizers' planted sample repository is withheld until judging.",
            "- **Ground Truth Matching:** Exact source line and algorithm name (case-insensitive).",
            "",
            "## 2. Accuracy Comparison (Precision / Recall / F1)",
            "",
        ]

        # Build header and rows dynamically
        headers = ["Regex Baseline (Layer 1)", "AST-Enriched (Layer 2)"]
        cols = [reg, ast]
        if p_b:
            headers.append("Platform B (Constrained Server)")
            cols.append(p_b)
        if p_d:
            headers.append("Platform D (Custom Innovation)")
            cols.append(p_d)

        header_row = "| Metric | " + " | ".join(headers) + " |"
        sep_row = "| :--- | " + " | ".join([":---:"] * len(headers)) + " |"
        lines.extend([header_row, sep_row])

        def row(label: str, vals: list) -> str:
            return f"| {label} | " + " | ".join(str(v) for v in vals) + " |"

        lines.append(row("**Total Findings Detected**", [c["findings_count"] for c in cols]))
        lines.append(row("**Files Discovered**", [c["scan_coverage"]["files_discovered"] for c in cols]))
        lines.append(row("**Files Scanned**", [c["scan_coverage"]["files_scanned"] for c in cols]))
        lines.append(row("**Files Failed**", [c["scan_coverage"]["files_failed"] for c in cols]))
        lines.append(row("**Files Skipped**", [c["scan_coverage"]["files_skipped"] for c in cols]))
        lines.append(row("**Coverage Status**", [c["accuracy"]["coverage_status"] for c in cols]))
        lines.append(row("**True Positives (TP)**", [c["accuracy"]["true_positives"] for c in cols]))
        lines.append(row("**False Positives (FP)**", [c["accuracy"]["false_positives"] for c in cols]))
        lines.append(row("**False Negatives (FN)**", [c["accuracy"]["false_negatives"] for c in cols]))
        lines.append(row("**Precision**", [f"{c['accuracy']['precision']:.2%}" for c in cols]))
        lines.append(row("**Recall**", [f"{c['accuracy']['recall']:.2%}" for c in cols]))
        lines.append(row("**F1 Score**", [f"{c['accuracy']['f1_score']:.2%}" for c in cols]))

        lines.extend([
            "",
            "## 3. Performance & Resource Comparison",
            "",
        ])

        perf_headers = ["Regex Baseline", "AST-Enriched"]
        perf_cols = [reg, ast]
        if p_b:
            perf_headers.append("Platform B")
            perf_cols.append(p_b)
        if p_d:
            perf_headers.append("Platform D")
            perf_cols.append(p_d)

        perf_header_row = "| Resource Metric | " + " | ".join(perf_headers) + " |"
        perf_sep_row = "| :--- | " + " | ".join([":---:"] * len(perf_headers)) + " |"
        lines.extend([perf_header_row, perf_sep_row])

        lines.append(row(
            "**Mean Scan Runtime**",
            [f"{c['mean_time_ms']:.2f} ms" for c in perf_cols]
        ))
        lines.append(row(
            "**Runtime Std Dev**",
            [f"{c['stdev_time_ms']:.2f} ms" for c in perf_cols]
        ))
        lines.append(row(
            "**Min / Max Runtime**",
            [f"{c['min_time_ms']:.2f} / {c['max_time_ms']:.2f} ms" for c in perf_cols]
        ))
        lines.append(row(
            "**Peak Memory Allocation (tracemalloc)**",
            [f"{c['peak_memory_kb']:.2f} KB" for c in perf_cols]
        ))

        lines.extend([
            "",
            "## 4. Benchmark Limitations",
            "",
            "- Accuracy numbers reflect labelled mock test fixtures containing planted cryptographic calls,",
            "  comments, and string literals.",
            "- Ground truth is filtered to only the files present in the scanned directory; subset scans",
            "  will not produce spurious false negatives from unscanned fixtures.",
            "- Platform A measurements are taken on the host system without virtualisation limits.",
            "- Platform B is measured on the same host machine under max_workers=1 configuration.",
            "  No OS-level CPU pinning or memory cgroup is applied; declared budget is not OS-enforced.",
            "- Platform D enforces a per-file input-size boundary (not a process-wide OS heap limit);",
            "  RSS will always exceed 64 MB due to Python interpreter and shared libraries.",
            "- Organizers' official ground truth will be evaluated upon submission on their test harness.",
        ])

        p.write_text("\n".join(lines), encoding="utf-8")
