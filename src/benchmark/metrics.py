"""
src/benchmark/metrics.py
────────────────────────
Metrics calculation engine for QuantumShield PS-P2 benchmark validation.

Calculates:
  • True Positives (TP): Correctly identified genuine cryptographic calls
  • False Positives (FP): Flags in comments, strings, or incorrect detections
  • False Negatives (FN): Genuine cryptographic calls missed by the scanner
  • Precision: TP / (TP + FP)
  • Recall: TP / (TP + FN)
  • F1 Score: 2 * (Precision * Recall) / (Precision + Recall)

Handles edge cases robustly:
  • Empty ground truth (e.g. clean files)
  • Empty scanner findings
  • Duplicate findings on identical lines
  • Division by zero safeguards

Algorithm matching:
  • Exact only: the detected algorithm must equal the expected algorithm.
    ECDSA (signatures), ECDH (key agreement) and ECC (generic category) are
    distinct and are NOT interchangeable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import posixpath
from typing import Any, Sequence

from .ground_truth import ExpectedFinding
from ..scanner.scan_result import FileScanOutcome

MATCH_MODES = ("exact",)


class ScanCoverageError(RuntimeError):
    """Raised when a benchmark run is invalid because scan coverage is inadequate."""


@dataclass(frozen=True)
class ScanCoverage:
    """
    What the scanner actually did, tracked separately from what it found.

    files_discovered : source files the benchmark expected to be scanned
    files_scanned    : files read and processed successfully
    files_failed     : files that could not be read or that raised an error
    scanner_errors   : internal scanner exceptions (e.g. caught and swallowed)
    """

    files_discovered: int
    files_scanned: int
    files_failed: int = 0
    scanner_errors: int = 0
    files_skipped: int = 0
    outcomes: tuple[FileScanOutcome, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_scan_coverage(coverage: ScanCoverage) -> None:
    """
    Raise ScanCoverageError unless every discovered file has exactly one outcome.

    Distinguishes:
      - never processed any files          -> invalid
      - failed to read / process some files -> reported as failed
      - intentionally excluded files        -> reported as skipped
      - scanned everything, found nothing   -> valid (legitimately clean)
    """
    if coverage.files_discovered <= 0:
        raise ScanCoverageError("Benchmark invalid: no source files were discovered.")

    accounted = (
        coverage.files_scanned + coverage.files_failed + coverage.files_skipped
    )
    if accounted != coverage.files_discovered:
        raise ScanCoverageError(
            "Benchmark invalid: scan coverage accounting mismatch "
            f"({coverage.files_discovered} discovered, {coverage.files_scanned} scanned, "
            f"{coverage.files_failed} failed, {coverage.files_skipped} skipped)."
        )

    outcome_paths = [outcome.file_path for outcome in coverage.outcomes]
    if len(outcome_paths) != len(set(outcome_paths)):
        raise ScanCoverageError(
            "Benchmark invalid: duplicate per-file scan outcomes were reported."
        )
    outcome_counts = {
        status: sum(outcome.status == status for outcome in coverage.outcomes)
        for status in ("scanned", "failed", "skipped")
    }
    if (
        len(coverage.outcomes) != coverage.files_discovered
        or outcome_counts["scanned"] != coverage.files_scanned
        or outcome_counts["failed"] != coverage.files_failed
        or outcome_counts["skipped"] != coverage.files_skipped
    ):
        raise ScanCoverageError(
            "Benchmark invalid: per-file outcomes do not match coverage counts."
        )


@dataclass
class AccuracyMetrics:
    total_expected: int
    total_detected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    # "verified"   : scan coverage was supplied and validated
    # "unverified" : no coverage info; an empty-vs-empty 1.0 is NOT evidence of success
    coverage_status: str = "unverified"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _algorithms_match(detected: str, expected: str) -> bool:
    """Return whether algorithm names match exactly, ignoring case."""
    d = (detected or "").upper()
    e = (expected or "").upper()
    return d == e


def _normalize_file_path(file_path: str) -> str:
    """Normalize path separators and redundant relative-path components."""
    return posixpath.normpath((file_path or "").replace("\\", "/"))


def evaluate_accuracy(
    detected_findings: Sequence[Any],
    expected_findings: Sequence[ExpectedFinding],
    match_line_tolerance: int = 1,
    match_mode: str = "exact",
    coverage: ScanCoverage | None = None,
) -> AccuracyMetrics:
    """
    Compare detected scanner findings against ground-truth expected findings.

    If `coverage` is given it is validated first. Complete scans are marked
    "verified"; scans with file failures or intentional skips are marked
    "partial". Coverage with no discovered files or inconsistent outcomes
    raises ScanCoverageError. Without coverage, results are marked
    "unverified": an empty-vs-empty 1.0 then only means "nothing to compare",
    not "the scanner worked".

    A detected finding matches an expected finding if:
      - The normalized relative paths match, or a basename-only expected label
        uniquely identifies a discovered file in supplied scan coverage
      - The line number matches (within match_line_tolerance, default 1 line)
      - The canonical algorithm names match exactly (case-insensitive)
    """
    if match_mode not in MATCH_MODES:
        raise ValueError(
            f"Invalid match_mode {match_mode!r}; expected one of {MATCH_MODES}"
        )

    if coverage is not None:
        validate_scan_coverage(coverage)
    coverage_status = "unverified"
    if coverage is not None:
        coverage_status = (
            "verified"
            if (
                coverage.files_failed == 0
                and coverage.files_skipped == 0
                and coverage.scanner_errors == 0
            )
            else "partial"
        )

    total_expected = len(expected_findings)
    total_detected = len(detected_findings)

    if total_expected == 0 and total_detected == 0:
        return AccuracyMetrics(
            total_expected=0,
            total_detected=0,
            true_positives=0,
            false_positives=0,
            false_negatives=0,
            precision=1.0,
            recall=1.0,
            f1_score=1.0,
            coverage_status=coverage_status,
        )

    matched_expected_indices: set[int] = set()
    matched_detected_indices: set[int] = set()

    # Match detected findings to ground truth by normalized relative path first.
    for d_idx, d in enumerate(detected_findings):
        d_file = getattr(d, "file_path", "")
        d_norm_path = _normalize_file_path(d_file)
        d_line = getattr(d, "line_number", -999)
        d_algo = getattr(d, "algorithm", "")

        for e_idx, e in enumerate(expected_findings):
            if e_idx in matched_expected_indices:
                continue

            e_norm_path = _normalize_file_path(e.file_name)

            algo_match = _algorithms_match(d_algo, e.algorithm)
            line_match = abs(d_line - e.line_number) <= match_line_tolerance

            if (
                d_norm_path not in ("", ".")
                and d_norm_path == e_norm_path
                and algo_match
                and line_match
            ):
                matched_expected_indices.add(e_idx)
                matched_detected_indices.add(d_idx)
                break

    # A basename fallback is safe only when coverage proves the name is unique
    # in the discovered repository, and the expected label has no directory.
    scanned_paths_by_basename: dict[str, set[str]] = {}
    if coverage is not None:
        for outcome in coverage.outcomes:
            scanned_path = _normalize_file_path(outcome.file_path)
            basename = posixpath.basename(scanned_path)
            if scanned_path not in ("", ".") and basename:
                scanned_paths_by_basename.setdefault(basename, set()).add(scanned_path)

    for d_idx, d in enumerate(detected_findings):
        if d_idx in matched_detected_indices:
            continue

        d_norm_path = _normalize_file_path(getattr(d, "file_path", ""))
        d_file_name = posixpath.basename(d_norm_path)
        d_line = getattr(d, "line_number", -999)
        d_algo = getattr(d, "algorithm", "")

        if (
            coverage is None
            or d_norm_path in ("", ".")
            or len(scanned_paths_by_basename.get(d_file_name, set())) != 1
        ):
            continue

        for e_idx, e in enumerate(expected_findings):
            if e_idx in matched_expected_indices:
                continue

            e_norm_path = _normalize_file_path(e.file_name)
            e_file_name = posixpath.basename(e_norm_path)

            file_match = (
                e_norm_path == e_file_name
                and d_file_name == e_file_name
            )
            algo_match = _algorithms_match(d_algo, e.algorithm)
            line_match = abs(d_line - e.line_number) <= match_line_tolerance

            if file_match and algo_match and line_match:
                matched_expected_indices.add(e_idx)
                matched_detected_indices.add(d_idx)
                break

    true_positives = len(matched_detected_indices)
    false_positives = total_detected - true_positives
    false_negatives = total_expected - len(matched_expected_indices)

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else (1.0 if total_expected == 0 else 0.0)
    )

    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else (1.0 if total_detected == 0 else 0.0)
    )

    f1_score = (
        (2.0 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return AccuracyMetrics(
        total_expected=total_expected,
        total_detected=total_detected,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
        coverage_status=coverage_status,
    )