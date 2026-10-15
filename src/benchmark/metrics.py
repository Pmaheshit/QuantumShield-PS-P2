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
from typing import Any, Sequence

from .ground_truth import ExpectedFinding

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


def validate_scan_coverage(coverage: ScanCoverage) -> None:
    """
    Raise ScanCoverageError unless the scan demonstrably processed every file.

    Distinguishes:
      - never processed any files          -> invalid
      - failed to read / process some files -> invalid
      - silently skipped some files         -> invalid
      - scanned everything, found nothing   -> valid (legitimately clean)
    """
    if coverage.files_discovered <= 0:
        raise ScanCoverageError("Benchmark invalid: no source files were discovered.")

    if coverage.files_failed > 0 or coverage.scanner_errors > 0:
        raise ScanCoverageError(
            "Benchmark invalid: scan had errors "
            f"({coverage.files_failed} file(s) failed, "
            f"{coverage.scanner_errors} scanner error(s))."
        )

    if coverage.files_scanned <= 0:
        raise ScanCoverageError("Benchmark invalid: no source files were scanned.")

    accounted = coverage.files_scanned + coverage.files_failed
    if accounted != coverage.files_discovered:
        raise ScanCoverageError(
            "Benchmark invalid: scan coverage accounting mismatch "
            f"({coverage.files_discovered} discovered, {coverage.files_scanned} scanned, "
            f"{coverage.files_failed} failed)."
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


def evaluate_accuracy(
    detected_findings: Sequence[Any],
    expected_findings: Sequence[ExpectedFinding],
    match_line_tolerance: int = 1,
    match_mode: str = "exact",
    coverage: ScanCoverage | None = None,
) -> AccuracyMetrics:
    """
    Compare detected scanner findings against ground-truth expected findings.

    If `coverage` is given it is validated first and an inadequate scan raises
    ScanCoverageError instead of producing scores. Without it, results are
    marked coverage_status="unverified": an empty-vs-empty 1.0 then only means
    "nothing to compare", not "the scanner worked".

    A detected finding matches an expected finding if:
      - The file name matches
      - The line number matches (within match_line_tolerance, default 1 line)
      - The canonical algorithm names match exactly (case-insensitive)
    """
    if match_mode not in MATCH_MODES:
        raise ValueError(
            f"Invalid match_mode {match_mode!r}; expected one of {MATCH_MODES}"
        )

    if coverage is not None:
        validate_scan_coverage(coverage)
    coverage_status = "verified" if coverage is not None else "unverified"

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

    # Match detected findings to ground truth
    # Pass 1: Exact relative path match (prevents cross-directory collision when duplicate basenames exist)
    for d_idx, d in enumerate(detected_findings):
        d_file = getattr(d, "file_path", "")
        d_norm_path = d_file.replace("\\", "/")
        d_line = getattr(d, "line_number", -999)
        d_algo = getattr(d, "algorithm", "")

        for e_idx, e in enumerate(expected_findings):
            if e_idx in matched_expected_indices:
                continue

            e_norm_path = e.file_name.replace("\\", "/")

            algo_match = _algorithms_match(d_algo, e.algorithm)
            line_match = abs(d_line - e.line_number) <= match_line_tolerance

            if d_norm_path == e_norm_path and algo_match and line_match:
                matched_expected_indices.add(e_idx)
                matched_detected_indices.add(d_idx)
                break

    # Pass 2: Fallback to basename match for any remaining unmatched findings
    for d_idx, d in enumerate(detected_findings):
        if d_idx in matched_detected_indices:
            continue

        d_file = getattr(d, "file_path", "")
        d_file_name = d_file.replace("\\", "/").split("/")[-1]
        d_line = getattr(d, "line_number", -999)
        d_algo = getattr(d, "algorithm", "")

        for e_idx, e in enumerate(expected_findings):
            if e_idx in matched_expected_indices:
                continue

            e_file_name = e.file_name.replace("\\", "/").split("/")[-1]

            file_match = (d_file_name == e_file_name) or (d_file_name == ".")
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