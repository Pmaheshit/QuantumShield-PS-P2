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
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Sequence, Set, Tuple

from .ground_truth import ExpectedFinding


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_accuracy(
    detected_findings: Sequence[Any],
    expected_findings: Sequence[ExpectedFinding],
    match_line_tolerance: int = 1,
) -> AccuracyMetrics:
    """
    Compare detected scanner findings against ground-truth expected findings.

    A detected finding matches an expected finding if:
      - The file name matches
      - The line number matches (within match_line_tolerance, default 1 line)
      - The algorithm matches (or maps to identical canonical category)
    """
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
        )

    matched_expected_indices: set[int] = set()
    matched_detected_indices: set[int] = set()

    # Match detected findings to ground truth
    for d_idx, d in enumerate(detected_findings):
        d_file = getattr(d, "file_path", "")
        # Normalize file path to basename for comparison
        d_file_name = d_file.replace("\\", "/").split("/")[-1]
        d_line = getattr(d, "line_number", -999)
        d_algo = getattr(d, "algorithm", "").upper()

        for e_idx, e in enumerate(expected_findings):
            if e_idx in matched_expected_indices:
                continue

            e_file_name = e.file_name.replace("\\", "/").split("/")[-1]
            e_algo = e.algorithm.upper()

            file_match = (d_file_name == e_file_name) or (d_file_name == ".")
            algo_match = (d_algo == e_algo) or (
                d_algo in ("ECDSA", "ECC", "ECDH") and e_algo in ("ECDSA", "ECC", "ECDH")
            )
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
    )
