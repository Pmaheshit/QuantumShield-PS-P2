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
  • Default ("exact"): the detected algorithm must equal the expected algorithm.
    ECDSA (signatures), ECDH (key agreement) and ECC (generic category) are
    distinct and are NOT interchangeable.
  • Optional ("family"): algorithms are compared by family. Use this only as a
    secondary, clearly-labelled metric, never as the primary benchmark score.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Sequence, Set, Tuple

from .ground_truth import ExpectedFinding

# Family-level grouping, used only when match_mode="family".
ALGORITHM_FAMILIES: dict[str, str] = {
    "ECDSA": "ELLIPTIC_CURVE",
    "ECDH": "ELLIPTIC_CURVE",
    "ECC": "ELLIPTIC_CURVE",
}

MATCH_MODES = ("exact", "family")


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


def _algorithms_match(detected: str, expected: str, match_mode: str = "exact") -> bool:
    """
    Decide whether a detected algorithm matches the expected one.

    exact  : identical algorithm names (case-insensitive). Default.
    family : identical names, or both belong to the same algorithm family.
    """
    d = (detected or "").upper()
    e = (expected or "").upper()

    if d == e:
        return True

    if match_mode == "family":
        d_family = ALGORITHM_FAMILIES.get(d)
        return d_family is not None and d_family == ALGORITHM_FAMILIES.get(e)

    return False


def evaluate_accuracy(
    detected_findings: Sequence[Any],
    expected_findings: Sequence[ExpectedFinding],
    match_line_tolerance: int = 1,
    match_mode: str = "exact",
) -> AccuracyMetrics:
    """
    Compare detected scanner findings against ground-truth expected findings.

    A detected finding matches an expected finding if:
      - The file name matches
      - The line number matches (within match_line_tolerance, default 1 line)
      - The algorithm matches per `match_mode`:
          "exact"  (default): identical algorithm names
          "family": identical names or same algorithm family
    """
    if match_mode not in MATCH_MODES:
        raise ValueError(
            f"Invalid match_mode {match_mode!r}; expected one of {MATCH_MODES}"
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

            algo_match = _algorithms_match(d_algo, e.algorithm, match_mode)
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
            algo_match = _algorithms_match(d_algo, e.algorithm, match_mode)
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