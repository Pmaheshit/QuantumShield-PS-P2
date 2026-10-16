# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-16T05:45:14Z`<br>
**Target Directory:** `C:\Users\DINESHBABU\QuantumShield-PS-P2\tests\fixtures`<br>
**Runs per Mode:** 10 iterations<br>
**Platform:** Platform A (Local Workstation/Cloud Host) (Windows AMD64, Python 3.14.6)

## 1. Platform Configurations & Benchmark Architecture Status

- **Platform A (Resource-Rich Host):** Evaluated locally on host machine (regex baseline and AST-enriched).
- **Platform B (Constrained Server/CI Runner):** Measured on the same host machine under Platform B   configuration (max_workers=1, memory_limit_mb=512, scan_strategy=full).    **No OS-level CPU or memory virtualisation is applied.**    The numbers reflect actual host-machine performance with single-worker constraint declared in config.
- **Platform C (IoT/Embedded):** Reserved for Phase 2 continuation.
- **Platform D (Custom Innovation):** Selective High-Risk AST Scanner — AST parse only for files   with asymmetric (HIGH-risk) patterns; fast regex for symmetric-only files.    Per-file input-size boundary at 64 MB (not an OS-level process heap limit).
- **Ground Truth Note:** Evaluated only against fixtures present in the scanned directory.   Organizers' planted sample repository is withheld until judging.
- **Ground Truth Matching:** Exact source line and algorithm name (case-insensitive).

## 2. Accuracy Comparison (Precision / Recall / F1)

| Metric | Regex Baseline (Layer 1) | AST-Enriched (Layer 2) | Platform B (Constrained Server) | Platform D (Custom Innovation) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Findings Detected** | 49 | 62 | 62 | 49 |
| **Files Discovered** | 7 | 7 | 7 | 7 |
| **Files Scanned** | 7 | 7 | 7 | 7 |
| **Files Failed** | 0 | 0 | 0 | 0 |
| **Files Skipped** | 0 | 0 | 0 | 0 |
| **Coverage Status** | verified | verified | verified | verified |
| **True Positives (TP)** | 10 | 16 | 16 | 16 |
| **False Positives (FP)** | 39 | 46 | 46 | 33 |
| **False Negatives (FN)** | 8 | 2 | 2 | 2 |
| **Precision** | 20.41% | 25.81% | 25.81% | 32.65% |
| **Recall** | 55.56% | 88.89% | 88.89% | 88.89% |
| **F1 Score** | 29.85% | 40.00% | 40.00% | 47.76% |

## 3. Performance & Resource Comparison

| Resource Metric | Regex Baseline | AST-Enriched | Platform B | Platform D |
| :--- | :---: | :---: | :---: | :---: |
| **Mean Scan Runtime** | 21.87 ms | 43.23 ms | 40.68 ms | 38.12 ms |
| **Runtime Std Dev** | 1.42 ms | 4.70 ms | 2.82 ms | 3.03 ms |
| **Min / Max Runtime** | 20.62 / 25.42 ms | 40.42 / 55.87 ms | 37.65 / 46.10 ms | 34.77 / 43.55 ms |
| **Peak Memory Allocation (tracemalloc)** | 203.31 KB | 231.14 KB | 226.81 KB | 224.91 KB |

## 4. Benchmark Limitations

- Accuracy numbers reflect labelled mock test fixtures containing planted cryptographic calls,
  comments, and string literals.
- Ground truth is filtered to only the files present in the scanned directory; subset scans
  will not produce spurious false negatives from unscanned fixtures.
- Platform A measurements are taken on the host system without virtualisation limits.
- Platform B is measured on the same host machine under max_workers=1 configuration.
  No OS-level CPU pinning or memory cgroup is applied; declared budget is not OS-enforced.
- Platform D enforces a per-file input-size boundary (not a process-wide OS heap limit);
  RSS will always exceed 64 MB due to Python interpreter and shared libraries.
- Organizers' official ground truth will be evaluated upon submission on their test harness.