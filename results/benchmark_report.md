# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-16T16:36:41Z`<br>
**Target Directory:** `C:\Users\DINESHBABU\QuantumShield-PS-P2\tests\fixtures`<br>
**Runs per Mode:** 2 iterations<br>
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
| **Total Findings Detected** | 43 | 47 | 47 | 44 |
| **Files Discovered** | 7 | 7 | 7 | 7 |
| **Files Scanned** | 7 | 7 | 7 | 7 |
| **Files Failed** | 0 | 0 | 0 | 0 |
| **Files Skipped** | 0 | 0 | 0 | 0 |
| **Coverage Status** | verified | verified | verified | verified |
| **True Positives (TP)** | 12 | 18 | 18 | 16 |
| **False Positives (FP)** | 31 | 29 | 29 | 28 |
| **False Negatives (FN)** | 6 | 0 | 0 | 2 |
| **Precision** | 27.91% | 38.30% | 38.30% | 36.36% |
| **Recall** | 66.67% | 100.00% | 100.00% | 88.89% |
| **F1 Score** | 39.34% | 55.38% | 55.38% | 51.61% |

## 3. Performance & Resource Comparison

| Resource Metric | Regex Baseline | AST-Enriched | Platform B | Platform D |
| :--- | :---: | :---: | :---: | :---: |
| **Mean Scan Runtime** | 44.32 ms | 60.69 ms | 58.73 ms | 49.19 ms |
| **Runtime Std Dev** | 1.98 ms | 1.20 ms | 0.01 ms | 1.74 ms |
| **Min / Max Runtime** | 42.92 / 45.72 ms | 59.84 / 61.53 ms | 58.72 / 58.74 ms | 47.95 / 50.42 ms |
| **Peak Memory Allocation (tracemalloc)** | 192.00 KB | 206.44 KB | 206.52 KB | 204.50 KB |

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