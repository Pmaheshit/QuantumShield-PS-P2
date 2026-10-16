# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-16T05:10:32Z`<br>
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
| **Total Findings Detected** | 49 | 55 | 55 | 49 |
| **Files Discovered** | 7 | 7 | 7 | 7 |
| **Files Scanned** | 7 | 7 | 7 | 7 |
| **Files Failed** | 0 | 0 | 0 | 0 |
| **Files Skipped** | 0 | 0 | 0 | 0 |
| **Coverage Status** | verified | verified | verified | verified |
| **True Positives (TP)** | 11 | 16 | 16 | 16 |
| **False Positives (FP)** | 38 | 39 | 39 | 33 |
| **False Negatives (FN)** | 7 | 2 | 2 | 2 |
| **Precision** | 22.45% | 29.09% | 29.09% | 32.65% |
| **Recall** | 61.11% | 88.89% | 88.89% | 88.89% |
| **F1 Score** | 32.84% | 43.84% | 43.84% | 47.76% |

## 3. Performance & Resource Comparison

| Resource Metric | Regex Baseline | AST-Enriched | Platform B | Platform D |
| :--- | :---: | :---: | :---: | :---: |
| **Mean Scan Runtime** | 11.76 ms | 19.71 ms | 19.59 ms | 17.60 ms |
| **Runtime Std Dev** | 1.92 ms | 1.30 ms | 1.02 ms | 1.70 ms |
| **Min / Max Runtime** | 10.13 / 16.70 ms | 17.69 / 21.92 ms | 17.72 / 20.81 ms | 15.87 / 20.89 ms |
| **Peak Memory Allocation (tracemalloc)** | 202.03 KB | 227.99 KB | 224.01 KB | 216.70 KB |

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