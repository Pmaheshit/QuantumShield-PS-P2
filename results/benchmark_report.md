# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-14T10:58:42Z`<br>
**Target Directory:** `C:\Users\ASUS\Desktop\QuantumShield-PS-P2\tests\fixtures`<br>
**Runs per Mode:** 10 iterations<br>
**Platform:** Platform A (Local Workstation/Cloud Host) (Windows AMD64, Python 3.14.7)

> **Historical snapshot:** These measurements predate tokenizer-aware Python regex filtering. Rerun the benchmark to obtain current precision, recall, and runtime results.

## 1. Platform Configurations & Benchmark Architecture Status

- **Platform A (Resource-Rich Host):** Evaluated locally on host machine (regex baseline and AST-enriched).
- **Platform B (Constrained Server/CI Runner):** Measured on the same host machine under Platform B   configuration (max_workers=1, memory_limit_mb=512, scan_strategy=full).    **No OS-level CPU or memory virtualisation is applied.**    The numbers reflect actual host-machine performance with single-worker constraint declared in config.
- **Platform C (IoT/Embedded):** Reserved for Phase 2 continuation.
- **Platform D (Custom Innovation):** Selective High-Risk AST Scanner — AST parse only for files   with asymmetric (HIGH-risk) patterns; fast regex for symmetric-only files.    Per-file input-size boundary at 64 MB (not an OS-level process heap limit).
- **Ground Truth Note:** Evaluated only against fixtures present in the scanned directory.   Organizers' planted sample repository is withheld until judging.

## 2. Accuracy Comparison (Precision / Recall / F1)

| Metric | Regex Baseline (Layer 1) | AST-Enriched (Layer 2) | Platform B (Constrained Server) | Platform D (Custom Innovation) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Findings Detected** | 68 | 47 | 47 | 60 |
| **True Positives (TP)** | 13 | 17 | 17 | 18 |
| **False Positives (FP)** | 55 | 30 | 30 | 42 |
| **False Negatives (FN)** | 5 | 1 | 1 | 0 |
| **Precision** | 19.12% | 36.17% | 36.17% | 30.00% |
| **Recall** | 72.22% | 94.44% | 94.44% | 100.00% |
| **F1 Score** | 30.23% | 52.31% | 52.31% | 46.15% |

## 3. Performance & Resource Comparison

| Resource Metric | Regex Baseline | AST-Enriched | Platform B | Platform D |
| :--- | :---: | :---: | :---: | :---: |
| **Mean Scan Runtime** | 18.20 ms | 18.52 ms | 18.76 ms | 18.96 ms |
| **Runtime Std Dev** | 1.42 ms | 1.06 ms | 1.37 ms | 2.31 ms |
| **Min / Max Runtime** | 16.76 / 20.98 ms | 17.80 / 21.43 ms | 17.38 / 21.59 ms | 17.26 / 24.43 ms |
| **Peak Memory Allocation (tracemalloc)** | 185.99 KB | 209.10 KB | 200.32 KB | 205.34 KB |

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