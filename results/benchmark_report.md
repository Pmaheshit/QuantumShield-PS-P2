# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-12T19:19:42Z`<br>
**Target Directory:** `C:\Users\ASUS\Desktop\QuantumShield-PS-P2\tests\fixtures`<br>
**Runs per Mode:** 10 iterations<br>
**Platform:** Platform A (Local Workstation/Cloud Host) (Windows AMD64, Python 3.14.7)

## 1. Platform Configurations & Benchmark Architecture Status

- **Platform A (Resource-Rich Host):** Evaluated locally on host machine.
- **Platform B (Constrained Server/CI Runner):** Evaluated under single-thread execution constraint. (Organizer remote CI configuration is withheld from participants).
- **Platform C (IoT/Embedded):** Reserved for Phase 2 continuation.
- **Platform D (Custom Innovation):** Memory-Budgeted High-Risk AST Scanner (64 MB budget, streaming execution, asymmetric Shor-vulnerable primitive priority).
- **Ground Truth Note:** Measured against our verified mock test fixtures with ground truth labels. Organizers' planted sample repository is withheld until judging.

## 2. Accuracy Comparison (Precision / Recall / F1)

| Metric | Regex Baseline (Layer 1) | AST-Enriched (Layer 2) | Platform D (Custom Innovation) |
| :--- | :---: | :---: | :---: |
| **Total Findings Detected** | 68 | 47 | 47 |
| **True Positives (TP)** | 13 | 17 | 17 |
| **False Positives (FP)** | 55 | 30 | 30 |
| **False Negatives (FN)** | 5 | 1 | 1 |
| **Precision** | 19.12% | 36.17% | 36.17% |
| **Recall** | 72.22% | 94.44% | 94.44% |
| **F1 Score** | 30.23% | 52.31% | 52.31% |

## 3. Performance & Resource Comparison

| Resource Metric | Regex Baseline | AST-Enriched | Platform D |
| :--- | :---: | :---: | :---: |
| **Mean Scan Runtime** | 18.79 ms | 31.95 ms | 20.54 ms |
| **Runtime Std Dev** | 2.50 ms | 15.01 ms | 1.06 ms |
| **Min / Max Runtime** | 17.18 / 25.47 ms | 19.06 / 71.16 ms | 19.37 / 22.59 ms |
| **Peak Memory Allocation** | 185.93 KB | 200.48 KB | 197.30 KB |

## 4. Benchmark Limitations

- The accuracy numbers reflect labelled mock test fixtures containing planted cryptographic calls, comments, and string literals.
- Measurements on Platform A are taken on the host system without virtualization limits.
- Platform B is simulated using single-worker constraint.
- Platform D enforces streaming constraints and asymmetric Shor-vulnerable primitive prioritization.
- Organizers' official ground truth will be evaluated upon submission on their test harness.