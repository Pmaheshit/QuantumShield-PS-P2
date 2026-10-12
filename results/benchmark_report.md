# QuantumShield — PS-P2 Benchmark Evaluation Report

**Timestamp:** `2026-10-12T18:54:04Z`  
**Target Directory:** `C:\Users\ASUS\Desktop\QuantumShield-PS-P2\tests\fixtures`  
**Runs per Mode:** 3 iterations  
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
| **Mean Scan Runtime** | 22.53 ms | 28.50 ms | 26.38 ms |
| **Runtime Std Dev** | 3.35 ms | 4.70 ms | 1.73 ms |
| **Min / Max Runtime** | 20.04 / 26.34 ms | 23.07 / 31.26 ms | 24.39 / 27.53 ms |
| **Peak Memory Allocation** | 182.82 KB | 194.66 KB | 193.06 KB |

## 4. Benchmark Limitations

- The accuracy numbers reflect labelled mock test fixtures containing planted cryptographic calls, comments, and string literals.
- Measurements on Platform A are taken on the host system without virtualization limits.
- Platform B is simulated using single-worker constraint.
- Platform D enforces streaming constraints and asymmetric Shor-vulnerable primitive prioritization.
- Organizers' official ground truth will be evaluated upon submission on their test harness.