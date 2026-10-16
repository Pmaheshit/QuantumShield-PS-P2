# QuantumShield (PS-P2) — Cryptographic Inventory & Migration Planner

> **Qiskit Fall Fest 2026** — *Post-Quantum Cryptography Track (PS-P2)*  
> An automated, multi-language static analysis and risk classification engine that discovers classical cryptographic primitives in source code, classifies quantum risk according to the official PS-P2 taxonomy, recommends NIST FIPS-standardized post-quantum replacements (FIPS 203 ML-KEM, FIPS 204 ML-DSA), and benchmarks performance across target deployment platforms.

---

## 1. Problem Statement & Architecture Overview

### The Migration Problem (PS-P2)
Organizations cannot migrate cryptography they have not discovered. Quantum computers running Shor's algorithm will break classical public-key cryptography (RSA, ECC, ECDSA, ECDH), while Grover's algorithm halves symmetric security (AES-128 reduced to ~64 bits of security). QuantumShield provides an automated discovery, inventorying, and migration-planning pipeline.

### Architectural Tiers
```
                   Source Code Repository (Python, Java, C)
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
      [Layer 1: Regex Engine]                       [Layer 2: Python AST]
      Fast multi-language scanning                  Deep syntax & parameter parsing
      Python / Java / C/C++                         Eliminates comments & strings
              │                                     Extracts key size & curves
              └───────────────────────┬───────────────────────┘
                                      │
                                      ▼
                        [Risk Classification Engine]
                  Maps detected primitives to PS-P2 taxonomy:
                    • HIGH: RSA, ECC, ECDSA, ECDH
                    • MODERATE: AES-128
                    • LOWER: AES-256, SHA-256
                                      │
                                      ▼
                      [Purpose-Specific Migration]
                    • Key Encapsulation  ──► ML-KEM (FIPS 203)
                    • Digital Signatures ──► ML-DSA (FIPS 204)
                    • Symmetric Upgrade  ──► AES-256
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
     [Inventory Reports]                             [Target Platform Benchmarks]
     • JSON (machine-readable)                       • Platform A: Cloud VM / Dev
     • Markdown (audit-ready)                        • Platform B: Constrained Server
     • Secret Sanitization                           • Platform C: Embedded IoT
                                                     • Platform D: Custom Innovation
```

In unified Python scanning, regex findings supplement AST results for APIs the AST
does not yet recognize. The fallback masks comments and string literals and avoids
re-reporting APIs already represented by an AST finding.

---

## 2. PS-P2 Risk Taxonomy & Migration Rules

| Detected Primitive | Quantum Risk Level | Theoretical Threat | Migration Recommendation | Standard |
| :--- | :---: | :--- | :--- | :--- |
| **RSA** *(Key Encapsulation / OAEP)* | 🔴 **HIGH** | Modulus factored in polynomial time (Shor's) | **ML-KEM** (Key Encapsulation) | FIPS 203 |
| **RSA** *(Digital Signatures / PSS)* | 🔴 **HIGH** | Discrete log / factoring broken (Shor's) | **ML-DSA** (Digital Signatures) | FIPS 204 |
| **ECDSA** *(Elliptic-Curve Signatures)* | 🔴 **HIGH** | Discrete log problem broken (Shor's) | **ML-DSA** (FIPS 204) or **SLH-DSA** | FIPS 204 / 205 |
| **ECDH** *(Elliptic-Curve Key Agreement)* | 🔴 **HIGH** | Key agreement intercepted (Shor's) | **ML-KEM** (FIPS 203) | FIPS 203 |
| **AES-128** *(Symmetric Cipher)* | 🟡 **MODERATE** | Key space halved to ~64 bits (Grover's) | **Upgrade to AES-256** | FIPS 197 |
| **AES-256** *(Symmetric Cipher)* | 🟢 **LOWER** | Key space reduced to ~128 bits (Grover's) | **No change needed** (Quantum-safe baseline) | FIPS 197 |
| **SHA-256** *(Cryptographic Hash)* | 🟢 **LOWER** | Collision search reduced to ~128 bits | **No change needed** (Acceptable post-quantum) | FIPS 180-4 |

---

## 3. Target Platform Definitions & Custom Platform D

In accordance with the Post-Quantum Cryptography Track rules ([`Problem_Statment_Details.pdf`](docs/Problem_Statment_Details.pdf), Page 14):

- **Platform A (Resource-Rich Baseline)**: Standard x86-64 workstation / Cloud VM, full memory availability.
- **Platform B (Constrained Server)**: Single-core execution (`max_workers=1`), 512 MB declared memory limit (`processors/platform_b.json`). **Measured on the host machine** with the Platform B configuration — no OS-level CPU pinning or memory cgroup is applied; the declared budget is not OS-enforced.
- **Platform C (Embedded/IoT Target)**: Microcontroller emulator (ARM Cortex-M / Raspberry Pi Zero, Phase 2 continuation).
- **Custom Platform D (Innovation)**: **Selective High-Risk AST Scanner**
  - **Input-Size Boundary (not an OS memory ceiling)**: Files exceeding 64 MB are rejected before parsing (`processors/platform_d.json`). This is a *per-file input-size limit*, not a process-wide heap ceiling. Total Python process RSS will always exceed 64 MB due to the interpreter and shared libraries. Python heap allocations during scanning are measured at < 210 KB via `tracemalloc` on benchmark fixtures.
  - **Selective Strategy (`high_risk_priority`)**: A tokenizer-aware pre-scan ignores Python comments and non-API strings when routing asymmetric files to AST; symmetric-only files use tokenizer-aware regex scanning. The benchmark reports precision and recall for regex-only, AST-enriched, and Platform D strategies alongside runtime.
  - **Pipeline & Concurrency**: Single-worker streaming iterator (`max_workers=1`).

All target platform configurations are exported in standard JSON format under [`processors/`](processors/):
`processors/platform_a.json`, `processors/platform_b.json`, `processors/platform_c.json`, `processors/platform_d.json`.

---

## 4. Installation & Environment Setup

### Prerequisites
- Python 3.9+ (Tested on Python 3.14.7 x86-64)
- Git

### Quick Setup
```bash
# 1. Clone repository
git clone https://github.com/Pmaheshit/QuantumShield-PS-P2.git
cd QuantumShield-PS-P2

# 2. (Optional) Create virtual environment
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (Command Prompt):
.venv\Scripts\activate.bat
# Linux/macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 5. Execution Commands

### A. Run Full End-to-End Pipeline
Executes the scan, generates inventory reports, runs the 3-mode benchmark, and saves artifacts:
```bash
python main.py --scan-dir tests/fixtures --runs 10 --output-dir results
```

### B. Command-Line Interface (Direct Scanner)
```bash
# Basic JSON output
python -m src.scanner.regex_scanner tests/fixtures/ --json

# AST-enriched scan with table display
python -m src.scanner.regex_scanner tests/fixtures/ --ast --pretty

# Generate audit Markdown report
python -m src.scanner.regex_scanner tests/fixtures/ --ast -f markdown -o results/inventory_report.md
```

### C. Run Comparative Benchmark Harness
```bash
python -c "from src.benchmark.runner import BenchmarkHarness; from pathlib import Path; h = BenchmarkHarness(Path('tests/fixtures'), runs=10); r = h.run_benchmark(include_platform_d=True); h.export_json(r, 'results/tables/benchmark_results.json'); h.export_csv(r, 'results/tables/benchmark_results.csv'); h.export_markdown_summary(r, 'results/benchmark_report.md'); print('Benchmark Complete')"
```

---

## 6. Testing & Quality Assurance

Run the comprehensive unit, regression, and integration test suite:
```bash
python -m pytest tests/ -v
```

### Latest Verified Test Run
The latest full run collected **201 pytest cases**; **201 passed**, with **0 failed, 0 skipped, and 0 deselected**. There were no collection errors. These results are from the latest verified run, not a guarantee for future runs.

Counts below are collected pytest cases grouped by test module (including parameterized cases), not counts of test functions. The modules account for the complete 201-case suite.

- `tests/test_ast_scanner.py`: 29 cases — AST detection, comment/string false-positive filtering, AES key-size inference including unresolved and conservative cases, ECC curves, and syntax errors.
- `tests/test_benchmark.py`: 33 cases — precision/recall/F1, exact algorithm matching, exact-path and basename behavior, file coverage and outcomes, and benchmark result/export consistency.
- `tests/test_unified_scanner.py`: 12 cases — cross-language scanning, regex fallback for unsupported APIs, AST/regex deduplication, multiline calls, comment/string masking, and best-effort behavior on tokenization failure.
- `tests/test_platform_d.py`: 27 cases — platform configuration and scanning, Platform D selective high-risk strategy, input-size limits, explicit file-processing outcomes, and ground-truth filtering.
- `tests/test_regex_scanner.py`: 64 cases — pattern detection across Python, Java, and C; comment/string-aware detection, multiline calls, line reporting, malformed Python, and boundary/error cases.
- `tests/test_risk_classifier.py`: 27 cases — risk taxonomy, aliases, recommendations, and preservation of unknown AES variants and unknown risk.
- `tests/test_inventory_report.py`: 7 cases — JSON and Markdown report structures, serialization, evidence sanitization, and preservation of unknown AES variants.
- `tests/test_end_to_end.py`: 2 cases — scanner-to-report/metrics regression for unresolved AES and complete pipeline execution.


---

## 7. Actual Benchmark Results & Measurements

> **Transparency Note**: The hackathon organizers' official sample repository and evaluation ground truth are **withheld until judging** (Problem Statement, Page 15). The figures below represent **actual measured values** generated by `python main.py --scan-dir tests/fixtures --runs 10 --output-dir results` on this machine. No values are simulated or fabricated.

Benchmark scores require an exact source-line match and exact case-insensitive algorithm-name match (`line_match_tolerance=0`); ECDSA, ECDH, and generic ECC findings are not interchangeable. Each scanner records a per-file outcome (`scanned`, `failed`, or `skipped`), and benchmark results expose unique file counts and outcome details. Incomplete scans are labeled `coverage_status="partial"` rather than presenting their scores as fully verified; a benchmark with no scannable files is rejected. Direct empty-input metric calculations are labeled `coverage_status="unverified"`.

### Accuracy & Detection Metrics
| Mode / Target Platform | Total Detected | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Regex Baseline (Layer 1)** | 49 | 11 | 38 | 7 | **22.45%** | **61.11%** | **32.84%** |
| **AST-Enriched (Layer 2)** | 55 | 16 | 39 | 2 | **29.09%** | **88.89%** | **43.84%** |
| **Platform B (Constrained Server)** | 55 | 16 | 39 | 2 | **29.09%** | **88.89%** | **43.84%** |
| **Platform D (Selective High-Risk AST)** | 49 | 16 | 33 | 2 | **32.65%** | **88.89%** | **47.76%** |

> **Platform B note**: measured on the **host machine** under `max_workers=1, memory_limit_mb=512` configuration; no OS-level CPU or memory virtualisation is applied.
> **Platform D note**: `high_risk_priority` strategy — AST parse for files with asymmetric (HIGH-risk) code, tokenizer-aware regex for symmetric-only files. The reported results were regenerated after the tokenizer-aware regex changes.


### Performance & Resource Usage (10 Iterations)
| Target Platform Mode | Mean Runtime | Runtime StdDev | Min / Max Runtime | Peak Memory (tracemalloc) |
| :--- | :---: | :---: | :---: | :---: |
| **Platform A — Regex Baseline** | 11.76 ms | 1.92 ms | 10.13 / 16.70 ms | 202.03 KB |
| **Platform A — AST-Enriched** | 19.71 ms | 1.30 ms | 17.69 / 21.92 ms | 227.99 KB |
| **Platform B — Constrained Server** | 19.59 ms | 1.02 ms | 17.72 / 20.81 ms | 224.01 KB |
| **Platform D — Selective High-Risk AST** | 17.60 ms | 1.70 ms | 15.87 / 20.89 ms | 216.70 KB |

> **Memory note**: `tracemalloc` measures Python-heap allocations only. Total process RSS (Python interpreter + shared libs) exceeds 64 MB regardless of the Platform D input-size boundary.

*Exported artifacts: [`results/tables/benchmark_results.csv`](results/tables/benchmark_results.csv), [`results/tables/benchmark_results.json`](results/tables/benchmark_results.json), [`results/figures/runtime_comparison.png`](results/figures/runtime_comparison.png)*.


---

## 8. Known Limitations & Operational Assumptions

1. **Dynamic / Runtime Values**: Variables computed dynamically at runtime (e.g. RSA and AES key sizes) cannot be statically resolved. AES calls with unresolved key size are reported as `AES-UNKNOWN` with `confidence="INFERRED"` and `UNKNOWN` risk by default. AES-192 retains its distinct algorithm label but has `UNKNOWN` risk because the current project taxonomy defines no AES-192 risk policy. `CONSERVATIVE_AES_DEFAULT` can be enabled only when competition rules require an assumed AES-128 report, which is marked with `assumed_default=true` in JSON and Markdown. Benchmark matching remains exact by algorithm label.
2. **Java & C Comments**: Java and C/C++ detection is performed via the Layer 1 Regex engine; keyword identifiers in inactive comments or strings in those languages remain flagged until dedicated tree-sitter parsers are linked.
3. **Organizers' Hidden Repository**: The official competition repository will be evaluated upon submission on the hackathon evaluation harness.

---

## 9. AI Assistance Disclosure

In compliance with the Qiskit Fall Fest 2026 submission rules and AI assistance disclosure guidelines:
- **AI Tooling Used**: Antigravity AI Assistant (Google DeepMind).
- **Scope of Use**:
  - Drafting initial boilerplate regex patterns and AST visitor node dispatchers.
  - Designing mock test fixtures (`snippet_rsa.py`, `snippet_ecc.py`, `snippet_aes.c`, `snippet_ecdsa.java`).
  - Formatting markdown reports and generating unit test assertions.
- **Human Review & Verification**:
  - All cryptographic risk classifications were verified against NIST FIPS 203, FIPS 204, and NIST SP 1800-38.
  - All test suites and benchmark timings were executed live on physical hardware. No results or benchmark numbers were generated by AI.
