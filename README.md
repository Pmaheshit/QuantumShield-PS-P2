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
  - **Selective Strategy (`high_risk_priority`)**: Quick regex pre-scan checks each Python file for asymmetric (HIGH-risk) keywords. Files containing RSA/ECC patterns receive full AST parsing (eliminating comment/string FPs); symmetric-only files use fast regex instead. This is the actual implemented trade-off between parsing precision and CPU overhead.
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

### Test Suite Structure (130 Passing Tests)
- `tests/test_regex_scanner.py`: 48 tests (Pattern detection across Python, Java, C, boundary conditions, empty dirs, invalid encodings).
- `tests/test_risk_classifier.py`: 24 tests (PS-P2 taxonomy classification, aliases, purpose-aware recommendations).
- `tests/test_platform_d.py`: 23 tests (Platform D profile validation, input-size limit guard, Platform B benchmark, high_risk_priority selective strategy, ground-truth subset/unrelated-dir/duplicate-basename filtering).
- `tests/test_ast_scanner.py`: 14 tests (Comment/string FP elimination, key-size extraction, ECC curves, syntax error handling).
- `tests/test_benchmark.py`: 13 tests (Precision, recall, F1, zero-division guards, duplicate handling, environment capture, Platform B result, subset scan, unrelated dir, and multi-subdir duplicate filename regression tests).
- `tests/test_inventory_report.py`: 5 tests (JSON/Markdown report schemas, secret and API-key redaction).
- `tests/test_unified_scanner.py`: 2 tests (Cross-language scanning and comparative differential analysis).
- `tests/test_end_to_end.py`: 1 test (End-to-end integration across scanner, classifier, reporting, and benchmarking including Platform B and D).


---

## 7. Actual Benchmark Results & Measurements

> **Transparency Note**: The hackathon organizers' official sample repository and evaluation ground truth are **withheld until judging** (Problem Statement, Page 15). The figures below represent **actual measured values** generated by `python main.py --scan-dir tests/fixtures --runs 10 --output-dir results` on this machine. No values are simulated or fabricated.

### Accuracy & Detection Metrics
| Mode / Target Platform | Total Detected | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Regex Baseline (Layer 1)** | 68 | 13 | 55 | 5 | **19.12%** | **72.22%** | **30.23%** |
| **AST-Enriched (Layer 2)** | 47 | 17 | 30 | 1 | **36.17%** | **94.44%** | **52.31%** |
| **Platform B (Constrained Server)** | 47 | 17 | 30 | 1 | **36.17%** | **94.44%** | **52.31%** |
| **Platform D (Selective High-Risk AST)** | 60 | 18 | 42 | 0 | **30.00%** | **100.00%** | **46.15%** |

> **Platform B note**: measured on the **host machine** under `max_workers=1, memory_limit_mb=512` configuration; no OS-level CPU or memory virtualisation is applied.
> **Platform D note**: `high_risk_priority` strategy — AST parse for files with asymmetric (HIGH-risk) keywords, fast regex for symmetric-only files. Achieves 100% recall (18/18) because the quick pre-scan correctly routes all asymmetric and mixed files through AST. Higher FP count vs pure-AST because symmetric-only files use regex (no comment suppression).


### Performance & Resource Usage (10 Iterations)
| Target Platform Mode | Mean Runtime | Runtime StdDev | Min / Max Runtime | Peak Memory (tracemalloc) |
| :--- | :---: | :---: | :---: | :---: |
| **Platform A — Regex Baseline** | 30.88 ms | 3.10 ms | 26.87 / 37.14 ms | 186.39 KB |
| **Platform A — AST-Enriched** | 26.30 ms | 2.45 ms | 22.87 / 29.13 ms | 199.73 KB |
| **Platform B — Constrained Server** | 27.22 ms | 2.26 ms | 23.62 / 30.02 ms | 197.89 KB |
| **Platform D — Selective High-Risk AST** | 49.85 ms | 13.40 ms | 30.83 / 67.56 ms | 204.59 KB |

> **Memory note**: `tracemalloc` measures Python-heap allocations only. Total process RSS (Python interpreter + shared libs) exceeds 64 MB regardless of the Platform D input-size boundary.

*Exported artifacts: [`results/tables/benchmark_results.csv`](results/tables/benchmark_results.csv), [`results/tables/benchmark_results.json`](results/tables/benchmark_results.json), [`results/figures/runtime_comparison.png`](results/figures/runtime_comparison.png)*.


---

## 8. Known Limitations & Operational Assumptions

1. **Dynamic / Runtime Values**: Variables computed dynamically at runtime (e.g. `RSA.generate(key_size_from_db)`) cannot be statically resolved and are explicitly marked with `confidence="UNKNOWN"` per competition guidelines.
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
