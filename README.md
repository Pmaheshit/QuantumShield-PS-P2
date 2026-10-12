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
- **Platform B (Constrained Server)**: Single-core execution, 512 MB capped memory (`processors/platform_b.json`), representative of deployed CI runner backend services.
- **Platform C (Embedded/IoT Target)**: Microcontroller emulator (ARM Cortex-M / Raspberry Pi Zero, Phase 2 continuation).
- **Custom Platform D (Innovation)**: **Memory-Budgeted High-Risk AST Scanner**
  - **Memory Ceiling Enforcement**: Enforces a strict 64 MB budget (`processors/platform_d.json`). The enforcement operates at the application level via defensive input file-size boundaries (`size <= 64 MB`) and streaming per-file iterator processing, ensuring peak Python heap allocations remain bounded (measured < 210 KB heap on the benchmark fixtures via `tracemalloc`).
  - **Memory Accounting Distinction**: *Python-tracked heap allocation* (measured via `tracemalloc.get_traced_memory()`, ~200 KB) accounts for objects allocated within Python during the scan; *total process memory / RSS* (reported via `psutil`, ~30–50 MB) includes the Python interpreter runtime, shared libraries, and loaded modules.
  - **Pipeline & Concurrency**: Single-worker streaming iterator (`max_workers=1`).
  - **Demonstrated Trade-Off**: Prioritizes deep AST inspection on high-risk Shor-vulnerable asymmetric primitives (RSA, ECC), while processing symmetric baselines with fast regex. Achieves **36.17% precision** and **94.44% recall** with low, stable runtime variance ($\sigma = 1.52\text{ ms}$ vs $3.07\text{ ms}$ for unconstrained AST).

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
.\.venv\Scripts\Activate.ps1
# Windows (Command Prompt):
.\.venv\Scripts\activate.bat
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

### Test Suite Structure (113 Passing Tests)
- `tests/test_regex_scanner.py`: 48 tests (Pattern detection across Python, Java, C, boundary conditions, empty dirs, invalid encodings).
- `tests/test_risk_classifier.py`: 24 tests (PS-P2 taxonomy classification, aliases, purpose-aware recommendations).
- `tests/test_ast_scanner.py`: 14 tests (Comment/string FP elimination, key-size extraction, ECC curves, syntax error handling).
- `tests/test_benchmark.py`: 10 tests (Precision, recall, F1, zero-division guards, duplicate handling, environment capture).
- `tests/test_platform_d.py`: 9 tests (Platform D profile validation, memory ceiling guard, benchmark integration).
- `tests/test_inventory_report.py`: 5 tests (JSON/Markdown report schemas, secret and API-key redaction).
- `tests/test_unified_scanner.py`: 2 tests (Cross-language scanning and comparative differential analysis).
- `tests/test_end_to_end.py`: 1 test (End-to-end integration across scanner, classifier, reporting, and benchmarking).

---

## 7. Actual Benchmark Results & Measurements

> **Transparency Note**: The hackathon organizers' official sample repository and evaluation ground truth are **withheld until judging** (Problem Statement, Page 15). The figures below represent **actual measured values** evaluated on our multi-language labeled benchmark fixtures ([`tests/fixtures/`](tests/fixtures/)). No values are simulated or fabricated.

### Accuracy & Detection Metrics
| Mode / Target Platform | Total Detected | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Regex Baseline (Layer 1)** | 68 | 13 | 55 | 5 | **19.12%** | **72.22%** | **30.23%** |
| **AST-Enriched (Layer 2)** | 47 | 17 | 30 | 1 | **36.17%** | **94.44%** | **52.31%** |
| **Platform D (Custom Innovation)** | 47 | 17 | 30 | 1 | **36.17%** | **94.44%** | **52.31%** |

### Performance & Resource Usage (10 Iterations)
| Target Platform Mode | Mean Runtime | Runtime StdDev ($\sigma$) | Min / Max Runtime | Peak Memory Allocation |
| :--- | :---: | :---: | :---: | :---: |
| **Platform A (Regex Baseline)** | 24.75 ms | 5.21 ms | 18.75 / 33.72 ms | 186.22 KB |
| **Platform A (AST-Enriched)** | 24.71 ms | 5.40 ms | 20.14 / 35.70 ms | 209.07 KB |
| **Platform D (Memory-Budgeted AST)** | 26.57 ms | 3.63 ms | 23.19 / 33.86 ms | 200.08 KB |

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
