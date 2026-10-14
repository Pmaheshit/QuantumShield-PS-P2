"""
main.py
───────
QuantumShield PS-P2: Cryptographic Inventory & Migration Planner.
Primary submission entry-point for Qiskit Fall Fest 2026.

Executes the complete end-to-end workflow:
  1. Scans multi-language source codebases (Python, Java, C).
  2. Rates quantum vulnerability according to the official PS-P2 risk taxonomy:
     - HIGH (RSA, ECC, ECDSA, ECDH) -> Shor's algorithm threat
     - MODERATE (AES-128) -> Grover's algorithm key halving
     - LOWER (AES-256, SHA-256) -> Quantum-safe symmetric/hash baselines
  3. Recommends purpose-specific post-quantum replacements (FIPS 203 ML-KEM vs FIPS 204 ML-DSA).
  4. Generates machine-readable JSON and human-readable Markdown inventory reports.
  5. Runs the reproducible 3-mode benchmark (Regex, AST-Enriched, Platform D).
  6. Exports benchmark metrics to results/tables/ and figures to results/figures/.

Usage:
  python main.py [--scan-dir DIR] [--runs N] [--output-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.benchmark.runner import BenchmarkHarness
from src.platforms.platform_config import export_platform_definitions
from src.reporting.inventory_report import InventoryReportGenerator
from src.scanner.unified_scanner import UnifiedScanner


def run_full_pipeline(
    scan_dir: str | Path = "tests/fixtures",
    runs: int = 10,
    output_dir: str | Path = "results",
) -> dict:
    scan_path = Path(scan_dir).resolve()
    out_path = Path(output_dir).resolve()
    tables_dir = out_path / "tables"
    figures_dir = out_path / "figures"
    processors_dir = Path("processors").resolve()

    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    processors_dir.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("  QuantumShield PS-P2: Crypto Inventory & Migration Planner")
    print("  Qiskit Fall Fest 2026 — End-to-End Execution Pipeline")
    print("======================================================================")
    print(f"[*] Target Scan Path:      {scan_path}")
    print(f"[*] Benchmark Iterations:  {runs}")
    print(f"[*] Output Directory:      {out_path}")
    print()

    # Step 1: Export target platform definitions
    print("[1/4] Exporting Target Platform specifications to processors/...")
    export_platform_definitions(processors_dir)
    print(f"      Exported: {[p.name for p in processors_dir.glob('*.json')]}")

    # Step 2: Multi-Language Cryptographic Scan
    print("[2/4] Executing AST-enriched multi-language cryptographic scan...")
    scanner = UnifiedScanner(root=scan_path, use_ast_for_python=True)
    findings = scanner.scan()
    print(f"      Detected {len(findings)} cryptographic findings across target repository.")

    # Step 3: Generate Inventory Reports
    print("[3/4] Generating structured inventory reports...")
    total_files = len(list(scanner._iter_source_files()))
    rep_gen = InventoryReportGenerator(findings, scanned_root=str(scan_path), total_files_scanned=total_files)

    json_report = rep_gen.generate_json()
    md_report = rep_gen.generate_markdown()

    json_report_path = tables_dir / "inventory_report.json"
    md_report_path = out_path / "inventory_report.md"

    json_report_path.write_text(json_report, encoding="utf-8")
    md_report_path.write_text(md_report, encoding="utf-8")
    print(f"      Report written to: {json_report_path}")
    print(f"      Report written to: {md_report_path}")

    # Step 4: Reproducible Multi-Platform Benchmark
    print(f"[4/4] Executing comparative benchmark ({runs} runs per platform mode)...")
    harness = BenchmarkHarness(target_dir=scan_path, runs=runs, platform_name="Platform A (Local Workstation/Cloud Host)")
    bench_results = harness.run_benchmark(include_platform_d=True, include_platform_b=True)

    bench_json_path = tables_dir / "benchmark_results.json"
    bench_csv_path = tables_dir / "benchmark_results.csv"
    bench_md_path = out_path / "benchmark_report.md"

    harness.export_json(bench_results, bench_json_path)
    harness.export_csv(bench_results, bench_csv_path)
    harness.export_markdown_summary(bench_results, bench_md_path)

    print(f"      Benchmark results written to: {bench_json_path}")
    print(f"      Benchmark metrics written to: {bench_csv_path}")
    print(f"      Benchmark summary written to: {bench_md_path}")

    # Optional plot generation if matplotlib is available
    try:
        import matplotlib.pyplot as plt

        available_modes = []
        available_keys = []
        available_colors = []

        mode_specs = [
            ("Regex (Layer 1)",   "regex_only",  "#4A90E2"),
            ("AST (Layer 2)",     "ast_enriched", "#50E3C2"),
            ("Platform B",        "platform_b",   "#F5A623"),
            ("Platform D",        "platform_d",   "#B8E986"),
        ]
        for label, key, color in mode_specs:
            if key in bench_results["results"]:
                available_modes.append(label)
                available_keys.append(key)
                available_colors.append(color)

        times = [bench_results["results"][k]["mean_time_ms"] for k in available_keys]

        fig, ax = plt.subplots(figsize=(9, 4.5))
        bars = ax.bar(available_modes, times, color=available_colors, width=0.5)
        ax.set_ylabel("Mean Execution Time (ms)")
        ax.set_title("QuantumShield PS-P2: Scanner Runtime by Target Platform Mode")
        for bar in bars:
            yval = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                yval + 0.3,
                f"{yval:.2f} ms",
                ha="center", va="bottom", fontsize=10,
            )

        plt.tight_layout()
        plot_path = figures_dir / "runtime_comparison.png"
        fig.savefig(plot_path, dpi=150)
        plt.close(fig)
        print(f"      Comparative figure written to: {plot_path}")
    except Exception as exc:
        print(f"      [Info] Plot generation skipped: {exc}")

    print()
    print("======================================================================")
    print("  Pipeline execution complete! All artifacts generated successfully.")
    print("======================================================================")

    return {
        "findings_count": len(findings),
        "benchmark_results": bench_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="quantumshield",
        description="QuantumShield PS-P2: End-to-end Cryptographic Scanner & Benchmark Pipeline",
    )
    parser.add_argument(
        "--scan-dir",
        default="tests/fixtures",
        help="Target repository or directory to scan (default: tests/fixtures)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of iterations for benchmark timing (default: 10)",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory to save generated reports and tables (default: results)",
    )
    args = parser.parse_args()

    run_full_pipeline(scan_dir=args.scan_dir, runs=args.runs, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
