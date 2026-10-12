"""
src/platforms/platform_config.py
────────────────────────────────
Platform definitions and execution constraints for QuantumShield PS-P2.

Post-Quantum Cryptography Track Target Platforms:
  • Platform A (resource-rich baseline): A standard x86-64 workstation / cloud VM.
  • Platform B (constrained server): Single CPU core, memory-capped (backend service / CI runner).
  • Platform C (embedded/IoT target): Microcontroller class device (Phase 2 continuation).
  • Platform D (custom innovation): User-defined execution profile exposing a genuine trade-off.

Platform D Architecture for QuantumShield Scanner:
  "Low-Memory Streaming & Targeted High-Risk AST Scanner"
  - Memory ceiling: 64 MB heap limit.
  - Workers / Concurrency: Single-worker streaming iterator.
  - Optimization: High-risk targeted analysis (AST prioritized for asymmetric primitives
    RSA/ECC to minimize migration risk while reducing parsing overhead).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class PlatformProfile:
    """Configuration specification for a target platform."""
    platform_id: str             # "platform_a" | "platform_b" | "platform_c" | "platform_d"
    name: str                    # Human-readable platform title
    category: str                # "baseline" | "constrained_server" | "embedded" | "custom_innovation"
    description: str
    max_workers: int = 1         # CPU parallelism limit
    memory_limit_mb: Optional[int] = None
    stream_chunk_size: int = 65536
    scan_strategy: str = "full"  # "full" | "high_risk_priority" | "regex_fast" | "ast_deep"
    parameters: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate platform configuration constraints."""
        if self.max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {self.max_workers}")
        if self.memory_limit_mb is not None and self.memory_limit_mb <= 0:
            raise ValueError(f"memory_limit_mb must be > 0 if specified, got {self.memory_limit_mb}")
        if self.stream_chunk_size < 1024:
            raise ValueError(f"stream_chunk_size must be >= 1024 bytes, got {self.stream_chunk_size}")
        if self.scan_strategy not in ("full", "high_risk_priority", "regex_fast", "ast_deep"):
            raise ValueError(f"Unsupported scan_strategy: {self.scan_strategy}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlatformProfile:
        return cls(**data)


# Standard Platform Profiles defined by competition rubric
PLATFORM_A = PlatformProfile(
    platform_id="platform_a",
    name="Platform A (Resource-Rich Workstation / Cloud VM)",
    category="baseline",
    description="Standard x86-64 host machine, full memory availability, multi-thread capability.",
    max_workers=4,
    memory_limit_mb=None,
    scan_strategy="full",
)

PLATFORM_B = PlatformProfile(
    platform_id="platform_b",
    name="Platform B (Constrained Server / CI Runner)",
    category="constrained_server",
    description="Single-core CPU execution, capped resources representative of deployed CI pipelines.",
    max_workers=1,
    memory_limit_mb=512,
    scan_strategy="full",
)

PLATFORM_C = PlatformProfile(
    platform_id="platform_c",
    name="Platform C (Embedded / IoT Target)",
    category="embedded",
    description="Constrained microcontroller emulator (ARM Cortex-M / Raspberry Pi Zero, Phase 2).",
    max_workers=1,
    memory_limit_mb=32,
    scan_strategy="regex_fast",
)

PLATFORM_D = PlatformProfile(
    platform_id="platform_d",
    name="Platform D (Custom Innovation: Memory-Budgeted High-Risk AST Scanner)",
    category="custom_innovation",
    description=(
        "Stream-oriented, single-worker pipeline with 64 MB memory ceiling and "
        "priority AST inspection on asymmetric Shor-vulnerable primitives (RSA, ECC) "
        "providing maximal PQC migration coverage with minimum resource footprint."
    ),
    max_workers=1,
    memory_limit_mb=64,
    scan_strategy="high_risk_priority",
    parameters={
        "streaming_io": True,
        "asymmetric_priority_ast": True,
        "target_algorithms": ["RSA", "ECDSA", "ECDH", "ECC"],
    },
)

STANDARD_PLATFORMS: dict[str, PlatformProfile] = {
    "platform_a": PLATFORM_A,
    "platform_b": PLATFORM_B,
    "platform_c": PLATFORM_C,
    "platform_d": PLATFORM_D,
}


def get_platform_profile(platform_id: str) -> PlatformProfile:
    """Retrieve platform profile by ID or raise KeyError."""
    pid = platform_id.lower().strip()
    if pid not in STANDARD_PLATFORMS:
        raise KeyError(f"Unknown platform ID: {platform_id}. Available: {list(STANDARD_PLATFORMS.keys())}")
    return STANDARD_PLATFORMS[pid]


def export_platform_definitions(output_dir: str | Path) -> None:
    """Export platform profile definitions as JSON files to processors/ or config dir."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for pid, profile in STANDARD_PLATFORMS.items():
        file_path = out / f"{pid}.json"
        file_path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
