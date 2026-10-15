"""Explicit per-file processing outcomes for scanner runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .regex_scanner import Finding

ScanStatus = Literal["scanned", "failed", "skipped"]


@dataclass(frozen=True)
class FileScanOutcome:
    file_path: str
    status: ScanStatus
    reason: str = ""


@dataclass
class ScanResult:
    findings: list[Finding]
    outcomes: list[FileScanOutcome]
    discovered_files: tuple[str, ...]
