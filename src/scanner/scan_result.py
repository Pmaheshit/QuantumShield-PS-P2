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

    def file_counts(self) -> dict[str, int]:
        """Validate final outcomes and return inventory-ready file counts."""
        discovered = self.discovered_files
        outcome_paths = [outcome.file_path for outcome in self.outcomes]
        if len(set(discovered)) != len(discovered):
            raise ValueError("Scan result contains duplicate discovered file paths.")
        if len(set(outcome_paths)) != len(outcome_paths):
            raise ValueError("Scan result contains duplicate file outcomes.")
        if set(outcome_paths) != set(discovered):
            raise ValueError(
                "Scan result outcomes must account for exactly the discovered files."
            )

        counts = {
            status: sum(outcome.status == status for outcome in self.outcomes)
            for status in ("scanned", "failed", "skipped")
        }
        if any(outcome.status not in counts for outcome in self.outcomes):
            raise ValueError("Scan result contains an unrecognized file outcome.")
        if sum(counts.values()) != len(discovered):
            raise ValueError("Scan result outcomes do not account for every discovered file.")
        return {
            "files_discovered": len(discovered),
            "files_scanned": counts["scanned"],
            "files_failed": counts["failed"],
            "files_skipped": counts["skipped"],
        }
