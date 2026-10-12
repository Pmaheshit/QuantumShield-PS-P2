"""
src/platforms/__init__.py
"""
from .platform_config import (
    PLATFORM_A,
    PLATFORM_B,
    PLATFORM_C,
    PLATFORM_D,
    STANDARD_PLATFORMS,
    PlatformProfile,
    export_platform_definitions,
    get_platform_profile,
)
from .platform_d_scanner import PlatformDScanner

__all__ = [
    "PlatformProfile",
    "PLATFORM_A",
    "PLATFORM_B",
    "PLATFORM_C",
    "PLATFORM_D",
    "STANDARD_PLATFORMS",
    "get_platform_profile",
    "export_platform_definitions",
    "PlatformDScanner",
]
