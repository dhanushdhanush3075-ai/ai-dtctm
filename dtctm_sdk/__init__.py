"""
AI-DTCTM Python SDK
═════════════════════════════════════════════════════════════════════
Official Python SDK for the AI-DTCTM Forensic Scanner API.

Installation:
    pip install dtctm-sdk

Quick Start:
    from dtctm import ForensicScanner

    scanner = ForensicScanner(api_key="your-api-key")
    result = scanner.scan_url("https://example.com")
    print(f"Verdict: {result.verdict}")
    print(f"Score: {result.score}")

Author: AI-DTCTM Development Team
"""

from .client import ForensicScanner, BatchScanner
from .models import ScanResult, BatchStatus
from .exceptions import DTCTMError, ScanError, BatchError

__version__ = "1.0.0"
__all__ = [
    "ForensicScanner",
    "BatchScanner",
    "ScanResult",
    "BatchStatus",
    "DTCTMError",
    "ScanError",
    "BatchError",
]
