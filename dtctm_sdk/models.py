"""
Data models for DTCTM SDK
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class ScanResult:
    """Result from a completed scan."""
    scan_id: str
    target: str
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
    score: float
    severity: str  # low, medium, high, critical
    findings: List[str]
    scan_time_ms: float
    timestamp: datetime

    def is_malicious(self) -> bool:
        """Check if scan detected malicious content."""
        return self.verdict == "MALICIOUS"

    def is_suspicious(self) -> bool:
        """Check if scan detected suspicious content."""
        return self.verdict == "SUSPICIOUS"

    def is_clean(self) -> bool:
        """Check if scan detected clean content."""
        return self.verdict == "CLEAN"


@dataclass
class BatchStatus:
    """Status of a batch job."""
    batch_id: str
    status: str  # pending, processing, complete
    progress_pct: float
    total_scans: int
    scans_completed: int
    current_target: Optional[str]
    eta_seconds: int
    results: List[ScanResult]
    created_at: datetime
    completed_at: Optional[datetime] = None

    def is_complete(self) -> bool:
        """Check if batch is complete."""
        return self.status == "complete"

    def is_processing(self) -> bool:
        """Check if batch is currently processing."""
        return self.status == "processing"

    def malicious_count(self) -> int:
        """Get count of malicious results."""
        return sum(1 for r in self.results if r.is_malicious())

    def suspicious_count(self) -> int:
        """Get count of suspicious results."""
        return sum(1 for r in self.results if r.is_suspicious())

    def clean_count(self) -> int:
        """Get count of clean results."""
        return sum(1 for r in self.results if r.is_clean())


@dataclass
class HealthStatus:
    """System health status."""
    status: str  # healthy, degraded, unhealthy
    timestamp: datetime
    api_version: str
    database_ok: bool
    ml_model_ok: bool
    threat_intel_apis: Dict[str, bool]
    uptime_seconds: int

    def is_healthy(self) -> bool:
        """Check if system is healthy."""
        return self.status == "healthy"

    def api_health_pct(self) -> float:
        """Get percentage of healthy threat intel APIs."""
        if not self.threat_intel_apis:
            return 0.0
        healthy = sum(1 for v in self.threat_intel_apis.values() if v)
        return (healthy / len(self.threat_intel_apis)) * 100


@dataclass
class TokenResponse:
    """JWT token response."""
    access_token: str
    token_type: str
    expires_in: int

    def is_expired(self) -> bool:
        """Check if token is expired (always False for new tokens)."""
        return False


@dataclass
class APIError:
    """API error response."""
    status_code: int
    detail: str
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None

    def __str__(self) -> str:
        """Format error message."""
        return f"API Error {self.status_code}: {self.detail}"
