"""
DTCTM SDK Client - Main API client classes
"""

import requests
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
import websocket

from .models import ScanResult, BatchStatus, HealthStatus, TokenResponse
from .exceptions import (
    AuthenticationError, RateLimitError, ScanError, BatchError,
    FileError, APIError, TimeoutError, ConnectionError, DTCTMError
)


class ForensicScanner:
    """Client for scanning individual URLs and files.

    Example:
        >>> scanner = ForensicScanner(api_key="your-key")
        >>> result = scanner.scan_url("https://example.com")
        >>> print(f"Verdict: {result.verdict}")
        >>> print(f"Score: {result.score:.2f}")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        timeout: int = 30
    ):
        """Initialize scanner.

        Args:
            api_key: API key for authentication
            base_url: Base URL of API (default: localhost:8000)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "dtctm-sdk/1.0.0"
        })

    def scan_url(
        self,
        url: str,
        priority: int = 5,
        notify_email: Optional[str] = None,
        report_format: str = "json"
    ) -> Dict[str, Any]:
        """Scan a URL.

        Args:
            url: URL to scan
            priority: Priority level (1-10, default 5)
            notify_email: Optional email for notification
            report_format: Format of report (json, pdf, or both)

        Returns:
            Dictionary with scan_id and status

        Raises:
            AuthenticationError: If API key is invalid
            RateLimitError: If rate limit exceeded
            ScanError: If scan fails
        """
        try:
            payload = {
                "url": url,
                "priority": priority,
                "notify_email": notify_email,
                "report_format": report_format
            }
            response = self.session.post(
                f"{self.base_url}/api/v1/scan/url",
                json=payload,
                timeout=self.timeout
            )

            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded")
            elif response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            elif response.status_code != 200:
                raise APIError(response.status_code, response.text)

            return response.json()
        except requests.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to API: {e}")
        except requests.Timeout as e:
            raise TimeoutError(f"Request timed out: {e}")

    def scan_file(
        self,
        file_path: str,
        priority: int = 5
    ) -> Dict[str, Any]:
        """Upload and scan a file.

        Args:
            file_path: Path to file to scan
            priority: Priority level (1-10)

        Returns:
            Dictionary with scan_id and status

        Raises:
            FileError: If file upload fails
            ScanError: If scan fails
        """
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f"{self.base_url}/api/v1/scan/file",
                    files=files,
                    params={"priority": priority},
                    timeout=self.timeout
                )

            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded")
            elif response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            elif response.status_code != 200:
                raise APIError(response.status_code, response.text)

            return response.json()
        except FileNotFoundError:
            raise FileError(f"File not found: {file_path}")
        except requests.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to API: {e}")

    def get_result(self, scan_id: str) -> ScanResult:
        """Get result of a completed scan.

        Args:
            scan_id: ID of scan to retrieve

        Returns:
            ScanResult object with verdict and score
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/scan/{scan_id}",
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        data = response.json()
        return ScanResult(
            scan_id=data['scan_id'],
            target=data.get('target', ''),
            verdict=data['verdict'],
            score=float(data['score']),
            severity=data['severity'],
            findings=data.get('findings', []),
            scan_time_ms=float(data.get('scan_time_ms', 0)),
            timestamp=datetime.fromisoformat(data['timestamp'])
        )

    def download_report(self, scan_id: str, format: str = "pdf") -> bytes:
        """Download scan report.

        Args:
            scan_id: ID of scan
            format: Report format (pdf, json, html)

        Returns:
            Report file content as bytes
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/scan/{scan_id}/report",
            params={"format": format},
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        return response.content


class BatchScanner:
    """Client for batch scanning operations.

    Example:
        >>> batch = BatchScanner(api_key="your-key")
        >>> batch_id = batch.submit(["https://a.com", "https://b.com"])
        >>> status = batch.get_status(batch_id)
        >>> print(f"Progress: {status.progress_pct}%")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        timeout: int = 30
    ):
        """Initialize batch scanner.

        Args:
            api_key: API key for authentication
            base_url: Base URL of API
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "dtctm-sdk/1.0.0"
        })

    def submit(
        self,
        targets: List[str],
        batch_name: str = "batch",
        target_type: str = "url",
        priority: int = 5,
        notify_on_complete: bool = False
    ) -> str:
        """Submit a batch of URLs/files for scanning.

        Args:
            targets: List of URLs or file paths
            batch_name: Human-readable batch name
            target_type: Type of target (url, file, hash)
            priority: Priority level (1-10)
            notify_on_complete: Whether to send email notification

        Returns:
            batch_id for tracking

        Raises:
            RateLimitError: If rate limit exceeded
            BatchError: If batch submission fails
        """
        try:
            payload = {
                "targets": targets,
                "batch_name": batch_name,
                "target_type": target_type,
                "priority": priority,
                "notify_on_complete": notify_on_complete
            }
            response = self.session.post(
                f"{self.base_url}/api/v1/scan/batch",
                json=payload,
                timeout=self.timeout
            )

            if response.status_code == 429:
                raise RateLimitError("Rate limit exceeded")
            elif response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            elif response.status_code != 200:
                raise APIError(response.status_code, response.text)

            return response.json()['batch_id']
        except requests.ConnectionError as e:
            raise ConnectionError(f"Failed to connect to API: {e}")

    def get_status(self, batch_id: str) -> BatchStatus:
        """Get status of a batch job.

        Args:
            batch_id: ID of batch

        Returns:
            BatchStatus object with progress and results
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/batch/{batch_id}",
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        data = response.json()
        return BatchStatus(
            batch_id=data['batch_id'],
            status=data['status'],
            progress_pct=float(data['progress_pct']),
            total_scans=int(data['total_scans']),
            scans_completed=int(data['scans_completed']),
            current_target=data.get('current_target'),
            eta_seconds=int(data['eta_seconds']),
            results=[],
            created_at=datetime.now()
        )

    def get_results(
        self,
        batch_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get results from a completed batch.

        Args:
            batch_id: ID of batch
            limit: Maximum results to return
            offset: Number of results to skip

        Returns:
            List of scan results
        """
        response = self.session.get(
            f"{self.base_url}/api/v1/batch/{batch_id}/results",
            params={"limit": limit, "offset": offset},
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        return response.json()

    def cancel(self, batch_id: str) -> bool:
        """Cancel a batch job.

        Args:
            batch_id: ID of batch to cancel

        Returns:
            True if cancelled successfully
        """
        response = self.session.post(
            f"{self.base_url}/api/v1/batch/{batch_id}/cancel",
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        return True

    def retry_failures(self, batch_id: str) -> int:
        """Retry all failed scans in a batch.

        Args:
            batch_id: ID of batch

        Returns:
            Number of jobs requeued
        """
        response = self.session.post(
            f"{self.base_url}/api/v1/batch/{batch_id}/retry",
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text)

        return response.json().get('jobs_requeued', 0)

    def stream_progress(self, batch_id: str):
        """Stream batch progress in real-time via WebSocket.

        Args:
            batch_id: ID of batch

        Yields:
            Progress update dictionaries
        """
        ws_url = f"ws://localhost:8000/ws/batch/{batch_id}".replace("http://", "ws://")

        try:
            ws = websocket.create_connection(ws_url)

            while True:
                data = ws.recv()
                if not data:
                    break

                event = json.loads(data)
                yield event

                if event.get('event') == 'complete':
                    break

            ws.close()
        except Exception as e:
            raise ConnectionError(f"WebSocket connection failed: {e}")
