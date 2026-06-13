"""
Exception classes for DTCTM SDK
"""


class DTCTMError(Exception):
    """Base exception for all DTCTM SDK errors."""
    pass


class AuthenticationError(DTCTMError):
    """Raised when authentication fails (invalid API key, token expired)."""
    pass


class RateLimitError(DTCTMError):
    """Raised when rate limit is exceeded."""
    pass


class ScanError(DTCTMError):
    """Raised when a scan fails."""
    pass


class BatchError(DTCTMError):
    """Raised when a batch operation fails."""
    pass


class FileError(DTCTMError):
    """Raised when file upload fails."""
    pass


class APIError(DTCTMError):
    """Raised when API returns an error."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API Error {status_code}: {detail}")


class TimeoutError(DTCTMError):
    """Raised when request times out."""
    pass


class ConnectionError(DTCTMError):
    """Raised when connection to API fails."""
    pass
