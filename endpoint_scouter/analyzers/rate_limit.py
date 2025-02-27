"""
Rate limiting analyzer for EndpointScouter.
"""

import logging
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


class RateLimitAnalyzer:
    """Analyzes rate limiting implementation in HTTP responses."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the analyzer.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
        ]

    def analyze(self, response: requests.Response, result: ScanResult) -> None:
        """
        Analyze rate limiting in the response.

        Args:
            response: HTTP response
            result: Scan result to update
        """
        # Check for rate limiting headers
        for header in (rate_headers := {h.lower(): h for h in response.headers}):
            if any(
                limit_header.lower() in header
                for limit_header in self.rate_limit_headers
            ):
                result.rate_limit_headers[rate_headers[header]] = response.headers[
                    rate_headers[header]
                ]

        # If no rate limiting headers detected, try making several requests
        if not result.rate_limit_headers:
            # Get settings from config
            test_count = self.config.get("rate_limit_test_count", 10)
            max_workers = self.config.get("max_workers", 10)
            timeout = self.config.get("timeout", 5)

            rate_limited = self._test_rate_limiting(
                result.endpoint.url,
                result.endpoint.method,
                result.endpoint.headers,
                test_count,
                max_workers,
                timeout,
            )
            result.rate_limit_detected = rate_limited
        else:
            result.rate_limit_detected = True

        # Add issue if no rate limiting detected
        if not result.rate_limit_detected:
            result.add_issue("No rate limiting detected")

    def _test_rate_limiting(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        test_count: int = 10,
        max_workers: int = 10,
        timeout: int = 5,
    ) -> bool:
        """
        Test if the endpoint implements rate limiting.

        Args:
            url: URL to test
            method: HTTP method
            headers: HTTP headers
            test_count: Number of requests to make
            max_workers: Maximum number of workers
            timeout: Request timeout

        Returns:
            bool: Whether rate limiting was detected
        """
        with ThreadPoolExecutor(max_workers=min(test_count, max_workers)) as executor:
            futures = []
            for _ in range(test_count):
                futures.append(
                    executor.submit(
                        self._make_single_request, method, url, headers, timeout
                    )
                )

            # Check if any request returned 429
            for future in futures:
                try:
                    if future.result() == 429:
                        return True
                except Exception:
                    pass

        return False

    def _make_single_request(
        self, method: str, url: str, headers: Dict[str, str], timeout: int
    ) -> Optional[int]:
        """
        Make a single request and return the status code.

        Args:
            method: HTTP method
            url: URL to request
            headers: HTTP headers
            timeout: Request timeout

        Returns:
            int: Status code or None if request failed
        """
        try:
            # Add a small random delay to avoid exact simultaneous requests
            time.sleep(random.uniform(0, 0.1))

            response = requests.request(
                method=method, url=url, headers=headers, timeout=timeout
            )
            return response.status_code
        except Exception:
            return None
