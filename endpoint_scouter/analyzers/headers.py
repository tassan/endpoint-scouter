"""
Security headers analyzer for EndpointScouter.
"""

import logging
import requests
from typing import Dict, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


class HeaderAnalyzer:
    """Analyzes security headers in HTTP responses."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the analyzer.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Report-To",
            "NEL",
        ]

    def analyze(self, response: requests.Response, result: ScanResult) -> None:
        """
        Analyze security headers in the response.

        Args:
            response: HTTP response
            result: Scan result to update
        """
        for header in self.security_headers:
            if header.lower() in {h.lower(): h for h in response.headers}:
                header_key = {h.lower(): h for h in response.headers}[header.lower()]
                result.security_headers[header] = response.headers[header_key]

        # Check for HTTPS
        from urllib.parse import urlparse

        parsed_url = urlparse(response.url)
        if parsed_url.scheme != "https":
            result.add_issue("Not using HTTPS")

        # Identify missing important headers
        self._check_missing_headers(result)

    def _check_missing_headers(self, result: ScanResult) -> None:
        """
        Check for missing important security headers.

        Args:
            result: Scan result to update
        """
        important_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content-Security-Policy",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
        }

        for header, issue in important_headers.items():
            if header not in result.security_headers:
                result.add_issue(issue)
