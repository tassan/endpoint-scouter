"""
Result module for EndpointScouter.

This module defines the ScanResult class that represents the results of scanning an endpoint.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

from .endpoint import Endpoint


class ScanResult:
    """Represents the results of scanning an endpoint."""

    def __init__(self, endpoint: Endpoint):
        """Initialize a ScanResult."""
        self.endpoint = endpoint
        self.timestamp = datetime.now().isoformat()
        self.is_accessible = False
        self.status_code = None
        self.response_time = None
        self.security_headers = {}
        self.cors_headers = {}
        self.rate_limit_detected = False
        self.rate_limit_headers = {}
        self.vulnerabilities = {}
        self.issues = []
        self.errors = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary representation."""
        return {
            "url": self.endpoint.url,
            "method": self.endpoint.method,
            "timestamp": self.timestamp,
            "is_accessible": self.is_accessible,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "security_headers": self.security_headers,
            "cors_headers": self.cors_headers,
            "rate_limit_detected": self.rate_limit_detected,
            "rate_limit_headers": self.rate_limit_headers,
            "vulnerabilities": self.vulnerabilities,
            "issues": self.issues,
            "errors": self.errors,
        }

    def add_issue(self, issue: str) -> None:
        """Add an issue to the result."""
        if issue not in self.issues:
            self.issues.append(issue)

    def add_error(self, error: str) -> None:
        """Add an error to the result."""
        if error not in self.errors:
            self.errors.append(error)

    def has_issues(self) -> bool:
        """Check if the result has any issues."""
        return len(self.issues) > 0

    def has_errors(self) -> bool:
        """Check if the result has any errors."""
        return len(self.errors) > 0

    def is_secure(self) -> bool:
        """
        Check if the endpoint is secure based on scan results.

        Returns:
            bool: True if no issues or vulnerabilities, False otherwise
        """
        return (
            not self.has_issues()
            and not any(self.vulnerabilities.values())
            and len(self.security_headers) >= 3
        )


class ScanSummary:
    """Summary of scan results across multiple endpoints."""

    def __init__(self, results: List[ScanResult]):
        """Initialize a ScanSummary."""
        self.results = results
        self.timestamp = datetime.now().isoformat()
        self.total_endpoints = len(results)
        self.accessible_endpoints = sum(1 for r in results if r.is_accessible)
        self.with_issues = sum(1 for r in results if r.issues)
        self.with_cors = sum(1 for r in results if r.cors_headers)
        self.with_rate_limit = sum(1 for r in results if r.rate_limit_detected)
        self.secure_endpoints = sum(1 for r in results if r.is_secure())

        # Group by domain
        self.domains = self._group_by_domain()

        # Collect all unique issues
        self.common_issues = self._collect_common_issues()

    def _group_by_domain(self) -> Dict[str, Dict[str, Any]]:
        """Group results by domain."""
        from urllib.parse import urlparse

        domains = {}

        for result in self.results:
            try:
                domain = urlparse(result.endpoint.url).netloc
                if domain not in domains:
                    domains[domain] = {"count": 0, "issues": 0, "secure": 0}

                domains[domain]["count"] += 1
                domains[domain]["issues"] += len(result.issues)

                if result.is_secure():
                    domains[domain]["secure"] += 1

            except Exception:
                pass

        return domains

    def _collect_common_issues(self) -> Dict[str, int]:
        """Collect common issues across all results."""
        issues = {}

        for result in self.results:
            for issue in result.issues:
                if issue not in issues:
                    issues[issue] = 0
                issues[issue] += 1

        # Sort by frequency
        return dict(sorted(issues.items(), key=lambda x: x[1], reverse=True))

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "total_endpoints": self.total_endpoints,
            "accessible_endpoints": self.accessible_endpoints,
            "with_issues": self.with_issues,
            "with_cors": self.with_cors,
            "with_rate_limit": self.with_rate_limit,
            "secure_endpoints": self.secure_endpoints,
            "domains": self.domains,
            "common_issues": self.common_issues,
        }
