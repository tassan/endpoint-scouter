"""
CORS configuration analyzer for EndpointScouter.
"""

import logging
import requests
from typing import Dict, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


class CorsAnalyzer:
    """Analyzes CORS configuration in HTTP responses."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.cors_headers = [
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Credentials",
            "Access-Control-Max-Age",
            "Access-Control-Expose-Headers",
        ]
    
    def analyze(self, response: requests.Response, result: ScanResult) -> None:
        """
        Analyze CORS headers in the response.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        # Extract CORS headers
        for header in self.cors_headers:
            if header.lower() in {h.lower(): h for h in response.headers}:
                header_key = {h.lower(): h for h in response.headers}[header.lower()]
                result.cors_headers[header] = response.headers[header_key]
        
        # Check for CORS issues
        self._check_cors_issues(result)
    
    def _check_cors_issues(self, result: ScanResult) -> None:
        """
        Check for CORS configuration issues.
        
        Args:
            result: Scan result to update
        """
        # Check for missing CORS headers
        if not result.cors_headers and result.endpoint.method != "OPTIONS":
            if result.status_code and result.status_code < 400:
                result.add_issue("No CORS headers configured")
        
        # Check for misconfigured CORS
        if "Access-Control-Allow-Origin" in result.cors_headers:
            if result.cors_headers["Access-Control-Allow-Origin"] == "*":
                if ("Access-Control-Allow-Credentials" in result.cors_headers and 
                    result.cors_headers["Access-Control-Allow-Credentials"].lower() == "true"):
                    result.add_issue("Misconfigured CORS: wildcard origin with credentials")