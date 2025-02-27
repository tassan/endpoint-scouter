"""
Scanner module for EndpointScouter.

This module orchestrates the scanning process for endpoints.
"""

import yaml
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Local imports
from endpoint_scouter.core.endpoint import Endpoint
from endpoint_scouter.core.result import ScanResult
from endpoint_scouter.analyzers.headers import HeaderAnalyzer
from endpoint_scouter.analyzers.cors import CorsAnalyzer
from endpoint_scouter.analyzers.rate_limit import RateLimitAnalyzer
from endpoint_scouter.analyzers.vulnerabilities import VulnerabilityAnalyzer

logger = logging.getLogger("EndpointScouter")


class Scanner:
    """Main scanner class that orchestrates the endpoint scanning process."""

    def __init__(self, config_path: str):
        """
        Initialize the scanner with configuration.

        Args:
            config_path: Path to the YAML configuration file
        """
        self.config = self._load_config(config_path)
        self.settings = self.config.get("settings", {})
        self.test_config = self.config.get("tests", {})
        self.endpoints = self._load_endpoints()
        self.results = []
        self.session = self._create_session()

        # Initialize analyzers
        self.analyzers = self._initialize_analyzers()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            Dict: Configuration dictionary
        """
        try:
            with open(config_path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file)

            logger.info(f"Loaded configuration from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise

    def _load_endpoints(self) -> List[Endpoint]:
        """
        Load endpoints from configuration.

        Returns:
            List[Endpoint]: List of endpoints to scan
        """
        endpoints = []

        for ep_data in self.config.get("endpoints", []):
            try:
                endpoint = Endpoint(
                    url=ep_data["url"],
                    method=ep_data.get("method", "GET"),
                    headers=ep_data.get("headers", {}),
                    payload=ep_data.get("payload"),
                    description=ep_data.get("description"),
                    tags=ep_data.get("tags", []),
                )
                endpoints.append(endpoint)
            except (KeyError, ValueError) as e:
                logger.warning(f"Invalid endpoint configuration: {str(e)}")

        logger.info(f"Loaded {len(endpoints)} endpoints from configuration")
        return endpoints

    def _create_session(self) -> requests.Session:
        """
        Create a session with retry capabilities.

        Returns:
            requests.Session: Configured session
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=[
                "HEAD",
                "GET",
                "OPTIONS",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
            ],
            backoff_factor=1,
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        user_agent = self.settings.get("user_agent", "EndpointScouter/1.0")
        session.headers.update({"User-Agent": user_agent})

        return session

    def _initialize_analyzers(self) -> Dict[str, Any]:
        """
        Initialize all analyzers.

        Returns:
            Dict[str, Any]: Dictionary of analyzer instances
        """
        return {
            "headers": HeaderAnalyzer(self.config),
            "cors": CorsAnalyzer(self.config),
            "rate_limit": RateLimitAnalyzer(self.config),
            "vulnerabilities": VulnerabilityAnalyzer(self.config),
        }

    def scan_endpoint(self, endpoint: Endpoint) -> ScanResult:
        """
        Scan a single endpoint and run all configured tests.

        Args:
            endpoint: Endpoint to scan

        Returns:
            ScanResult: Results of the scan
        """
        logger.info(f"Scanning endpoint: {endpoint.method} {endpoint.url}")

        result = ScanResult(endpoint)

        try:
            # Make the initial request
            start_time = time.time()
            response = self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=endpoint.headers,
                json=(
                    endpoint.payload
                    if endpoint.method in ["POST", "PUT", "PATCH"] and endpoint.payload
                    else None
                ),
                timeout=self.settings.get("timeout", 5),
                allow_redirects=False,
            )
            result.response_time = round(time.time() - start_time, 3)
            result.is_accessible = True
            result.status_code = response.status_code

            # Run all enabled tests
            self._run_all_tests(response, result)

        except requests.exceptions.Timeout:
            result.add_error("Connection timeout")
        except requests.exceptions.ConnectionError:
            result.add_error("Connection error")
        except requests.exceptions.RequestException as e:
            result.add_error(f"Request error: {str(e)}")
        except Exception as e:
            result.add_error(f"Unexpected error: {str(e)}")

        return result

    def _run_all_tests(self, response: requests.Response, result: ScanResult) -> None:
        """
        Run all enabled tests on the response.

        Args:
            response: HTTP response
            result: Scan result to update
        """
        # Security headers test
        if self.test_config.get("security_headers", True):
            self.analyzers["headers"].analyze(response, result)

        # CORS headers test
        if self.test_config.get("cors_headers", True):
            self.analyzers["cors"].analyze(response, result)

        # Rate limiting test
        if self.test_config.get("rate_limiting", True):
            self.analyzers["rate_limit"].analyze(response, result)

        # Vulnerability scan
        if self.test_config.get("vulnerability_scan", True):
            self.analyzers["vulnerabilities"].analyze(response, result)

    def scan_all(self) -> List[ScanResult]:
        """
        Scan all endpoints in parallel.

        Returns:
            List[ScanResult]: Results of all scans
        """
        max_workers = self.settings.get("max_workers", 10)

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                self.results = list(executor.map(self.scan_endpoint, self.endpoints))

            logger.info(f"Scan completed for {len(self.results)} endpoints")
            return self.results
        except Exception as e:
            logger.error(f"Error scanning endpoints: {str(e)}")
            raise

    def calculate_security_score(self) -> str:
        """
        Calculate overall security score based on scan results.

        Returns:
            str: Security score with message
        """
        if not self.results:
            return "0 - No results to score"

        total_score = 0
        max_score_per_endpoint = 9000

        for result in self.results:
            endpoint_score = 0

            # Points for security headers
            endpoint_score += len(result.security_headers) * 500

            # Points for CORS configuration
            if result.cors_headers:
                origin_header = result.cors_headers.get("Access-Control-Allow-Origin")
                if origin_header and origin_header != "*":
                    endpoint_score += 1500  # Restrictive CORS
                else:
                    endpoint_score += 500  # CORS configured, but permissive

            # Points for rate limiting
            if result.rate_limit_detected:
                endpoint_score += 2000

            # Deduct points for issues
            endpoint_score -= len(result.issues) * 300

            # Deduct points for vulnerabilities
            if result.vulnerabilities:
                endpoint_score -= (
                    sum(1 for v in result.vulnerabilities.values() if v) * 1000
                )

            # Limit maximum endpoint score
            endpoint_score = max(0, min(endpoint_score, max_score_per_endpoint))
            total_score += endpoint_score

        # Average score
        avg_score = total_score / len(self.results)

        # Return score with appropriate message
        dbz_mode = self.settings.get("dbz_mode", False)

        # Return score with appropriate message based on mode
        if dbz_mode:
            if avg_score >= 8000:
                return f"{avg_score:.0f} - IT'S OVER 8000! Super Saiyan level security!"
            elif avg_score >= 6000:
                return f"{avg_score:.0f} - Super Saiyan: Excellent security implementation!"
            elif avg_score >= 5000:
                return f"{avg_score:.0f} - Elite Saiyan: Very good security measures"
            elif avg_score >= 3000:
                return f"{avg_score:.0f} - Saiyan Warrior: Good foundation but room for improvement"
            elif avg_score >= 1000:
                return (
                    f"{avg_score:.0f} - Trained Human: Basic security measures present"
                )
            else:
                return f"{avg_score:.0f} - Ordinary Human... serious security improvements needed!"
        else:
            if avg_score >= 8000:
                return f"{avg_score:.0f} - Excellent. Comprehensive security measures implemented."
            elif avg_score >= 6000:
                return f"{avg_score:.0f} - Very Good. Strong security implementation."
            elif avg_score >= 5000:
                return f"{avg_score:.0f} - Good. Strong security foundation present."
            elif avg_score >= 3000:
                return f"{avg_score:.0f} - Moderate. Basic security measures in place."
            elif avg_score >= 1000:
                return f"{avg_score:.0f} - Fair. Minimal security protections detected."
            else:
                return f"{avg_score:.0f} - Inadequate. Security improvements strongly recommended."
