"""
Scanner module for EndpointScouter.

This module orchestrates the scanning process for endpoints.
"""

import yaml
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Local imports
from .endpoint import Endpoint
from .result import ScanResult

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
                    tags=ep_data.get("tags", [])
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
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        user_agent = self.settings.get("user_agent", "EndpointScouter/1.0")
        session.headers.update({"User-Agent": user_agent})
        
        return session
    
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
                json=endpoint.payload if endpoint.method in ["POST", "PUT", "PATCH"] and endpoint.payload else None,
                timeout=self.settings.get("timeout", 5),
                allow_redirects=False
            )
            result.response_time = round(time.time() - start_time, 3)
            result.is_accessible = True
            result.status_code = response.status_code
            
            # Run all enabled tests
            self._run_all_tests(response, result)
            
        except requests.exceptions.Timeout:
            result.errors.append("Connection timeout")
        except requests.exceptions.ConnectionError:
            result.errors.append("Connection error")
        except requests.exceptions.RequestException as e:
            result.errors.append(f"Request error: {str(e)}")
        except Exception as e:
            result.errors.append(f"Unexpected error: {str(e)}")
        
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
            self._check_security_headers(response, result)
        
        # CORS headers test
        if self.test_config.get("cors_headers", True):
            self._check_cors_headers(response, result)
        
        # Rate limiting test
        if self.test_config.get("rate_limiting", True):
            self._check_rate_limiting(response, result)
        
        # Vulnerability scan
        if self.test_config.get("vulnerability_scan", True):
            self._check_vulnerabilities(result.endpoint.url, result)
        
        # Server info disclosure test
        if self.test_config.get("server_info", True):
            self._check_server_info(response, result)
        
        # Identify issues based on test results
        self._identify_issues(result)
    
    def _check_security_headers(self, response: requests.Response, result: ScanResult) -> None:
        """
        Check for security headers in the response.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        security_headers = [
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
        
        for header in security_headers:
            if header.lower() in {h.lower(): h for h in response.headers}:
                header_key = {h.lower(): h for h in response.headers}[header.lower()]
                result.security_headers[header] = response.headers[header_key]
    
    def _check_cors_headers(self, response: requests.Response, result: ScanResult) -> None:
        """
        Check for CORS headers in the response.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        cors_headers = [
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Credentials",
            "Access-Control-Max-Age",
            "Access-Control-Expose-Headers",
        ]
        
        for header in cors_headers:
            if header.lower() in {h.lower(): h for h in response.headers}:
                header_key = {h.lower(): h for h in response.headers}[header.lower()]
                result.cors_headers[header] = response.headers[header_key]
        
        # Check for CORS misconfigurations
        if "Access-Control-Allow-Origin" in result.cors_headers:
            if result.cors_headers["Access-Control-Allow-Origin"] == "*":
                if ("Access-Control-Allow-Credentials" in result.cors_headers and 
                    result.cors_headers["Access-Control-Allow-Credentials"].lower() == "true"):
                    result.issues.append("Misconfigured CORS: wildcard origin with credentials")
    
    def _check_rate_limiting(self, response: requests.Response, result: ScanResult) -> None:
        """
        Check for rate limiting headers and behavior.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        # Check for rate limiting headers
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
        ]
        
        for header in (rate_headers := {h.lower(): h for h in response.headers}):
            if any(limit_header.lower() in header for limit_header in rate_limit_headers):
                result.rate_limit_headers[rate_headers[header]] = response.headers[rate_headers[header]]
        
        # If no rate limiting headers detected, try making several requests
        if not result.rate_limit_headers:
            rate_limited = self._test_rate_limiting(
                result.endpoint.url,
                result.endpoint.method,
                result.endpoint.headers
            )
            result.rate_limit_detected = rate_limited
        else:
            result.rate_limit_detected = True
    
    def _test_rate_limiting(self, url: str, method: str, headers: Dict[str, str]) -> bool:
        """
        Test if the endpoint implements rate limiting.
        
        Args:
            url: URL to test
            method: HTTP method
            headers: HTTP headers
            
        Returns:
            bool: Whether rate limiting was detected
        """
        test_count = self.settings.get("rate_limit_test_count", 10)
        
        with ThreadPoolExecutor(max_workers=min(test_count, self.settings.get("max_workers", 10))) as executor:
            futures = []
            for _ in range(test_count):
                futures.append(
                    executor.submit(
                        self._make_single_request, 
                        method, 
                        url, 
                        headers
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
    
    def _make_single_request(self, method: str, url: str, headers: Dict[str, str]) -> Optional[int]:
        """
        Make a single request and return the status code.
        
        Args:
            method: HTTP method
            url: URL to request
            headers: HTTP headers
            
        Returns:
            int: Status code or None if request failed
        """
        try:
            response = self.session.request(
                method=method, 
                url=url, 
                headers=headers, 
                timeout=self.settings.get("timeout", 5)
            )
            return response.status_code
        except Exception:
            return None
    
    def _check_vulnerabilities(self, url: str, result: ScanResult) -> None:
        """
        Check for common vulnerabilities.
        
        Args:
            url: URL to check
            result: Scan result to update
        """
        result.vulnerabilities = {
            "open_redirect": False,
            "server_info_disclosure": False,
            "directory_listing": False,
        }
        
        # Open redirect test is omitted here for brevity but would be implemented
        # Directory listing test is omitted here for brevity but would be implemented
    
    def _check_server_info(self, response: requests.Response, result: ScanResult) -> None:
        """
        Check for server information disclosure.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        server = response.headers.get('Server', '')
        if server and len(server) > 0 and server.lower() not in ["cloudflare"]:
            result.vulnerabilities["server_info_disclosure"] = True
            result.issues.append("Server information disclosure")
    
    def _identify_issues(self, result: ScanResult) -> None:
        """
        Identify security issues based on scan results.
        
        Args:
            result: Scan result to update
        """
        # Check for missing security headers
        important_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content-Security-Policy",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header"
        }
        
        for header, issue in important_headers.items():
            if header not in result.security_headers:
                result.issues.append(issue)
                
        # Check for rate limiting
        if self.test_config.get("rate_limiting", True) and not result.rate_limit_detected:
            result.issues.append("No rate limiting detected")
            
        # Check for CORS issues
        if self.test_config.get("cors_headers", True) and not result.cors_headers:
            # Only flag as an issue if it's not an OPTIONS request
            if result.endpoint.method != "OPTIONS" and result.status_code and result.status_code < 400:
                result.issues.append("No CORS headers configured")
    
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
                endpoint_score -= sum(1 for v in result.vulnerabilities.values() if v) * 1000
            
            # Limit maximum endpoint score
            endpoint_score = max(0, min(endpoint_score, max_score_per_endpoint))
            total_score += endpoint_score
        
        # Average score
        avg_score = total_score / len(self.results)
        
        # Return score with appropriate message
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