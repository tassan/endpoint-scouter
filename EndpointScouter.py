#!/usr/bin/env python3
"""
EndpointScouter - A tool for verifying security measures in API endpoints
Inspired by Dragon Ball Z Scouters - checks the "power level" of your endpoints' security!
"""

import requests
import argparse
import csv
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
import logging
import sys
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("EndpointScouter")


class EndpointScouter:
    def __init__(
        self,
        timeout=5,
        max_workers=10,
        rate_limit_test_count=10,
        dbz_mode=False,
        test_vulnerability=False,
    ):
        self.timeout = timeout  # Timeout for requests in seconds
        self.max_workers = (
            max_workers  # Maximum number of threads for parallel requests
        )
        self.rate_limit_test_count = (
            rate_limit_test_count  # Number of requests to test rate limiting
        )
        self.dbz_mode = dbz_mode  # Whether to use Dragon Ball Z themed responses
        self.test_vulnerability = (
            test_vulnerability  # Whether to test for common vulnerabilities
        )
        self.results = []
        self.session = self._create_session()

    def _create_session(self):
        """Creates a session with retry capabilities"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=[
                "HEAD",
                "GET",
                "OPTIONS",
                "POST",
                "PUT",
                "DELETE",
                "PATCH",
            ],
            backoff_factor=1,  # Factor to apply between attempts. Wait 1s, 2s, 4s between retries
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def load_endpoints(self, file_path):
        """
        Loads endpoints from a CSV or JSON file

        Args:
            file_path (str): Path to the CSV or JSON file

        Returns:
            list: List of standardized endpoint dictionaries

        Raises:
            ValueError: If the file format is unsupported
            FileNotFoundError: If the file cannot be found
        """
        endpoints = []
        file_extension = file_path.split(".")[-1].lower()

        try:
            if file_extension == "csv":
                with open(file_path, "r", encoding="utf-8") as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        endpoints.append(row)
            elif file_extension == "json":
                with open(file_path, "r", encoding="utf-8") as file:
                    endpoints = json.load(file)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")

            # Verify and standardize structure
            standardized_endpoints = self._standardize_endpoints(endpoints)
            logger.info(f"Loaded {len(standardized_endpoints)} endpoints")
            return standardized_endpoints

        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON format in file: {file_path}")
            raise ValueError(f"Invalid JSON format in file: {file_path}")
        except Exception as e:
            logger.error(f"Error loading endpoints: {str(e)}")
            raise

    def _standardize_endpoints(self, endpoints):
        """
        Standardizes endpoint format

        Args:
            endpoints (list): List of endpoints in various formats

        Returns:
            list: List of standardized endpoint dictionaries
        """
        standardized_endpoints = []
        for ep in endpoints:
            if isinstance(ep, str):
                # If it's just a string, assume it's a URL with GET method
                standardized_endpoints.append(
                    {
                        "url": ep,
                        "method": "GET",
                        "expected_status": None,
                        "headers": {},
                        "payload": None,
                    }
                )
            elif isinstance(ep, dict):
                # If it's a dictionary, get the necessary keys or set default values
                if not ep.get("url"):
                    logger.warning(f"Skipping endpoint without URL: {ep}")
                    continue

                standardized_endpoints.append(
                    {
                        "url": ep.get("url"),
                        "method": ep.get("method", "GET"),
                        "expected_status": ep.get("expected_status"),
                        "headers": ep.get("headers", {}),
                        "payload": ep.get("payload"),
                    }
                )
        return standardized_endpoints

    def scan_endpoint(self, endpoint):
        """
        Scans a single endpoint and returns the results

        Args:
            endpoint (dict): Endpoint configuration

        Returns:
            dict: Results of the scan
        """
        url = endpoint["url"]
        method = endpoint["method"].upper()
        expected_status = endpoint.get("expected_status")
        headers = endpoint.get("headers", {})
        payload = endpoint.get("payload")

        logger.info(f"Scanning endpoint: {method} {url}")

        result = {
            "url": url,
            "method": method,
            "timestamp": datetime.now().isoformat(),
            "is_accessible": False,
            "status_code": None,
            "status_expected": False,
            "cors_headers": {},
            "rate_limit_detected": False,
            "rate_limit_headers": {},
            "security_headers": {},
            "response_time": None,
            "vulnerabilities": {},
            "issues": [],
            "errors": [],
        }

        try:
            # Basic accessibility test
            start_time = time.time()
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=(
                    payload if method in ["POST", "PUT", "PATCH"] and payload else None
                ),
                timeout=self.timeout,
                allow_redirects=False,
            )
            result["response_time"] = round(time.time() - start_time, 3)
            result["is_accessible"] = True
            result["status_code"] = response.status_code

            # Check if status is as expected (if specified)
            if expected_status:
                result["status_expected"] = response.status_code == expected_status

            # Analyze headers
            self._analyze_security_headers(response, result)
            self._analyze_cors_headers(response, result)
            self._analyze_rate_limiting(response, result, url, method, headers)

            # Test for vulnerabilities if enabled
            if self.test_vulnerability:
                self._test_vulnerabilities(url, result)

            # Add issues based on findings
            self._identify_issues(result)

        except requests.exceptions.Timeout:
            result["errors"].append("Connection timeout")
        except requests.exceptions.ConnectionError:
            result["errors"].append("Connection error")
        except requests.exceptions.RequestException as e:
            result["errors"].append(f"Request error: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Unexpected error: {str(e)}")

        return result

    def _analyze_security_headers(self, response, result):
        """
        Analyzes security headers in the response

        Args:
            response (Response): Response object
            result (dict): Result dictionary to update
        """
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",  # Added modern headers
            "Report-To",
            "NEL",
        ]

        for header in security_headers:
            if header.lower() in {h.lower(): h for h in response.headers}:
                header_key = {h.lower(): h for h in response.headers}[header.lower()]
                result["security_headers"][header] = response.headers[header_key]

        # Check for additional security issues
        parsed_url = urlparse(response.url)
        if parsed_url.scheme != "https":
            result["issues"].append("Not using HTTPS")

    def _analyze_cors_headers(self, response, result):
        """
        Analyzes CORS headers in the response

        Args:
            response (Response): Response object
            result (dict): Result dictionary to update
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
                result["cors_headers"][header] = response.headers[header_key]

        # Check for CORS misconfigurations
        if "Access-Control-Allow-Origin" in result["cors_headers"]:
            if result["cors_headers"]["Access-Control-Allow-Origin"] == "*":
                if (
                    "Access-Control-Allow-Credentials" in result["cors_headers"]
                    and result["cors_headers"][
                        "Access-Control-Allow-Credentials"
                    ].lower()
                    == "true"
                ):
                    result["issues"].append(
                        "Misconfigured CORS: wildcard origin with credentials"
                    )

    def _analyze_rate_limiting(self, response, result, url, method, headers):
        """
        Analyzes rate limiting in the response

        Args:
            response (Response): Response object
            result (dict): Result dictionary to update
            url (str): URL to test
            method (str): HTTP method
            headers (dict): Headers to use
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
            if any(
                limit_header.lower() in header for limit_header in rate_limit_headers
            ):
                result["rate_limit_headers"][rate_headers[header]] = response.headers[
                    rate_headers[header]
                ]

        # If no rate limiting headers detected, try making several requests in parallel
        if not result["rate_limit_headers"]:
            rate_limited = self._test_rate_limiting_parallel(url, method, headers)
            result["rate_limit_detected"] = rate_limited
        else:
            result["rate_limit_detected"] = True

    def _test_rate_limiting_parallel(self, url, method, headers):
        """
        Tests if the endpoint implements rate limiting using parallel requests

        Args:
            url (str): URL to test
            method (str): HTTP method
            headers (dict): Headers to use

        Returns:
            bool: Whether rate limiting was detected
        """
        with ThreadPoolExecutor(
            max_workers=min(self.rate_limit_test_count, self.max_workers)
        ) as executor:
            futures = []
            for _ in range(self.rate_limit_test_count):
                futures.append(
                    executor.submit(self._make_single_request, method, url, headers)
                )

            # Check if any request returned 429
            for future in futures:
                try:
                    if future.result() == 429:
                        return True
                except Exception:
                    pass

        return False

    def _make_single_request(self, method, url, headers):
        """
        Makes a single request and returns the status code

        Args:
            method (str): HTTP method
            url (str): URL to request
            headers (dict): Headers to use

        Returns:
            int: Status code or None if request failed
        """
        try:
            # Add a small random delay to avoid exact simultaneous requests
            time.sleep(random.uniform(0, 0.1))
            response = requests.request(
                method=method, url=url, headers=headers, timeout=self.timeout
            )
            return response.status_code
        except Exception:
            return None

    def _test_vulnerabilities(self, url, result):
        """
        Tests for common vulnerabilities

        Args:
            url (str): Base URL to test
            result (dict): Result dictionary to update
        """
        result["vulnerabilities"] = {
            "open_redirect": False,
            "server_info_disclosure": False,
            "directory_listing": False,
        }

        # 1. Test for open redirect vulnerability
        try:
            redirect_param = {
                "url": "https://example.com",
                "redirect": "https://example.com",
                "next": "https://example.com",
            }
            for param, value in redirect_param.items():
                redirect_url = f"{url}?{param}={value}"
                response = self.session.get(
                    redirect_url, timeout=self.timeout, allow_redirects=False
                )
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get("Location", "")
                    if "example.com" in location:
                        result["vulnerabilities"]["open_redirect"] = True
                        result["issues"].append(
                            "Potential open redirect vulnerability detected"
                        )
                        break
        except Exception:
            pass

        # 2. Check for server info disclosure
        try:
            response = self.session.get(url, timeout=self.timeout)
            server = response.headers.get("Server", "")
            if server and len(server) > 0 and server != "cloudflare":
                result["vulnerabilities"]["server_info_disclosure"] = True
                result["issues"].append("Server information disclosure")
        except Exception:
            pass

        # 3. Check for directory listing
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            common_dirs = ["/images/", "/uploads/", "/assets/", "/files/", "/backup/"]

            for directory in common_dirs:
                try:
                    dir_url = urljoin(base_url, directory)
                    response = self.session.get(dir_url, timeout=self.timeout)
                    if response.status_code == 200:
                        # Check for common directory listing indicators
                        indicators = [
                            "Index of",
                            "Directory Listing",
                            "Parent Directory",
                        ]
                        if any(indicator in response.text for indicator in indicators):
                            result["vulnerabilities"]["directory_listing"] = True
                            result["issues"].append(
                                f"Directory listing enabled at {dir_url}"
                            )
                            break
                except Exception:
                    continue
        except Exception:
            pass

    def _identify_issues(self, result):
        """
        Identifies security issues based on scan results

        Args:
            result (dict): Result dictionary to update
        """
        # Check for missing security headers
        important_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content-Security-Policy",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
        }

        for header, issue in important_headers.items():
            if header not in result["security_headers"]:
                result["issues"].append(issue)

        # Check for rate limiting
        if not result["rate_limit_detected"]:
            result["issues"].append("No rate limiting detected")

        # Check for CORS issues
        if not result["cors_headers"] and result["method"] != "OPTIONS":
            # Only flag as an issue if it's not an OPTIONS request
            if result["status_code"] and result["status_code"] < 400:
                result["issues"].append("No CORS headers configured")

    def scan_all(self, endpoints):
        """
        Scans all endpoints in parallel using threads

        Args:
            endpoints (list): List of endpoints to scan

        Returns:
            list: Results of all scans
        """
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                self.results = list(executor.map(self.scan_endpoint, endpoints))
            logger.info(f"Scan completed for {len(self.results)} endpoints")
        except Exception as e:
            logger.error(f"Error scanning endpoints: {str(e)}")
            raise

        return self.results

    def generate_report(self, output_file=None):
        """
        Generates a report of the scan results

        Args:
            output_file (str, optional): Output file path. If None, a default name is used.

        Returns:
            bool: Whether the report was generated successfully
        """
        if not self.results:
            logger.warning("No results to generate report")
            return False

        # Create default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"endpoint_scouter_report_{timestamp}.json"

        # Calculate statistics
        total = len(self.results)
        accessible = sum(1 for r in self.results if r["is_accessible"])
        expected_status = sum(1 for r in self.results if r["status_expected"])
        with_cors = sum(1 for r in self.results if r["cors_headers"])
        with_rate_limit = sum(1 for r in self.results if r["rate_limit_detected"])
        with_issues = sum(1 for r in self.results if r["issues"])
        vulnerability_count = sum(
            1 for r in self.results if any(r["vulnerabilities"].values())
        )

        # Group endpoints by domain
        domains = {}
        for r in self.results:
            try:
                domain = urlparse(r["url"]).netloc
                if domain not in domains:
                    domains[domain] = {"count": 0, "issues": 0, "security_score": 0}
                domains[domain]["count"] += 1
                domains[domain]["issues"] += len(r["issues"])
            except Exception:
                pass

        # Prepare summary
        summary = {
            "scan_date": datetime.now().isoformat(),
            "total_endpoints": total,
            "accessible_endpoints": accessible,
            "expected_status_count": expected_status,
            "with_cors": with_cors,
            "with_rate_limit": with_rate_limit,
            "with_issues": with_issues,
            "vulnerability_count": vulnerability_count,
            "domains": domains,
            "security_score": self._calculate_security_score(),
        }

        # Combine summary and detailed results
        report = {"summary": summary, "endpoints": self.results}

        # Write report to file
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report generated: {output_file}")

            # Also generate a CSV version for easy viewing
            csv_file = output_file.rsplit(".", 1)[0] + ".csv"
            self._write_csv_report(csv_file)

            # Generate HTML report for better visualization
            html_file = output_file.rsplit(".", 1)[0] + ".html"
            self._write_html_report(html_file, summary, self.results)

            return True
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return False

    def _write_csv_report(self, csv_file):
        """
        Generates report in CSV format

        Args:
            csv_file (str): Path to CSV file
        """
        try:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Header
                writer.writerow(
                    [
                        "URL",
                        "Method",
                        "Accessible",
                        "Status Code",
                        "Expected Status",
                        "CORS Configured",
                        "Rate Limit",
                        "Security Headers",
                        "Response Time (s)",
                        "Issues",
                        "Errors",
                    ]
                )

                # Data
                for r in self.results:
                    writer.writerow(
                        [
                            r["url"],
                            r["method"],
                            r["is_accessible"],
                            r["status_code"],
                            r["status_expected"],
                            bool(r["cors_headers"]),
                            r["rate_limit_detected"],
                            len(r["security_headers"]),
                            r["response_time"],
                            "; ".join(r["issues"]),
                            "; ".join(r["errors"]),
                        ]
                    )
            logger.info(f"CSV Report generated: {csv_file}")
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")

    def _write_html_report(self, html_file, summary, results):
        """
        Generates an HTML report for better visualization

        Args:
            html_file (str): Path to HTML file
            summary (dict): Summary information
            results (list): Detailed results
        """
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>EndpointScouter Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    h2 {{ color: #555; margin-top: 30px; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .score {{ font-size: 24px; font-weight: bold; }}
                    .good {{ color: green; }}
                    .medium {{ color: orange; }}
                    .bad {{ color: red; }}
                    .summary-box {{ border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; }}
                    .endpoint-row:hover {{ background-color: #f0f0f0; }}
                    .issues-list {{ color: #d9534f; }}
                </style>
            </head>
            <body>
                <h1>EndpointScouter Security Report</h1>
                <p>Scan Date: {summary['scan_date']}</p>
                
                <div class="summary-box">
                    <h2>Summary</h2>
                    <p class="score {self._get_score_class(summary['security_score'])}">
                        Security Score: {summary['security_score']}
                    </p>
                    <p>Total Endpoints: {summary['total_endpoints']}</p>
                    <p>Accessible Endpoints: {summary['accessible_endpoints']}</p>
                    <p>Endpoints with Issues: {summary['with_issues']}</p>
                    <p>Endpoints with Vulnerabilities: {summary['vulnerability_count']}</p>
                </div>
                
                <h2>Domains Overview</h2>
                <table>
                    <tr>
                        <th>Domain</th>
                        <th>Endpoints</th>
                        <th>Issues</th>
                    </tr>
            """

            # Add domains
            for domain, data in summary["domains"].items():
                html_content += f"""
                    <tr>
                        <td>{domain}</td>
                        <td>{data['count']}</td>
                        <td>{data['issues']}</td>
                    </tr>
                """

            html_content += """
                </table>
                
                <h2>Endpoint Details</h2>
                <table>
                    <tr>
                        <th>URL</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Security Headers</th>
                        <th>CORS</th>
                        <th>Rate Limit</th>
                        <th>Issues</th>
                    </tr>
            """

            # Add endpoints
            for r in results:
                status_class = ""
                if r["status_code"]:
                    if r["status_code"] < 400:
                        status_class = "good"
                    elif r["status_code"] < 500:
                        status_class = "medium"
                    else:
                        status_class = "bad"

                issues = "<br>".join(r["issues"]) if r["issues"] else "None"

                html_content += f"""
                    <tr class="endpoint-row">
                        <td>{r["url"]}</td>
                        <td>{r["method"]}</td>
                        <td class="{status_class}">{r["status_code"]}</td>
                        <td>{len(r["security_headers"])}</td>
                        <td>{"Yes" if r["cors_headers"] else "No"}</td>
                        <td>{"Yes" if r["rate_limit_detected"] else "No"}</td>
                        <td class="issues-list">{issues}</td>
                    </tr>
                """

            html_content += """
                </table>
            </body>
            </html>
            """

            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML Report generated: {html_file}")
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")

    def _get_score_class(self, score):
        """Returns CSS class based on score value"""
        if isinstance(score, str):
            score_value = float(score.split()[0])
        else:
            score_value = float(score)

        if score_value >= 5000:
            return "good"
        elif score_value >= 3000:
            return "medium"
        else:
            return "bad"

    def _calculate_security_score(self):
        """
        Calculates security score based on results

        Returns:
            str: Security score with appropriate message
        """
        if not self.results:
            return 0

        total_score = 0
        max_score_per_endpoint = 9000  # Reference to the "OVER 9000!" DBZ meme

        for r in self.results:
            endpoint_score = 0

            # Points for implementing basic access control
            if r.get("status_code") in [401, 403]:
                endpoint_score += 2000

            # Points for security headers
            endpoint_score += len(r.get("security_headers", {})) * 500

            # Points for CORS configuration
            if r.get("cors_headers"):
                origin_header = r.get("cors_headers", {}).get(
                    "Access-Control-Allow-Origin"
                )
                if origin_header and origin_header != "*":
                    endpoint_score += 1500  # Restrictive CORS
                else:
                    endpoint_score += 500  # CORS configured, but permissive

            # Points for rate limiting
            if r.get("rate_limit_detected"):
                endpoint_score += 2000

            # Deduct points for issues
            endpoint_score -= len(r.get("issues", [])) * 300

            # Deduct points for vulnerabilities
            if r.get("vulnerabilities"):
                endpoint_score -= (
                    sum(1 for v in r["vulnerabilities"].values() if v) * 1000
                )

            # Limit maximum endpoint score
            endpoint_score = max(0, min(endpoint_score, max_score_per_endpoint))
            total_score += endpoint_score

        # Average score
        avg_score = total_score / len(self.results)

        # Return score with appropriate formatting based on mode
        if self.dbz_mode:
            # DBZ-themed scoring messages
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
            # Formal scoring messages for workplace use
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


def main():
    parser = argparse.ArgumentParser(
        description="EndpointScouter - Verifies security measures in API endpoints"
    )
    parser.add_argument(
        "endpoints_file", help="CSV or JSON file containing endpoints to check"
    )
    parser.add_argument("-o", "--output", help="Output file for the report (JSON)")
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=5,
        help="Timeout for requests in seconds (default: 5)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Number of parallel workers (default: 10)",
    )
    parser.add_argument(
        "-r",
        "--rate-limit-test",
        type=int,
        default=10,
        help="Number of requests to test rate limiting (default: 10)",
    )
    parser.add_argument(
        "--dbz-mode",
        action="store_true",
        help="Enable Dragon Ball Z themed responses instead of formal workplace responses",
    )
    parser.add_argument(
        "--test-vulnerabilities",
        action="store_true",
        help="Test for common vulnerabilities like open redirect",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Print header
        if args.dbz_mode:
            print("\n" + "=" * 60)
            print("🐉 EndpointScouter - Ultimate Security Scouter! 🐉")
            print("=" * 60 + "\n")
        else:
            print("\n" + "=" * 60)
            print("🔒 EndpointScouter - API Security Scanner 🔒")
            print("=" * 60 + "\n")

        # Initialize the scouter
        scouter = EndpointScouter(
            timeout=args.timeout,
            max_workers=args.workers,
            rate_limit_test_count=args.rate_limit_test,
            dbz_mode=args.dbz_mode,
            test_vulnerability=args.test_vulnerabilities,
        )

        # Load endpoints
        endpoints = scouter.load_endpoints(args.endpoints_file)

        # Execute the scan
        if args.dbz_mode:
            print(f"🔍 Powering up scouter... scanning {len(endpoints)} endpoints!")
        else:
            print(f"🔍 Scanning {len(endpoints)} endpoints...")
        scouter.scan_all(endpoints)

        # Generate report
        if args.dbz_mode:
            print("📊 Calculating power levels...")
        else:
            print("📊 Generating report...")
        report_file = args.output
        scouter.generate_report(report_file)

        if args.dbz_mode:
            print("✅ Scan complete! The Prince of all Saiyans would be proud!")
        else:
            print("✅ Scan completed successfully.")

        # Print report location
        if report_file:
            base_name = report_file.rsplit(".", 1)[0]
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"endpoint_scouter_report_{timestamp}"

        print(f"\nReports generated:")
        print(f"- JSON: {base_name}.json")
        print(f"- CSV: {base_name}.csv")
        print(f"- HTML: {base_name}.html")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
