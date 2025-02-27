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
from urllib.parse import urlparse
import logging

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("EndpointScouter")


class EndpointScouter:
    def __init__(
        self, timeout=5, max_workers=10, rate_limit_test_count=10, dbz_mode=False
    ):
        self.timeout = timeout  # Timeout for requests in seconds
        self.max_workers = (
            max_workers  # Maximum number of threads for parallel requests
        )
        self.rate_limit_test_count = (
            rate_limit_test_count  # Number of requests to test rate limiting
        )
        self.dbz_mode = dbz_mode  # Whether to use Dragon Ball Z themed responses
        self.results = []

    def load_endpoints(self, file_path):
        """Loads endpoints from a CSV or JSON file"""
        endpoints = []
        file_extension = file_path.split(".")[-1].lower()

        try:
            if file_extension == "csv":
                with open(file_path, "r") as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        endpoints.append(row)
            elif file_extension == "json":
                with open(file_path, "r") as file:
                    endpoints = json.load(file)
            else:
                raise ValueError(f"Unsupported file format: {file_extension}")

            # Verify and standardize structure
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
                        }
                    )
                elif isinstance(ep, dict):
                    # If it's a dictionary, get the necessary keys or set default values
                    standardized_endpoints.append(
                        {
                            "url": ep.get("url"),
                            "method": ep.get("method", "GET"),
                            "expected_status": ep.get("expected_status"),
                            "headers": ep.get("headers", {}),
                        }
                    )

            logger.info(f"Loaded {len(standardized_endpoints)} endpoints")
            return standardized_endpoints

        except Exception as e:
            logger.error(f"Error loading endpoints: {str(e)}")
            raise

    def scan_endpoint(self, endpoint):
        """Scans a single endpoint and returns the results"""
        url = endpoint["url"]
        method = endpoint["method"].upper()
        expected_status = endpoint.get("expected_status")
        headers = endpoint.get("headers", {})

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
            "errors": [],
        }

        try:
            # Basic accessibility test
            start_time = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
            result["response_time"] = round(time.time() - start_time, 3)
            result["is_accessible"] = True
            result["status_code"] = response.status_code

            # Check if status is as expected (if specified)
            if expected_status:
                result["status_expected"] = response.status_code == expected_status

            # Capture security headers
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
            ]

            for header in security_headers:
                if header.lower() in {h.lower(): h for h in response.headers}:
                    header_key = {h.lower(): h for h in response.headers}[
                        header.lower()
                    ]
                    result["security_headers"][header] = response.headers[header_key]

            # Check CORS
            cors_headers = [
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
                "Access-Control-Allow-Credentials",
                "Access-Control-Max-Age",
            ]

            for header in cors_headers:
                if header.lower() in {h.lower(): h for h in response.headers}:
                    header_key = {h.lower(): h for h in response.headers}[
                        header.lower()
                    ]
                    result["cors_headers"][header] = response.headers[header_key]

            # Rate limiting test
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
                    limit_header.lower() in header
                    for limit_header in rate_limit_headers
                ):
                    result["rate_limit_headers"][rate_headers[header]] = (
                        response.headers[rate_headers[header]]
                    )

            # If no rate limiting headers detected, try making several requests
            if not result["rate_limit_headers"]:
                rate_limited = self.test_rate_limiting(url, method, headers)
                result["rate_limit_detected"] = rate_limited
            else:
                result["rate_limit_detected"] = True

        except requests.exceptions.Timeout:
            result["errors"].append("Connection timeout")
        except requests.exceptions.ConnectionError:
            result["errors"].append("Connection error")
        except requests.exceptions.RequestException as e:
            result["errors"].append(f"Request error: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Unexpected error: {str(e)}")

        return result

    def test_rate_limiting(self, url, method, headers):
        """Tests if the endpoint implements rate limiting"""
        for i in range(self.rate_limit_test_count):
            try:
                response = requests.request(
                    method=method, url=url, headers=headers, timeout=self.timeout
                )
                # If returns 429 (Too Many Requests), we found rate limiting
                if response.status_code == 429:
                    return True
            except:
                # If any error occurs, we ignore it
                pass
            time.sleep(0.2)  # Small pause between requests

        return False

    def scan_all(self, endpoints):
        """Scans all endpoints in parallel using threads"""
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                self.results = list(executor.map(self.scan_endpoint, endpoints))
            logger.info(f"Scan completed for {len(self.results)} endpoints")
        except Exception as e:
            logger.error(f"Error scanning endpoints: {str(e)}")
            raise

        return self.results

    def generate_report(self, output_file=None):
        """Generates a report of the scan results"""
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

        # Prepare summary
        summary = {
            "scan_date": datetime.now().isoformat(),
            "total_endpoints": total,
            "accessible_endpoints": accessible,
            "expected_status_count": expected_status,
            "with_cors": with_cors,
            "with_rate_limit": with_rate_limit,
            "security_score": self._calculate_security_score(),
        }

        # Combine summary and detailed results
        report = {"summary": summary, "endpoints": self.results}

        # Write report to file
        try:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report generated: {output_file}")

            # Also generate a CSV version for easy viewing
            csv_file = output_file.rsplit(".", 1)[0] + ".csv"
            self._write_csv_report(csv_file)

            return True
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return False

    def _write_csv_report(self, csv_file):
        """Generates report in CSV format"""
        try:
            with open(csv_file, "w", newline="") as f:
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
                            "; ".join(r["errors"]),
                        ]
                    )
            logger.info(f"CSV Report generated: {csv_file}")
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")

    def _calculate_security_score(self):
        """Calculates security score based on results"""
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

            # Limit maximum endpoint score
            endpoint_score = min(endpoint_score, max_score_per_endpoint)
            total_score += endpoint_score

        # Average score
        avg_score = total_score / len(self.results)

        # Return score with appropriate formatting based on mode
        if self.dbz_mode:
            # DBZ-themed scoring messages
            if avg_score >= 8000:
                return f"{avg_score:.0f} - OVER 8000! Super Saiyan level security!"
            elif avg_score >= 5000:
                return f"{avg_score:.0f} - Elite Saiyan"
            elif avg_score >= 3000:
                return f"{avg_score:.0f} - Saiyan Warrior"
            elif avg_score >= 1000:
                return f"{avg_score:.0f} - Trained Human"
            else:
                return f"{avg_score:.0f} - Ordinary Human... needs improvement!"
        else:
            # Formal scoring messages for workplace use
            if avg_score >= 8000:
                return f"{avg_score:.0f} - Excellent. Comprehensive security measures implemented."
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

    args = parser.parse_args()

    try:
        # Initialize the scouter
        scouter = EndpointScouter(
            timeout=args.timeout,
            max_workers=args.workers,
            rate_limit_test_count=args.rate_limit_test,
            dbz_mode=args.dbz_mode,
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
        scouter.generate_report(args.output)

        if args.dbz_mode:
            print("✅ Scan complete! The Prince of all Saiyans would be proud!")
        else:
            print("✅ Scan completed successfully.")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
