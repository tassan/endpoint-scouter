"""
CSV reporter for EndpointScouter.
"""

import csv
import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


class CsvReporter:
    """Generates CSV reports from scan results."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the reporter.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """
        Generate a CSV report.

        Args:
            results: List of scan results
            output_file: Output file path

        Returns:
            str: Path to the generated report
        """
        try:
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                # Header
                writer.writerow(
                    [
                        "URL",
                        "Method",
                        "Accessible",
                        "Status Code",
                        "CORS Configured",
                        "Rate Limit",
                        "Security Headers",
                        "Response Time (s)",
                        "Issues",
                        "Errors",
                    ]
                )

                # Data
                for r in results:
                    writer.writerow(
                        [
                            r.endpoint.url,
                            r.endpoint.method,
                            r.is_accessible,
                            r.status_code,
                            bool(r.cors_headers),
                            r.rate_limit_detected,
                            len(r.security_headers),
                            r.response_time,
                            "; ".join(r.issues),
                            "; ".join(r.errors),
                        ]
                    )

            logger.info(f"CSV report generated: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            raise
