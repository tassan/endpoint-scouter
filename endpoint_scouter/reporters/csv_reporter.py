"""
CSV reporter for EndpointScouter.
"""

import os
import csv
import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")

# Define the reports directory
REPORTS_DIR = "reports"


class CsvReporter:
    """Generates CSV reports from scan results."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the reporter."""
        self.config = config or {}

        # Ensure reports directory exists
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            logger.info(f"Created reports directory: {REPORTS_DIR}")

    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """Generate a CSV report."""
        try:
            # Ensure path exists with subfolder
            file_dir = os.path.join(
                REPORTS_DIR, os.path.splitext(os.path.basename(output_file))[0]
            )
            os.makedirs(file_dir, exist_ok=True)

            # Full path for the file
            file_path = os.path.join(file_dir, os.path.basename(output_file))

            with open(file_path, "w", newline="", encoding="utf-8") as f:
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

            logger.info(f"CSV report generated: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            raise
