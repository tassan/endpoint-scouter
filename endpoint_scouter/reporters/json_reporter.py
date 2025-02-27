"""
JSON reporter for EndpointScouter.
"""

import os
import json
import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult, ScanSummary

logger = logging.getLogger("EndpointScouter")

# Define the reports directory
REPORTS_DIR = "reports"


class JsonReporter:
    """Generates JSON reports from scan results."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the reporter."""
        self.config = config or {}

        # Ensure reports directory exists
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            logger.info(f"Created reports directory: {REPORTS_DIR}")

    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """Generate a JSON report."""
        try:
            # Create summary
            summary = ScanSummary(results)

            # Prepare data for JSON report
            report_data = {
                "summary": summary.to_dict(),
                "endpoints": [result.to_dict() for result in results],
                "config": self.config,
            }

            # Ensure path exists with subfolder
            file_dir = os.path.join(
                REPORTS_DIR, os.path.splitext(os.path.basename(output_file))[0]
            )
            os.makedirs(file_dir, exist_ok=True)

            # Full path for the file
            file_path = os.path.join(file_dir, os.path.basename(output_file))

            # Write to file
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

            logger.info(f"JSON report generated: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise
