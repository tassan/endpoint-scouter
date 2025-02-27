"""
JSON reporter for EndpointScouter.
"""

import json
import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult, ScanSummary

logger = logging.getLogger("EndpointScouter")


class JsonReporter:
    """Generates JSON reports from scan results."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the reporter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def generate(self, results: List[ScanResult], output_file: str) -> str:
        """
        Generate a JSON report.
        
        Args:
            results: List of scan results
            output_file: Output file path
            
        Returns:
            str: Path to the generated report
        """
        try:
            # Create summary
            summary = ScanSummary(results)
            
            # Prepare data for JSON report
            report_data = {
                "summary": summary.to_dict(),
                "endpoints": [result.to_dict() for result in results],
                "config": self.config
            }
            
            # Write to file
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
                
            logger.info(f"JSON report generated: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise