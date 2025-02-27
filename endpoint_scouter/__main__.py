#!/usr/bin/env python3
"""
EndpointScouter - A tool for verifying security measures in API endpoints
"""

import sys
from datetime import datetime

from endpoint_scouter.utils.cli import (
    parse_arguments, 
    setup_logging, 
    print_header,
    print_scan_start,
    print_report_generation,
    print_completion,
    print_report_locations,
    print_error
)
from endpoint_scouter.core.scanner import Scanner
from endpoint_scouter.reporters.json_reporter import JsonReporter
from endpoint_scouter.reporters.csv_reporter import CsvReporter
from endpoint_scouter.reporters.html_reporter import HtmlReporter


def main():
    """Main entry point for EndpointScouter."""
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Set up logging
        setup_logging(args.verbose)
        
        # Print header
        print_header(args.dbz_mode)
        
        # Initialize scanner with configuration
        scanner = Scanner(args.config_file)
        
        # Update scanner settings with command-line arguments
        scanner.settings["dbz_mode"] = args.dbz_mode
        
        # Print scan start message
        print_scan_start(len(scanner.endpoints), args.dbz_mode)
        
        # Execute the scan
        results = scanner.scan_all()
        
        # Print report generation message
        print_report_generation(args.dbz_mode)
        
        # Determine report formats
        formats = []
        if args.format == "all":
            formats = ["json", "csv", "html"]
        else:
            formats = [args.format]
        
        # Output file name
        if args.output:
            output_prefix = args.output
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_prefix = f"endpoint_scouter_report_{timestamp}"
        
        # Generate reports
        report_files = {}
        
        # Initialize reporters
        reporters = {
            "json": JsonReporter(scanner.config),
            "csv": CsvReporter(scanner.config),
            "html": HtmlReporter({**scanner.config, "dbz_mode": args.dbz_mode})
        }
        
        # Generate each requested report format
        for report_format in formats:
            output_file = f"{output_prefix}.{report_format}"
            report_files[report_format] = reporters[report_format].generate(results, output_file)
        
        # Calculate security score
        security_score = scanner.calculate_security_score()
        
        # Print completion message
        print_completion(security_score, args.dbz_mode)
        
        # Print report locations
        print_report_locations(report_files)
        
    except Exception as e:
        print_error(e, args.verbose if 'args' in locals() else False)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())