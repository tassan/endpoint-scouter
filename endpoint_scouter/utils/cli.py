"""
Command-line interface utilities for EndpointScouter.
"""

import argparse
import logging
import sys
from typing import Dict, Any

logger = logging.getLogger("EndpointScouter")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="EndpointScouter - Verifies security measures in API endpoints"
    )
    parser.add_argument(
        "config_file", help="YAML configuration file with endpoints and settings"
    )
    parser.add_argument(
        "-o", "--output", help="Output file for the report (without extension)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format(s) to generate (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--dbz-mode", action="store_true", help="Enable Dragon Ball Z themed responses"
    )

    return parser.parse_args()


def setup_logging(verbose: bool = False) -> None:
    """
    Set up logging configuration.

    Args:
        verbose: Whether to enable verbose logging
    """
    log_level = logging.DEBUG if verbose else logging.WARNING

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def print_header(dbz_mode: bool = False) -> None:
    """
    Print header information.

    Args:
        dbz_mode: Whether to use Dragon Ball Z themed messages
    """
    if dbz_mode:
        print("\n" + "=" * 60)
        print("🐉 EndpointScouter - Ultimate Security Scouter! 🐉")
        print("=" * 60 + "\n")
    else:
        print("\n" + "=" * 60)
        print("🔒 EndpointScouter - API Security Scanner 🔒")
        print("=" * 60 + "\n")


def print_scan_start(endpoint_count: int, dbz_mode: bool = False) -> None:
    """
    Print scan start message.

    Args:
        endpoint_count: Number of endpoints to scan
        dbz_mode: Whether to use Dragon Ball Z themed messages
    """
    if dbz_mode:
        print(f"🔍 Powering up scouter... scanning {endpoint_count} endpoints!")
    else:
        print(f"🔍 Scanning {endpoint_count} endpoints...")


def print_report_generation(dbz_mode: bool = False) -> None:
    """
    Print report generation message.

    Args:
        dbz_mode: Whether to use Dragon Ball Z themed messages
    """
    if dbz_mode:
        print("📊 Calculating power levels...")
    else:
        print("📊 Generating report...")


def print_completion(security_score: str, dbz_mode: bool = False) -> None:
    """
    Print completion message.

    Args:
        security_score: Security score
        dbz_mode: Whether to use Dragon Ball Z themed messages
    """
    if dbz_mode:
        print(f"🔥 Power level: {security_score}")
        print("✅ Scan complete! The Prince of all Saiyans would be proud!")
    else:
        print(f"🔒 Security Score: {security_score}")
        print("✅ Scan completed successfully.")


def print_report_locations(report_files: Dict[str, str]) -> None:
    """
    Print report file locations.

    Args:
        report_files: Dictionary mapping format to file path
    """
    print("\nReports generated:")
    for report_format, file_path in report_files.items():
        print(f"- {report_format.upper()}: {file_path}")


def print_error(error: Exception, verbose: bool = False) -> None:
    """
    Print error message.

    Args:
        error: Exception that occurred
        verbose: Whether to enable verbose logging
    """
    print(f"❌ Error: {str(error)}")
    if verbose:
        import traceback

        traceback.print_exc()
