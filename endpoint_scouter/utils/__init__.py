"""
Utilities package for EndpointScouter.

This package contains utility modules for the scanner.
"""

from endpoint_scouter.utils.config import load_config
from endpoint_scouter.utils.http import create_session, make_request, parallel_requests
from endpoint_scouter.utils.scoring import (
    calculate_endpoint_score,
    calculate_overall_score,
    get_score_message,
)
from endpoint_scouter.utils.validators import (
    validate_url,
    validate_http_method,
    validate_headers,
    validate_payload,
)

# add cli to __all__
from endpoint_scouter.utils.cli import (
    setup_logging,
    print_header,
    print_scan_start,
    print_report_generation,
    print_completion,
    print_report_locations,
    print_error,
)

__all__ = [
    "load_config",
    "create_session",
    "make_request",
    "parallel_requests",
    "calculate_endpoint_score",
    "calculate_overall_score",
    "get_score_message",
    "validate_url",
    "validate_http_method",
    "validate_headers",
    "validate_payload",
    "setup_logging",
    "print_header",
    "print_scan_start",
    "print_report_generation",
    "print_completion",
    "print_report_locations",
    "print_error",
]
