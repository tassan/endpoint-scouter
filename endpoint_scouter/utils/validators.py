"""
Validation utilities for EndpointScouter.
"""

import re
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Union, Optional

logger = logging.getLogger("EndpointScouter")


def validate_url(url: str) -> bool:
    """
    Validate a URL.

    Args:
        url: URL to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False

    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except Exception:
        return False


def validate_http_method(method: str) -> bool:
    """
    Validate an HTTP method.

    Args:
        method: HTTP method to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not method or not isinstance(method, str):
        return False

    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    return method.upper() in valid_methods


def validate_headers(headers: Dict[str, str]) -> bool:
    """
    Validate HTTP headers.

    Args:
        headers: Headers to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(headers, dict):
        return False

    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return False

    return True


def validate_payload(payload: Any) -> bool:
    """
    Validate request payload.

    Args:
        payload: Payload to validate

    Returns:
        bool: True if valid, False otherwise
    """
    # Payload can be None, dict, list, or any JSON-serializable type
    try:
        import json

        json.dumps(payload)
        return True
    except (TypeError, OverflowError):
        return False


def validate_endpoint_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize endpoint data.

    Args:
        data: Endpoint data to validate

    Returns:
        Dict[str, Any]: Sanitized endpoint data or empty dict if invalid
    """
    if not isinstance(data, dict):
        logger.warning("Endpoint data is not a dictionary")
        return {}

    # URL is required
    if "url" not in data or not validate_url(data["url"]):
        logger.warning(f"Invalid or missing URL in endpoint data: {data}")
        return {}

    # Validate method if present
    if "method" in data and not validate_http_method(data["method"]):
        logger.warning(f"Invalid HTTP method in endpoint data: {data['method']}")
        data["method"] = "GET"  # Default to GET

    # Validate headers if present
    if "headers" in data and not validate_headers(data["headers"]):
        logger.warning(f"Invalid headers in endpoint data: {data['headers']}")
        data["headers"] = {}  # Default to empty headers

    # Validate payload if present
    if "payload" in data and not validate_payload(data["payload"]):
        logger.warning(f"Invalid payload in endpoint data")
        data["payload"] = None  # Default to no payload

    return data


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    # IPv6 pattern (simplified)
    ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::$"

    return bool(re.match(ipv4_pattern, ip)) or bool(re.match(ipv6_pattern, ip))


def sanitize_header_name(header: str) -> str:
    """
    Sanitize HTTP header name.

    Args:
        header: Header name to sanitize

    Returns:
        str: Sanitized header name
    """
    # Standard HTTP headers formatting (e.g., Content-Type)
    words = header.split("-")
    return "-".join(word.capitalize() for word in words)


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Check if a port number is valid.

    Args:
        port: Port number to validate

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def get_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.

    Args:
        url: URL to extract domain from

    Returns:
        str: Domain name or None if invalid
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.netloc:
            return parsed_url.netloc
    except Exception:
        pass

    return None
