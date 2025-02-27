"""
HTTP utilities for EndpointScouter.
"""

import requests
import random
import time
import logging
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger("EndpointScouter")


def create_session(config: Dict[str, Any] = None) -> requests.Session:
    """
    Create a session with retry capabilities.

    Args:
        config: Configuration dictionary

    Returns:
        requests.Session: Configured session
    """
    config = config or {}
    session = requests.Session()

    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
        backoff_factor=1,
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Set default headers
    user_agent = config.get("user_agent", "EndpointScouter/1.0")
    session.headers.update({"User-Agent": user_agent})

    return session


def make_request(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str] = None,
    payload: Any = None,
    timeout: int = 5,
    allow_redirects: bool = False,
) -> Optional[requests.Response]:
    """
    Make an HTTP request with error handling.

    Args:
        session: Request session
        method: HTTP method
        url: URL to request
        headers: HTTP headers
        payload: Request payload (for POST/PUT/PATCH)
        timeout: Request timeout
        allow_redirects: Whether to follow redirects

    Returns:
        requests.Response: Response object or None if request failed
    """
    try:
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            json=payload if method in ["POST", "PUT", "PATCH"] and payload else None,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        return response
    except requests.exceptions.Timeout:
        logger.debug(f"Request timeout: {url}")
    except requests.exceptions.ConnectionError:
        logger.debug(f"Connection error: {url}")
    except requests.exceptions.RequestException as e:
        logger.debug(f"Request error: {url} - {str(e)}")
    except Exception as e:
        logger.debug(f"Unexpected error: {url} - {str(e)}")

    return None


def parallel_requests(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str] = None,
    count: int = 10,
    timeout: int = 5,
) -> Dict[str, Any]:
    """
    Make multiple requests to the same URL for testing rate limiting.

    Args:
        session: Request session
        method: HTTP method
        url: URL to request
        headers: HTTP headers
        count: Number of requests to make
        timeout: Request timeout

    Returns:
        Dict[str, Any]: Results of the requests
    """
    results = {"status_codes": [], "rate_limited": False, "errors": 0}

    for _ in range(count):
        try:
            # Add a small random delay to avoid exact simultaneous requests
            time.sleep(random.uniform(0, 0.1))

            response = session.request(
                method=method, url=url, headers=headers, timeout=timeout
            )

            results["status_codes"].append(response.status_code)

            # Check for rate limiting
            if response.status_code == 429:
                results["rate_limited"] = True
        except Exception:
            results["errors"] += 1

    return results


def extract_headers(response: requests.Response, header_list: list) -> Dict[str, str]:
    """
    Extract headers from a response object.

    Args:
        response: HTTP response
        header_list: List of headers to extract

    Returns:
        Dict[str, str]: Extracted headers
    """
    extracted = {}

    for header in header_list:
        if header.lower() in {h.lower(): h for h in response.headers}:
            header_key = {h.lower(): h for h in response.headers}[header.lower()]
            extracted[header] = response.headers[header_key]

    return extracted
