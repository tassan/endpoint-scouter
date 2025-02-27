"""
Security scoring utilities for EndpointScouter.
"""

import logging
from typing import Dict, List, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


def calculate_endpoint_score(result: ScanResult) -> int:
    """
    Calculate security score for a single endpoint.

    Args:
        result: Scan result

    Returns:
        int: Security score
    """
    endpoint_score = 0

    # Points for security headers
    endpoint_score += len(result.security_headers) * 500

    # Points for CORS configuration
    if result.cors_headers:
        origin_header = result.cors_headers.get("Access-Control-Allow-Origin")
        if origin_header and origin_header != "*":
            endpoint_score += 1500  # Restrictive CORS
        else:
            endpoint_score += 500  # CORS configured, but permissive

    # Points for rate limiting
    if result.rate_limit_detected:
        endpoint_score += 2000

    # Deduct points for issues
    endpoint_score -= len(result.issues) * 300

    # Deduct points for vulnerabilities
    if result.vulnerabilities:
        endpoint_score -= sum(1 for v in result.vulnerabilities.values() if v) * 1000

    # Ensure score is not negative
    return max(0, endpoint_score)


def calculate_overall_score(results: List[ScanResult], max_score: int = 9000) -> int:
    """
    Calculate overall security score for all endpoints.

    Args:
        results: List of scan results
        max_score: Maximum score per endpoint

    Returns:
        int: Average security score
    """
    if not results:
        return 0

    total_score = 0

    for result in results:
        # Calculate score for this endpoint
        endpoint_score = calculate_endpoint_score(result)

        # Limit maximum endpoint score
        endpoint_score = min(endpoint_score, max_score)
        total_score += endpoint_score

    # Calculate average score
    return int(total_score / len(results))


def get_score_message(score: int, dbz_mode: bool = False) -> str:
    """
    Get appropriate message for a security score.

    Args:
        score: Security score
        dbz_mode: Whether to use Dragon Ball Z themed messages

    Returns:
        str: Security score with message
    """
    if dbz_mode:
        if score >= 8000:
            return f"{score} - IT'S OVER 8000! Super Saiyan level security!"
        elif score >= 6000:
            return f"{score} - Super Saiyan: Excellent security implementation!"
        elif score >= 5000:
            return f"{score} - Elite Saiyan: Very good security measures"
        elif score >= 3000:
            return f"{score} - Saiyan Warrior: Good foundation but room for improvement"
        elif score >= 1000:
            return f"{score} - Trained Human: Basic security measures present"
        else:
            return f"{score} - Ordinary Human... serious security improvements needed!"
    else:
        if score >= 8000:
            return f"{score} - Excellent. Comprehensive security measures implemented."
        elif score >= 6000:
            return f"{score} - Very Good. Strong security implementation."
        elif score >= 5000:
            return f"{score} - Good. Strong security foundation present."
        elif score >= 3000:
            return f"{score} - Moderate. Basic security measures in place."
        elif score >= 1000:
            return f"{score} - Fair. Minimal security protections detected."
        else:
            return f"{score} - Inadequate. Security improvements strongly recommended."


def calculate_domain_scores(results: List[ScanResult]) -> Dict[str, Any]:
    """
    Calculate security scores grouped by domain.

    Args:
        results: List of scan results

    Returns:
        Dict[str, Any]: Dictionary mapping domains to scores
    """
    from urllib.parse import urlparse

    domains = {}

    for result in results:
        try:
            domain = urlparse(result.endpoint.url).netloc

            if domain not in domains:
                domains[domain] = {
                    "count": 0,
                    "score": 0,
                    "issues": 0,
                    "secure": 0,
                    "endpoints": [],
                }

            # Calculate score for this endpoint
            endpoint_score = calculate_endpoint_score(result)

            domains[domain]["count"] += 1
            domains[domain]["score"] += endpoint_score
            domains[domain]["issues"] += len(result.issues)

            if result.is_secure():
                domains[domain]["secure"] += 1

            domains[domain]["endpoints"].append(result.endpoint.url)

        except Exception as e:
            logger.debug(f"Error calculating domain score: {str(e)}")

    # Calculate average score for each domain
    for domain in domains:
        if domains[domain]["count"] > 0:
            domains[domain]["score"] = int(
                domains[domain]["score"] / domains[domain]["count"]
            )

    return domains
