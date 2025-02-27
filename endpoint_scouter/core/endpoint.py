"""
Endpoint module for EndpointScouter.

This module defines the Endpoint class that represents an API endpoint to be scanned.
"""

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("EndpointScouter")


class Endpoint:
    """Represents an API endpoint to be scanned."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[Any] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        """
        Initialize an Endpoint.

        Args:
            url: The URL of the endpoint
            method: The HTTP method (GET, POST, etc.)
            headers: HTTP headers to include in requests
            payload: Payload data for POST/PUT methods
            description: Description of the endpoint
            tags: Tags associated with the endpoint

        Raises:
            ValueError: If the URL is invalid or empty
        """
        if not url or not url.strip():
            raise ValueError("URL cannot be empty")

        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid URL: {url}")

        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.payload = payload
        self.description = description
        self.tags = tags or []

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert endpoint to dictionary representation.

        Returns:
            Dict[str, Any]: Dictionary representation of the endpoint
        """
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "payload": self.payload,
            "description": self.description,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Endpoint":
        """
        Create endpoint from dictionary data.

        Args:
            data: Dictionary containing endpoint data

        Returns:
            Endpoint: New endpoint instance

        Raises:
            ValueError: If required fields are missing or invalid
        """
        if not data.get("url"):
            raise ValueError("URL is required")

        return cls(
            url=data["url"],
            method=data.get("method", "GET"),
            headers=data.get("headers", {}),
            payload=data.get("payload"),
            description=data.get("description"),
            tags=data.get("tags", []),
        )


def load_endpoints_from_config(config: Dict[str, Any]) -> List[Endpoint]:
    """
    Load endpoints from configuration dictionary.

    Args:
        config: Configuration dictionary

    Returns:
        List[Endpoint]: List of endpoint objects
    """
    endpoints = []

    for ep_data in config.get("endpoints", []):
        try:
            endpoint = Endpoint(
                url=ep_data["url"],
                method=ep_data.get("method", "GET"),
                headers=ep_data.get("headers", {}),
                payload=ep_data.get("payload"),
                description=ep_data.get("description"),
                tags=ep_data.get("tags", []),
            )
            endpoints.append(endpoint)
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid endpoint configuration: {str(e)}")

    logger.info(f"Loaded {len(endpoints)} endpoints from configuration")
    return endpoints
