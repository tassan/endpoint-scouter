"""
Configuration utilities for EndpointScouter.
"""

import os
import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger("EndpointScouter")


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to the YAML configuration file

    Returns:
        Dict: Configuration dictionary

    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file is invalid
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

        if not config:
            raise ValueError(f"Empty or invalid configuration file: {config_path}")

        # Ensure required sections exist
        if "endpoints" not in config:
            raise ValueError(
                f"No endpoints section in configuration file: {config_path}"
            )

        # Create default sections if not present
        if "settings" not in config:
            config["settings"] = {}

        if "tests" not in config:
            config["tests"] = {
                "security_headers": True,
                "cors_headers": True,
                "rate_limiting": True,
                "vulnerability_scan": True,
                "server_info": True,
            }

        # Apply default settings if not present
        default_settings = {
            "timeout": 5,
            "max_workers": 10,
            "user_agent": "EndpointScouter/1.0",
            "rate_limit_test_count": 10,
            "debug": False,
        }

        for key, value in default_settings.items():
            if key not in config["settings"]:
                config["settings"][key] = value

        logger.info(f"Loaded configuration from {config_path}")
        return config

    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format in configuration file: {str(e)}")

    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        raise


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration dictionary.

    Args:
        config: Configuration dictionary

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Check if endpoints section exists and is a list
        if "endpoints" not in config or not isinstance(config["endpoints"], list):
            logger.error(
                "Invalid configuration: endpoints section missing or not a list"
            )
            return False

        # Check if all endpoints have a URL
        for i, endpoint in enumerate(config["endpoints"]):
            if not isinstance(endpoint, dict):
                logger.error(f"Invalid endpoint at index {i}: not a dictionary")
                return False

            if "url" not in endpoint:
                logger.error(f"Invalid endpoint at index {i}: missing URL")
                return False

        # Check if settings is a dictionary
        if "settings" in config and not isinstance(config["settings"], dict):
            logger.error("Invalid configuration: settings section is not a dictionary")
            return False

        # Check if tests is a dictionary
        if "tests" in config and not isinstance(config["tests"], dict):
            logger.error("Invalid configuration: tests section is not a dictionary")
            return False

        return True

    except Exception as e:
        logger.error(f"Error validating configuration: {str(e)}")
        return False
