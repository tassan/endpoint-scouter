"""
Vulnerability analyzer for EndpointScouter.
"""

import logging
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, Any

from endpoint_scouter.core.result import ScanResult

logger = logging.getLogger("EndpointScouter")


class VulnerabilityAnalyzer:
    """Analyzes endpoints for common vulnerabilities."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """
        Create a session for making requests.
        
        Returns:
            requests.Session: Configured session
        """
        session = requests.Session()
        
        # Set default headers
        user_agent = self.config.get("user_agent", "EndpointScouter/1.0")
        session.headers.update({"User-Agent": user_agent})
        
        return session
    
    def analyze(self, response: requests.Response, result: ScanResult) -> None:
        """
        Analyze response for vulnerabilities.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        # Initialize vulnerabilities dictionary
        result.vulnerabilities = {
            "open_redirect": False,
            "server_info_disclosure": False,
            "directory_listing": False,
        }
        
        # Check for server information disclosure
        self._check_server_info_disclosure(response, result)
        
        # Check for vulnerabilities that require additional requests
        timeout = self.config.get("timeout", 5)
        
        # Only perform these tests if they are enabled
        if self.config.get("test_open_redirect", True):
            self._check_open_redirect(result.endpoint.url, timeout, result)
        
        if self.config.get("test_directory_listing", True):
            self._check_directory_listing(result.endpoint.url, timeout, result)
    
    def _check_server_info_disclosure(self, response: requests.Response, result: ScanResult) -> None:
        """
        Check for server information disclosure.
        
        Args:
            response: HTTP response
            result: Scan result to update
        """
        server = response.headers.get('Server', '')
        if server and len(server) > 0 and server.lower() not in ["cloudflare"]:
            result.vulnerabilities["server_info_disclosure"] = True
            result.add_issue("Server information disclosure")
    
    def _check_open_redirect(self, url: str, timeout: int, result: ScanResult) -> None:
        """
        Check for open redirect vulnerability.
        
        Args:
            url: URL to check
            timeout: Request timeout
            result: Scan result to update
        """
        try:
            redirect_params = {"url": "https://example.com", "redirect": "https://example.com", "next": "https://example.com"}
            
            for param, value in redirect_params.items():
                redirect_url = f"{url}?{param}={value}"
                response = self.session.get(redirect_url, timeout=timeout, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if "example.com" in location:
                        result.vulnerabilities["open_redirect"] = True
                        result.add_issue("Potential open redirect vulnerability detected")
                        break
        except Exception as e:
            logger.debug(f"Error checking for open redirect: {str(e)}")
    
    def _check_directory_listing(self, url: str, timeout: int, result: ScanResult) -> None:
        """
        Check for directory listing vulnerability.
        
        Args:
            url: URL to check
            timeout: Request timeout
            result: Scan result to update
        """
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            common_dirs = ["/images/", "/uploads/", "/assets/", "/files/", "/backup/"]
            
            for directory in common_dirs:
                try:
                    dir_url = urljoin(base_url, directory)
                    response = self.session.get(dir_url, timeout=timeout)
                    
                    if response.status_code == 200:
                        # Check for common directory listing indicators
                        indicators = ["Index of", "Directory Listing", "Parent Directory"]
                        if any(indicator in response.text for indicator in indicators):
                            result.vulnerabilities["directory_listing"] = True
                            result.add_issue(f"Directory listing enabled at {dir_url}")
                            break
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Error checking for directory listing: {str(e)}")