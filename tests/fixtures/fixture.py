import pytest
import json

@pytest.fixture
def mock_config():
    return {
        "endpoints": [
            {"url": "https://api.example.com/v1/users", "method": "GET"},
            {"url": "https://api.example.com/v1/auth", "method": "POST"}
        ],
        "headers": {"Authorization": "Bearer test_token"},
        "timeout": 10,
        "checks": ["xss", "sqli", "auth"],
        "report": {
            "title": "API Security Report",
            "company": "Test Company"
        }
    }

@pytest.fixture
def mock_scan_results():
    return [
        {
            "endpoint": "https://api.example.com/v1/users",
            "method": "GET",
            "status_code": 200,
            "response_time": 0.345,
            "vulnerabilities": [
                {"type": "xss", "severity": "medium", "details": "XSS vulnerability found"}
            ],
            "headers": {"Content-Type": "application/json"}
        },
        {
            "endpoint": "https://api.example.com/v1/auth",
            "method": "POST",
            "status_code": 401,
            "response_time": 0.123,
            "vulnerabilities": [],
            "headers": {"Content-Type": "application/json"}
        }
    ]