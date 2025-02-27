import pytest
from endpoint_scouter.core.result import ScanResult, Endpoint

@pytest.fixture
def mock_scan_results():
    return [
        ScanResult(
            endpoint=Endpoint(url="https://api.example.com/v1/users", method="GET"),
            is_accessible=True,
            status_code=200,
            response_time=0.345,
            vulnerabilities=[{"type": "xss", "severity": "medium"}],
            cors_headers={},
            security_headers=[],
            rate_limit_detected=False,
            issues=[],
            errors=[]
        ),
        ScanResult(
            endpoint=Endpoint(url="https://api.example.com/v1/auth", method="POST"),
            is_accessible=False,
            status_code=401,
            response_time=0.123,
            vulnerabilities=[],
            cors_headers={},
            security_headers=[],
            rate_limit_detected=False,
            issues=[],
            errors=[]
        )
    ]