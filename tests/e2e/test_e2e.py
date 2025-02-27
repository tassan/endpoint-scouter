import os
import sys
import json
import pytest
import subprocess

@pytest.mark.skipif(sys.platform != "linux", reason="E2E tests only run on Linux")
class TestEndToEnd:
    def test_end_to_end(self, tmp_path):
        # Create a test config file
        config_file = tmp_path / "test_config.json"
        config = {
            "endpoints": [
                {"url": "https://httpbin.org/get", "method": "GET"},
                {"url": "https://httpbin.org/post", "method": "POST"}
            ],
            "headers": {"User-Agent": "EndpointScouter-Test"},
            "timeout": 5,
            "checks": ["headers", "response"]
        }
        with open(config_file, "w") as f:
            json.dump(config, f)
        
        # Run the scanner (using subprocess to avoi