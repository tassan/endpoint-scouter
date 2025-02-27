import json
from unittest.mock import patch, mock_open

from endpoint_scouter.core.scanner import Scanner
from ..fixtures.fixture import mock_config, mock_scan_results

class TestScanner:
    @patch('builtins.open', new_callable=mock_open, read_data=json.dumps({"endpoints": [{"url": "https://example.com/api"}]}))
    def test_scanner_initialization(self, mock_file):
        scanner = Scanner("config.json")
        assert scanner.config is not None
        assert "endpoints" in scanner.config
        assert scanner.endpoints[0]["url"] == "https://example.com/api"
    
    @patch('endpoint_scouter.core.scanner.Scanner.scan_endpoint')
    def test_scan_all(self, mock_scan_endpoint, mock_config):
        mock_scan_endpoint.return_value = {"status": "success"}
        
        with patch('builtins.open', new_callable=mock_open, read_data=json.dumps(mock_config)):
            scanner = Scanner("config.json")
            results = scanner.scan_all()
            
            assert len(results) == 2  # Two endpoints in mock_config
            assert mock_scan_endpoint.call_count == 2
    
    def test_calculate_security_score(self, mock_config, mock_scan_results):
        with patch('builtins.open', new_callable=mock_open, read_data=json.dumps(mock_config)):
            scanner = Scanner("config.json")
            # Mock the scan results
            scanner.last_scan_results = mock_scan_results
            
            score = scanner.calculate_security_score()
            assert isinstance(score, int)
            assert 0 <= score <= 100