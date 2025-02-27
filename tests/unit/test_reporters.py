import json
from unittest.mock import patch, mock_open

from endpoint_scouter.reporters.json_reporter import JsonReporter
from endpoint_scouter.reporters.csv_reporter import CsvReporter
from endpoint_scouter.reporters.html_reporter import HtmlReporter
from ..fixtures.fixture import mock_config, mock_scan_results

class TestReporters:
    def test_json_reporter(self, mock_config, mock_scan_results):
        reporter = JsonReporter(mock_config)
        
        with patch('builtins.open', new_callable=mock_open()) as mock_file:
            output_file = reporter.generate(mock_scan_results, "report.json")
            
            assert output_file == "report.json"
            mock_file.assert_called_once_with("report.json", "w")
            handle = mock_file()
            
            # Verify JSON was written
            write_args = handle.write.call_args[0][0]
            assert isinstance(json.loads(write_args), dict)
    
    def test_csv_reporter(self, mock_config, mock_scan_results):
        reporter = CsvReporter(mock_config)
        
        with patch('builtins.open', new_callable=mock_open()) as mock_file:
            output_file = reporter.generate(mock_scan_results, "report.csv")
            
            assert output_file == "report.csv"
            mock_file.assert_called_once_with("report.csv", "w", newline="")
    
    def test_html_reporter(self, mock_config, mock_scan_results):
        config = {**mock_config, "dbz_mode": False}
        reporter = HtmlReporter(config)
        
        with patch('builtins.open', new_callable=mock_open()) as mock_file:
            output_file = reporter.generate(mock_scan_results, "report.html")
            
            assert output_file == "report.html"
            mock_file.assert_called_once_with("report.html", "w")