import sys
from unittest.mock import patch, MagicMock

from endpoint_scouter import main
from endpoint_scouter.utils.cli import parse_arguments
from .fixtures import mock_config, mock_scan_results

class TestIntegration:
    @patch('endpoint_scouter.utils.cli.parse_arguments')
    @patch('endpoint_scouter.core.scanner.Scanner')
    @patch('endpoint_scouter.reporters.json_reporter.JsonReporter')
    @patch('endpoint_scouter.reporters.csv_reporter.CsvReporter')
    @patch('endpoint_scouter.reporters.html_reporter.HtmlReporter')
    def test_main_flow(self, mock_html_reporter, mock_csv_reporter, mock_json_reporter, 
                       mock_scanner, mock_parse_args, mock_config, mock_scan_results):
        # Setup mocks
        args = MagicMock()
        args.config_file = "config.json"
        args.format = "all"
        args.output = "test_report"
        args.verbose = False
        args.dbz_mode = False
        mock_parse_args.return_value = args
        
        scanner_instance = mock_scanner.return_value
        scanner_instance.config = mock_config
        scanner_instance.endpoints = mock_config["endpoints"]
        scanner_instance.scan_all.return_value = mock_scan_results
        scanner_instance.calculate_security_score.return_value = 85
        
        json_reporter_instance = mock_json_reporter.return_value
        json_reporter_instance.generate.return_value = "test_report.json"
        
        csv_reporter_instance = mock_csv_reporter.return_value
        csv_reporter_instance.generate.return_value = "test_report.csv"
        
        html_reporter_instance = mock_html_reporter.return_value
        html_reporter_instance.generate.return_value = "test_report.html"
        
        # Call main function
        result = main()
        
        # Verify flow
        assert result == 0
        mock_parse_args.assert_called_once()
        mock_scanner.assert_called_once_with("config.json")
        scanner_instance.scan_all.assert_called_once()
        scanner_instance.calculate_security_score.assert_called_once()
        
        # Verify reporters were called
        json_reporter_instance.generate.assert_called_once()
        csv_reporter_instance.generate.assert_called_once()
        html_reporter_instance.generate.assert_called_once()
    
    @patch('endpoint_scouter.utils.cli.parse_arguments')
    def test_main_error_handling(self, mock_parse_args):
        # Simulate an error in argument parsing
        mock_parse_args.side_effect = Exception("Test error")
        
        # Call main function
        result = main()
        
        # Verify error handling
        assert result == 1