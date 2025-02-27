import sys
import pytest
from io import StringIO
from contextlib import redirect_stdout
from unittest.mock import patch

from endpoint_scouter.utils.cli import (
    parse_arguments,
    setup_logging,
    print_header,
    print_scan_start,
    print_report_generation,
    print_completion,
    print_report_locations,
    print_error,
)

class TestCLIUtils:
    def test_parse_arguments(self):
        # Test with default arguments
        with patch('sys.argv', ['endpoint_scouter', 'config.json']):
            args = parse_arguments()
            assert args.config_file == 'config.json'
            assert args.format == 'json'
            assert args.output is None
            assert args.verbose is False
            assert args.dbz_mode is False
        
        # Test with custom arguments
        with patch('sys.argv', ['endpoint_scouter', 'custom_config.json', '--format', 'all', 
                                '--output', 'custom_report', '--verbose', '--dbz']):
            args = parse_arguments()
            assert args.config_file == 'custom_config.json'
            assert args.format == 'all'
            assert args.output == 'custom_report'
            assert args.verbose is True
            assert args.dbz_mode is True
    
    @patch('logging.basicConfig')
    def test_setup_logging(self, mock_logging):
        # Test with verbose=False
        setup_logging(False)
        mock_logging.assert_called_once()
        args, kwargs = mock_logging.call_args
        assert kwargs['level'] == 30  # WARNING level
        
        mock_logging.reset_mock()
        
        # Test with verbose=True
        setup_logging(True)
        mock_logging.assert_called_once()
        args, kwargs = mock_logging.call_args
        assert kwargs['level'] == 10  # DEBUG level
    
    def test_print_functions(self):
        # Test print_header
        with StringIO() as buf, redirect_stdout(buf):
            print_header(False)
            output = buf.getvalue()
            assert "EndpointScouter" in output
            assert "DBZ MODE" not in output
        
        with StringIO() as buf, redirect_stdout(buf):
            print_header(True)
            output = buf.getvalue()
            assert "EndpointScouter" in output
            assert "DBZ MODE" in output
        
        # Test print_scan_start
        with StringIO() as buf, redirect_stdout(buf):
            print_scan_start(5, False)
            output = buf.getvalue()
            assert "Scanning 5 endpoints" in output
        
        # Test print_report_generation
        with StringIO() as buf, redirect_stdout(buf):
            print_report_generation(False)
            output = buf.getvalue()
            assert "Generating report" in output
        
        # Test print_completion
        with StringIO() as buf, redirect_stdout(buf):
            print_completion(85, False)
            output = buf.getvalue()
            assert "Security Score: 85" in output
        
        # Test print_report_locations
        report_files = {"json": "report.json", "html": "report.html"}
        with StringIO() as buf, redirect_stdout(buf):
            print_report_locations(report_files)
            output = buf.getvalue()
            assert "Report location" in output
            assert "report.json" in output
            assert "report.html" in output
        
        # Test print_error
        with StringIO() as buf, redirect_stdout(buf):
            print_error(Exception("Test error"), False)
            output = buf.getvalue()
            assert "Error" in output
            assert "Test error" in output
            assert "Traceback" not in output
        
        with StringIO() as buf, redirect_stdout(buf):
            print_error(Exception("Test error"), True)
            output = buf.getvalue()
            assert "Error" in output
            assert "Test error" in output
            assert "Traceback" in output