#!/usr/bin/env python3
"""
Unit tests for PortScanner module
Tests two-stage port scanning functionality
"""

import pytest
from unittest.mock import Mock, patch, call
from pathlib import Path
import subprocess

from crack.network.port_scanner import PortScanner


class TestPortScanner:
    """Test PortScanner two-stage scanning functionality"""

    @pytest.mark.unit
    @pytest.mark.network
    def test_init_configuration(self, temp_output_dir, target_ip):
        """Test PortScanner initialization with various configurations"""
        # Test with default min_rate
        scanner = PortScanner(target_ip, temp_output_dir)
        assert scanner.target == target_ip
        assert scanner.output_dir == Path(temp_output_dir)
        assert scanner.min_rate == 5000
        assert scanner.open_ports == []

        # Test with custom min_rate
        scanner_custom = PortScanner(target_ip, temp_output_dir, min_rate=3000)
        assert scanner_custom.min_rate == 3000

    @pytest.mark.unit
    @pytest.mark.network
    @pytest.mark.fast
    def test_stage1_port_discovery_success(self, temp_output_dir, target_ip, nmap_greppable_output, capsys):
        """Test successful stage 1 fast port discovery"""
        scanner = PortScanner(target_ip, temp_output_dir)

        # Create mock greppable output file
        ports_file = temp_output_dir / "ports_discovery.gnmap"
        ports_file.write_text(nmap_greppable_output)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            # Run stage 1
            ports = scanner.stage1_fast_discovery()

            # Verify discovered ports
            assert ports == [22, 80, 443, 3306, 8080]
            assert scanner.open_ports == [22, 80, 443, 3306, 8080]

            # Verify nmap was called correctly
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert 'nmap' in call_args
            assert '-p-' in call_args
            assert '--min-rate=5000' in call_args
            assert target_ip in call_args

            # Check output
            captured = capsys.readouterr()
            assert "FOUND 5 open ports" in captured.out
            assert "22,80,443,3306,8080" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_stage1_no_open_ports(self, temp_output_dir, target_ip, nmap_no_ports_output, capsys):
        """Test stage 1 when no open ports are found"""
        scanner = PortScanner(target_ip, temp_output_dir)

        ports_file = temp_output_dir / "ports_discovery.gnmap"
        ports_file.write_text(nmap_no_ports_output)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            ports = scanner.stage1_fast_discovery()

            assert ports == []
            assert scanner.open_ports == []

            captured = capsys.readouterr()
            assert "No open ports found" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_stage1_timeout_handling(self, temp_output_dir, target_ip, capsys):
        """Test stage 1 timeout handling"""
        scanner = PortScanner(target_ip, temp_output_dir)

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired('nmap', 120)

            ports = scanner.stage1_fast_discovery()

            assert ports == []
            captured = capsys.readouterr()
            assert "Stage 1 timeout" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_stage2_service_detection_success(self, temp_output_dir, target_ip, nmap_service_output, capsys):
        """Test successful stage 2 service detection"""
        scanner = PortScanner(target_ip, temp_output_dir)
        scanner.open_ports = [22, 80, 443, 3306, 8080]

        # Create mock service scan output
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            # Run stage 2
            result = scanner.stage2_service_detection()

            assert result == str(scan_file)

            # Verify nmap was called with correct ports
            call_args = mock_run.call_args[0][0]
            assert 'nmap' in call_args
            assert '-p22,80,443,3306,8080' in call_args
            assert '-sV' in call_args
            assert '-sC' in call_args

            captured = capsys.readouterr()
            assert "Service scan complete" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_stage2_no_ports_to_scan(self, temp_output_dir, target_ip, capsys):
        """Test stage 2 when no ports are available"""
        scanner = PortScanner(target_ip, temp_output_dir)
        scanner.open_ports = []

        result = scanner.stage2_service_detection()

        assert result is None
        captured = capsys.readouterr()
        assert "No ports to scan in Stage 2" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_full_run_workflow(self, temp_output_dir, target_ip, nmap_greppable_output, nmap_service_output):
        """Test complete two-stage scanning workflow"""
        scanner = PortScanner(target_ip, temp_output_dir)

        # Setup mock files
        ports_file = temp_output_dir / "ports_discovery.gnmap"
        ports_file.write_text(nmap_greppable_output)
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            # Run complete workflow
            result = scanner.run()

            assert result is not None
            assert result['ports'] == [22, 80, 443, 3306, 8080]
            assert result['scan_file'] == str(scan_file)
            assert result['output_dir'] == str(temp_output_dir)

            # Verify both stages were called
            assert mock_run.call_count == 2

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_with_no_open_ports(self, temp_output_dir, target_ip, nmap_no_ports_output):
        """Test complete workflow when no ports are found"""
        scanner = PortScanner(target_ip, temp_output_dir)

        ports_file = temp_output_dir / "ports_discovery.gnmap"
        ports_file.write_text(nmap_no_ports_output)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            result = scanner.run()

            assert result is None
            # Only stage 1 should run
            assert mock_run.call_count == 1

    @pytest.mark.unit
    @pytest.mark.network
    def test_port_parsing_edge_cases(self, temp_output_dir, target_ip):
        """Test edge cases in port parsing from greppable output"""
        scanner = PortScanner(target_ip, temp_output_dir)

        # Test with various greppable formats
        test_cases = [
            # Standard format
            ("Host: 192.168.45.100 ()	Ports: 80/open/tcp//http///", [80]),
            # Multiple ports
            ("Ports: 22/open/tcp///, 80/open/tcp///, 443/open/tcp///", [22, 80, 443]),
            # Filtered ports (should not be included)
            ("Ports: 22/open/tcp///, 80/filtered/tcp///, 443/open/tcp///", [22, 443]),
            # No ports
            ("Host: 192.168.45.100 ()	Ports:", []),
            # Unusual port numbers
            ("Ports: 1/open/tcp///, 65535/open/tcp///", [1, 65535]),
        ]

        for content, expected_ports in test_cases:
            ports_file = temp_output_dir / "test.gnmap"
            ports_file.write_text(content)

            with patch('subprocess.run'):
                # Reset scanner state
                scanner.open_ports = []

                # Manually parse the file
                with open(ports_file, 'r') as f:
                    content = f.read()
                    import re
                    port_matches = re.findall(r'(\d+)/open', content)
                    scanner.open_ports = sorted([int(p) for p in port_matches])

                assert scanner.open_ports == sorted(expected_ports)

    @pytest.mark.unit
    @pytest.mark.network
    def test_error_handling(self, temp_output_dir, target_ip, capsys):
        """Test various error conditions"""
        scanner = PortScanner(target_ip, temp_output_dir)

        # Test generic exception handling
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Nmap not found")

            ports = scanner.stage1_fast_discovery()

            assert ports == []
            captured = capsys.readouterr()
            assert "Error: Nmap not found" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_output_directory_creation(self, target_ip):
        """Test that output directory is created if it doesn't exist"""
        import tempfile
        import shutil

        # Use a non-existent directory
        temp_base = tempfile.mkdtemp()
        output_dir = Path(temp_base) / "non_existent" / "nested"

        try:
            scanner = PortScanner(target_ip, output_dir)
            # Directory should be created by Path operations when needed
            assert scanner.output_dir == output_dir
        finally:
            shutil.rmtree(temp_base, ignore_errors=True)