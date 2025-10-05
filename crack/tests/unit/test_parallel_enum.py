#!/usr/bin/env python3
"""
Unit tests for ParallelEnumerator module
Tests parallel execution of enumeration tools
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import subprocess
from concurrent.futures import Future

from crack.network.parallel_enumerator import ParallelEnumerator


class TestParallelEnumerator:
    """Test ParallelEnumerator functionality"""

    @pytest.mark.unit
    @pytest.mark.network
    def test_init_detection(self, temp_output_dir, target_ip):
        """Test initialization and service detection logic"""
        # Test with web and SMB ports
        ports = [22, 80, 443, 139, 445, 3306]
        enumerator = ParallelEnumerator(target_ip, ports, temp_output_dir, run_udp=False)

        assert enumerator.target == target_ip
        assert enumerator.ports == ports
        assert enumerator.has_web is True  # Port 80 and 443 present
        assert enumerator.has_smb is True  # Port 139 and 445 present
        assert enumerator.run_udp is False

        # Test with no web/SMB ports
        enumerator2 = ParallelEnumerator(target_ip, [22, 3306], temp_output_dir, run_udp=True)
        assert enumerator2.has_web is False
        assert enumerator2.has_smb is False
        assert enumerator2.run_udp is True

    @pytest.mark.unit
    @pytest.mark.network
    @pytest.mark.fast
    def test_run_command_success(self, temp_output_dir, target_ip, capsys):
        """Test successful command execution"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "Scan completed successfully"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            success, output = enumerator._run_command("Test Scan", ["test", "command"], timeout=10)

            assert success is True
            assert output == "Scan completed successfully"

            captured = capsys.readouterr()
            assert "[Starting] Test Scan" in captured.out
            assert "[Complete] Test Scan" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_command_failure(self, temp_output_dir, target_ip, capsys):
        """Test command execution with non-zero exit code"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 1
            mock_result.stdout = ""
            mock_result.stderr = "Error occurred"
            mock_run.return_value = mock_result

            success, output = enumerator._run_command("Failed Scan", ["test"], timeout=10)

            assert success is False
            assert output == "Error occurred"

            captured = capsys.readouterr()
            assert "[Warning] Failed Scan exited with code 1" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_command_timeout(self, temp_output_dir, target_ip, capsys):
        """Test command timeout handling"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired('test', 10)

            success, output = enumerator._run_command("Timeout Scan", ["test"], timeout=10)

            assert success is False
            assert output == "Timeout"

            captured = capsys.readouterr()
            assert "[Timeout] Timeout Scan" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_command_missing_tool(self, temp_output_dir, target_ip, capsys):
        """Test handling of missing tools"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("Command not found")

            success, output = enumerator._run_command("Missing Tool", ["nonexistent"], timeout=10)

            assert success is False
            assert output == "Tool not found"

            captured = capsys.readouterr()
            assert "[Missing] Missing Tool - tool not installed" in captured.out

    @pytest.mark.unit
    @pytest.mark.network
    def test_scan_udp_enabled(self, temp_output_dir, target_ip):
        """Test UDP scan when enabled"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir, run_udp=True)

        with patch.object(enumerator, '_run_command') as mock_run:
            mock_run.return_value = (True, "UDP scan output")

            success, output = enumerator.scan_udp()

            assert success is True
            assert output == "UDP scan output"

            # Verify command structure
            call_args = mock_run.call_args
            assert call_args[0][0] == "UDP Scan"
            cmd = call_args[0][1]
            assert 'sudo' in cmd
            assert 'nmap' in cmd
            assert '-sU' in cmd
            assert '--top-ports' in cmd
            assert '20' in cmd

    @pytest.mark.unit
    @pytest.mark.network
    def test_scan_udp_disabled(self, temp_output_dir, target_ip):
        """Test UDP scan when disabled"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir, run_udp=False)

        success, output = enumerator.scan_udp()

        assert success is False
        assert "Skipped" in output

    @pytest.mark.unit
    @pytest.mark.network
    @pytest.mark.web
    def test_scan_web_with_https(self, temp_output_dir, target_ip):
        """Test web scanning with HTTPS ports"""
        enumerator = ParallelEnumerator(target_ip, [443, 8443], temp_output_dir)

        with patch.object(enumerator, '_run_command') as mock_run:
            mock_run.return_value = (True, "Nikto scan output")

            success, output = enumerator.scan_web()

            assert success is True

            # Verify HTTPS URL was used
            call_args = mock_run.call_args
            cmd = call_args[0][1]
            assert f'https://{target_ip}' in cmd
            assert 'nikto' in cmd

    @pytest.mark.unit
    @pytest.mark.network
    @pytest.mark.web
    def test_scan_web_with_http(self, temp_output_dir, target_ip):
        """Test web scanning with HTTP ports"""
        enumerator = ParallelEnumerator(target_ip, [80, 8080], temp_output_dir)

        with patch.object(enumerator, '_run_command') as mock_run:
            mock_run.return_value = (True, "Nikto scan output")

            success, output = enumerator.scan_web()

            assert success is True

            # Verify HTTP URL was used
            call_args = mock_run.call_args
            cmd = call_args[0][1]
            assert f'http://{target_ip}' in cmd

    @pytest.mark.unit
    @pytest.mark.network
    def test_scan_web_no_ports(self, temp_output_dir, target_ip):
        """Test web scanning when no web ports are detected"""
        enumerator = ParallelEnumerator(target_ip, [22, 3306], temp_output_dir)

        success, output = enumerator.scan_web()

        assert success is False
        assert "No web ports detected" in output

    @pytest.mark.unit
    @pytest.mark.network
    def test_scan_smb(self, temp_output_dir, target_ip):
        """Test SMB enumeration"""
        enumerator = ParallelEnumerator(target_ip, [139, 445], temp_output_dir)

        with patch.object(enumerator, '_run_command') as mock_run:
            mock_run.return_value = (True, "enum4linux output")

            success, output = enumerator.scan_smb()

            assert success is True
            assert output == "enum4linux output"

            # Verify output file was written
            expected_file = temp_output_dir / "enum4linux.txt"
            assert expected_file.exists()
            assert expected_file.read_text() == "enum4linux output"

            # Verify command structure
            call_args = mock_run.call_args
            cmd = call_args[0][1]
            assert 'enum4linux' in cmd
            assert '-a' in cmd

    @pytest.mark.unit
    @pytest.mark.network
    def test_scan_whatweb(self, temp_output_dir, target_ip):
        """Test WhatWeb fingerprinting"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        with patch.object(enumerator, '_run_command') as mock_run:
            mock_run.return_value = (True, "WhatWeb output")

            success, output = enumerator.scan_whatweb()

            assert success is True
            assert output == "WhatWeb output"

            # Verify output file was written
            expected_file = temp_output_dir / "whatweb.txt"
            assert expected_file.exists()

            # Verify command structure
            call_args = mock_run.call_args
            cmd = call_args[0][1]
            assert 'whatweb' in cmd
            assert '-v' in cmd

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_all_parallel_execution(self, temp_output_dir, target_ip):
        """Test parallel execution of all scans"""
        # Setup with web and SMB ports
        enumerator = ParallelEnumerator(target_ip, [80, 139], temp_output_dir, run_udp=True)

        # Mock the individual scan methods
        with patch.object(enumerator, 'scan_udp') as mock_udp, \
             patch.object(enumerator, 'scan_whatweb') as mock_whatweb, \
             patch.object(enumerator, 'scan_web') as mock_nikto, \
             patch.object(enumerator, 'scan_smb') as mock_smb:

            mock_udp.return_value = (True, "UDP output")
            mock_whatweb.return_value = (True, "WhatWeb output")
            mock_nikto.return_value = (True, "Nikto output")
            mock_smb.return_value = (True, "SMB output")

            results = enumerator.run_all()

            # Verify all scans were executed
            assert 'UDP' in results
            assert 'WhatWeb' in results
            assert 'Nikto' in results
            assert 'SMB' in results

            # Verify results structure
            assert results['UDP']['success'] is True
            assert results['WhatWeb']['success'] is True
            assert results['Nikto']['success'] is True
            assert results['SMB']['success'] is True

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_all_with_failures(self, temp_output_dir, target_ip):
        """Test parallel execution with some scan failures"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir, run_udp=False)

        with patch.object(enumerator, 'scan_whatweb') as mock_whatweb, \
             patch.object(enumerator, 'scan_web') as mock_nikto:

            mock_whatweb.return_value = (True, "WhatWeb output")
            mock_nikto.side_effect = Exception("Nikto failed")

            results = enumerator.run_all()

            # WhatWeb should succeed
            assert results['WhatWeb']['success'] is True

            # Nikto should fail gracefully
            assert 'Nikto' in results
            assert results['Nikto']['success'] is False
            assert "Nikto failed" in results['Nikto']['output']

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_all_no_scans(self, temp_output_dir, target_ip):
        """Test when no scans are applicable"""
        enumerator = ParallelEnumerator(target_ip, [22], temp_output_dir, run_udp=False)

        results = enumerator.run_all()

        assert results == {}

    @pytest.mark.unit
    @pytest.mark.network
    def test_get_summary(self, temp_output_dir, target_ip):
        """Test summary generation"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        # Set some results
        enumerator.results = {
            'WhatWeb': {'success': True, 'output': 'WhatWeb output'},
            'Nikto': {'success': False, 'output': 'Error'},
            'UDP': {'success': True, 'output': 'UDP output'}
        }

        summary = enumerator.get_summary()

        assert "[PARALLEL SCAN SUMMARY]" in summary
        assert "✓ WhatWeb" in summary
        assert "✗ Nikto" in summary
        assert "✓ UDP" in summary

    @pytest.mark.unit
    @pytest.mark.network
    def test_output_truncation(self, temp_output_dir, target_ip):
        """Test that long output is truncated in results"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        # Create long output string
        long_output = "A" * 1000

        with patch.object(enumerator, 'scan_whatweb') as mock_whatweb:
            mock_whatweb.return_value = (True, long_output)

            results = enumerator.run_all()

            # Output should be truncated to 500 chars
            assert len(results['WhatWeb']['output']) == 500

    @pytest.mark.unit
    @pytest.mark.network
    def test_run_method_alias(self, temp_output_dir, target_ip):
        """Test that run_all is the main entry point"""
        enumerator = ParallelEnumerator(target_ip, [80], temp_output_dir)

        # Verify run_all exists and is callable
        assert hasattr(enumerator, 'run_all')
        assert callable(enumerator.run_all)

        # The run() method is referenced as run_all in the main code
        # Verify we can call it
        with patch.object(enumerator, 'scan_whatweb') as mock_whatweb:
            mock_whatweb.return_value = (True, "Output")
            results = enumerator.run_all()
            assert 'WhatWeb' in results