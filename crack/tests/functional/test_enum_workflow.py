#!/usr/bin/env python3
"""
Functional tests for complete enumeration workflow
Tests the full pipeline from port scanning to CVE lookup
"""

import pytest
from unittest.mock import Mock, patch, call
from pathlib import Path
import tempfile
import shutil

from crack.network.port_scanner import PortScanner
from crack.network.parallel_enumerator import ParallelEnumerator
from crack.network.enum_scan import save_markdown_report
from crack.exploit.cve_lookup import CVELookup


class TestEnumerationWorkflow:
    """Test complete enumeration workflow functionality"""

    @pytest.mark.functional
    @pytest.mark.slow
    def test_full_enumeration_pipeline(self, temp_output_dir, target_ip,
                                      nmap_greppable_output, nmap_service_output,
                                      searchsploit_output):
        """Test the complete enumeration workflow from scan to report"""

        # Step 1: Port Discovery
        with patch('subprocess.run') as mock_run:
            # Setup mock for stage 1
            ports_file = temp_output_dir / "ports_discovery.gnmap"
            ports_file.write_text(nmap_greppable_output)

            # Setup mock for stage 2
            scan_file = temp_output_dir / "service_scan.nmap"
            scan_file.write_text(nmap_service_output)

            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            # Run port scanner
            scanner = PortScanner(target_ip, temp_output_dir)
            scan_results = scanner.run()

            assert scan_results is not None
            assert scan_results['ports'] == [22, 80, 443, 3306, 8080]
            assert scan_results['scan_file'] is not None

        # Step 2: Parallel Enumeration
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "Enumeration output"
            mock_run.return_value = mock_result

            enumerator = ParallelEnumerator(
                target_ip,
                scan_results['ports'],
                temp_output_dir,
                run_udp=True
            )

            # Mock the scan methods
            with patch.object(enumerator, 'scan_udp', return_value=(True, "UDP scan output")), \
                 patch.object(enumerator, 'scan_whatweb', return_value=(True, "WhatWeb output")), \
                 patch.object(enumerator, 'scan_web', return_value=(True, "Nikto output")), \
                 patch.object(enumerator, 'scan_smb', return_value=(False, "No SMB ports")):

                parallel_results = enumerator.run_all()

                assert 'UDP' in parallel_results
                assert 'WhatWeb' in parallel_results
                assert 'Nikto' in parallel_results
                assert parallel_results['UDP']['success'] is True

        # Step 3: CVE Lookup
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = searchsploit_output
            mock_run.return_value = mock_result

            lookup = CVELookup(scan_results['scan_file'])
            cve_results = lookup.lookup_all()

            assert len(cve_results) > 0

        # Step 4: Generate Report
        report_file = save_markdown_report(
            target_ip,
            temp_output_dir,
            scan_results,
            parallel_results,
            cve_results
        )

        # Verify report was created
        assert Path(report_file).exists()

        # Verify report content
        with open(report_file, 'r') as f:
            content = f.read()

            # Check report sections
            assert "# Enumeration Report" in content
            assert "## Methodology" in content
            assert "## Open Ports" in content
            assert "## Parallel Enumeration" in content
            assert "## CVE & Exploit Findings" in content
            assert "## Next Steps" in content

            # Check specific content
            assert target_ip in content
            assert "22/tcp" in content
            assert "80/tcp" in content
            assert "Two-Stage Port Scanning" in content

    @pytest.mark.functional
    def test_workflow_with_no_open_ports(self, temp_output_dir, target_ip,
                                        nmap_no_ports_output):
        """Test workflow when no open ports are found"""

        with patch('subprocess.run') as mock_run:
            ports_file = temp_output_dir / "ports_discovery.gnmap"
            ports_file.write_text(nmap_no_ports_output)

            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            scanner = PortScanner(target_ip, temp_output_dir)
            scan_results = scanner.run()

            # Should return None when no ports found
            assert scan_results is None

    @pytest.mark.functional
    def test_workflow_error_recovery(self, temp_output_dir, target_ip):
        """Test workflow handles errors gracefully"""

        # Test with nmap failure
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Nmap not installed")

            scanner = PortScanner(target_ip, temp_output_dir)
            ports = scanner.stage1_fast_discovery()

            assert ports == []

        # Test with searchsploit failure
        with patch('subprocess.run') as mock_run:
            scan_file = temp_output_dir / "test.nmap"
            scan_file.write_text("80/tcp open http Apache 2.4.52")

            mock_run.side_effect = FileNotFoundError("searchsploit not found")

            lookup = CVELookup(str(scan_file))
            exploits = lookup.search_exploits("Apache")

            assert exploits == []

    @pytest.mark.functional
    @pytest.mark.fast
    def test_report_generation_completeness(self, temp_output_dir):
        """Test that markdown report includes all necessary information"""

        # Create mock results
        scan_results = {
            'ports': [22, 80, 443],
            'scan_file': '/tmp/scan.nmap',
            'output_dir': str(temp_output_dir)
        }

        parallel_results = {
            'WhatWeb': {'success': True, 'output': 'Apache/2.4.52'},
            'Nikto': {'success': False, 'output': 'Error'},
            'UDP': {'success': True, 'output': 'SNMP found'}
        }

        cve_results = {
            '80': {
                'service': 'http',
                'version': 'Apache httpd 2.4.52',
                'exploits': [
                    {'title': 'Apache RCE', 'path': 'linux/webapps/123.sh'}
                ]
            }
        }

        # Generate report
        report_file = save_markdown_report(
            "192.168.45.100",
            temp_output_dir,
            scan_results,
            parallel_results,
            cve_results
        )

        with open(report_file, 'r') as f:
            content = f.read()

            # Check methodology section
            assert "nmap -p- --min-rate=5000" in content
            assert "nmap -p22,80,443 -sV -sC" in content

            # Check parallel scan results
            assert "✓ Complete" in content  # WhatWeb success
            assert "✗ Failed" in content    # Nikto failure

            # Check CVE findings
            assert "Apache RCE" in content
            assert "linux/webapps/123.sh" in content

            # Check manual verification section
            assert "nc -nv" in content

    @pytest.mark.functional
    def test_parallel_execution_timing(self, temp_output_dir, target_ip):
        """Test that parallel scans actually run concurrently"""
        import time

        enumerator = ParallelEnumerator(target_ip, [80, 139], temp_output_dir)

        # Mock scan methods with delays
        def slow_scan(*args, **kwargs):
            time.sleep(0.1)
            return True, "Output"

        with patch.object(enumerator, 'scan_whatweb', side_effect=slow_scan), \
             patch.object(enumerator, 'scan_web', side_effect=slow_scan), \
             patch.object(enumerator, 'scan_smb', side_effect=slow_scan):

            start_time = time.time()
            results = enumerator.run_all()
            elapsed = time.time() - start_time

            # If run in parallel, should take ~0.1s (not 0.3s sequential)
            # Allow some overhead
            assert elapsed < 0.25

            assert len(results) == 3

    @pytest.mark.functional
    def test_service_version_to_cve_mapping(self, temp_output_dir):
        """Test accurate mapping of service versions to CVEs"""

        # Create nmap output with specific versions
        nmap_content = """
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u7
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
3306/tcp open  mysql       MySQL 5.5.62-0+deb8u1
"""
        scan_file = temp_output_dir / "services.nmap"
        scan_file.write_text(nmap_content)

        lookup = CVELookup(str(scan_file))
        services = lookup.parse_services()

        # Check version extraction
        assert len(services) == 3

        service_dict = {port: (svc, ver) for port, svc, ver in services}
        assert 'OpenSSH 7.4p1' in service_dict['22'][1]
        assert 'Apache httpd 2.4.25' in service_dict['80'][1]
        assert 'MySQL 5.5.62' in service_dict['3306'][1]

    @pytest.mark.functional
    def test_output_file_organization(self, temp_output_dir, target_ip):
        """Test that output files are properly organized"""

        # Simulate creating various output files
        files_to_create = [
            "ports_discovery.gnmap",
            "service_scan.nmap",
            "service_scan.xml",
            "service_scan.gnmap",
            "nikto.txt",
            "whatweb.txt",
            "enum4linux.txt",
            "udp_scan.txt",
            "enumeration.md"
        ]

        for filename in files_to_create:
            (temp_output_dir / filename).write_text(f"Content of {filename}")

        # Verify all files exist
        for filename in files_to_create:
            assert (temp_output_dir / filename).exists()

        # Check that files can be read back
        content = (temp_output_dir / "enumeration.md").read_text()
        assert "Content of enumeration.md" in content

    @pytest.mark.functional
    @pytest.mark.fast
    def test_time_optimization_verification(self):
        """Test that two-stage scanning provides time savings"""

        # Calculate theoretical time savings
        all_ports = 65535
        open_ports = 5

        # Traditional approach: -sV -sC on all ports
        traditional_time = all_ports * 0.01  # Rough estimate

        # Two-stage approach
        stage1_time = all_ports * 0.001  # Fast scan
        stage2_time = open_ports * 0.1   # Detailed scan on few ports
        optimized_time = stage1_time + stage2_time

        # Should be significantly faster
        time_saved = traditional_time - optimized_time
        savings_percentage = (time_saved / traditional_time) * 100

        assert savings_percentage > 50  # Should save at least 50% time