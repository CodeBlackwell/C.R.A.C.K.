#!/usr/bin/env python3
"""
Unit tests for CVELookup module
Tests searchsploit integration and service parsing
"""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path
import subprocess

from crack.exploit.cve_lookup import CVELookup


class TestCVELookup:
    """Test CVELookup functionality"""

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_init(self, temp_output_dir, nmap_service_output):
        """Test CVELookup initialization"""
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        lookup = CVELookup(str(scan_file))

        assert lookup.scan_file == Path(scan_file)
        assert lookup.services == []
        assert lookup.exploits == {}

    @pytest.mark.unit
    @pytest.mark.exploit
    @pytest.mark.fast
    def test_parse_services(self, temp_output_dir, nmap_service_output):
        """Test parsing service versions from nmap output"""
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        lookup = CVELookup(str(scan_file))
        services = lookup.parse_services()

        # Should extract port, service, and version
        assert len(services) > 0
        assert lookup.services == services

        # Check specific services
        service_dict = {port: (svc, ver) for port, svc, ver in services}

        assert '22' in service_dict
        assert service_dict['22'][0] == 'ssh'
        assert 'OpenSSH 8.9p1' in service_dict['22'][1]

        assert '80' in service_dict
        assert service_dict['80'][0] == 'http'
        assert 'Apache httpd 2.4.52' in service_dict['80'][1]

        assert '3306' in service_dict
        assert service_dict['3306'][0] == 'mysql'
        assert 'MySQL 8.0.35' in service_dict['3306'][1]

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_parse_services_no_file(self):
        """Test parsing when scan file doesn't exist"""
        lookup = CVELookup("/nonexistent/file.nmap")
        services = lookup.parse_services()

        assert services == []
        assert lookup.services == []

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_parse_services_edge_cases(self, temp_output_dir):
        """Test parsing various nmap output formats"""
        test_cases = [
            # Standard format with version info
            ("80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))",
             [('80', 'http', 'Apache httpd 2.4.52')]),

            # No version info
            ("22/tcp   open  ssh",
             []),

            # Multiple services
            ("80/tcp   open  http    Apache httpd 2.4.52\n443/tcp   open  ssl/http    nginx 1.18.0",
             [('80', 'http', 'Apache httpd 2.4.52'), ('443', 'ssl/http', 'nginx 1.18.0')]),

            # Service with complex version string
            ("3306/tcp open  mysql   MySQL 5.7.42-0ubuntu0.18.04.1 (Ubuntu)",
             [('3306', 'mysql', 'MySQL 5.7.42-0ubuntu0.18.04.1')]),

            # Closed/filtered ports (should be ignored)
            ("80/tcp   closed  http\n443/tcp   filtered  https",
             []),
        ]

        for content, expected in test_cases:
            scan_file = temp_output_dir / "test.nmap"
            scan_file.write_text(content)

            lookup = CVELookup(str(scan_file))
            services = lookup.parse_services()

            assert services == expected

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_search_exploits_success(self, searchsploit_output):
        """Test successful searchsploit execution"""
        lookup = CVELookup("/dummy/path")

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = searchsploit_output
            mock_run.return_value = mock_result

            exploits = lookup.search_exploits("Apache 2.4", max_results=3)

            assert len(exploits) == 3
            assert exploits[0]['title'] == "Apache 2.4.49/2.4.50 - Path Traversal & Remote Code Execution"
            assert exploits[0]['path'] == "linux/webapps/50383.sh"
            assert exploits[1]['title'] == "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution"
            assert exploits[2]['title'] == "Apache HTTP Server 2.4.50 - Remote Code Execution"

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_search_exploits_no_results(self, searchsploit_no_results):
        """Test searchsploit with no results"""
        lookup = CVELookup("/dummy/path")

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = searchsploit_no_results
            mock_run.return_value = mock_result

            exploits = lookup.search_exploits("NonexistentSoftware")

            assert exploits == []

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_search_exploits_max_results(self, searchsploit_output):
        """Test limiting maximum results"""
        lookup = CVELookup("/dummy/path")

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            # Add more exploits to test max_results
            extended_output = searchsploit_output + "\n" + \
                "Extra Exploit 1 | path1\n" + \
                "Extra Exploit 2 | path2\n"
            mock_result.stdout = extended_output
            mock_run.return_value = mock_result

            exploits = lookup.search_exploits("Apache", max_results=2)

            assert len(exploits) == 2

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_search_exploits_timeout(self):
        """Test searchsploit timeout handling"""
        lookup = CVELookup("/dummy/path")

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired('searchsploit', 30)

            exploits = lookup.search_exploits("Apache")

            assert exploits == []

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_search_exploits_not_installed(self):
        """Test handling when searchsploit is not installed"""
        lookup = CVELookup("/dummy/path")

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()

            exploits = lookup.search_exploits("Apache")

            assert exploits == []

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_lookup_all(self, temp_output_dir, nmap_service_output, searchsploit_output, capsys):
        """Test complete lookup workflow"""
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        lookup = CVELookup(str(scan_file))

        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = searchsploit_output
            mock_run.return_value = mock_result

            results = lookup.lookup_all()

            # Should have results for services with exploits found
            assert len(results) > 0

            # Check that services were queried
            assert mock_run.called

            # Verify result structure
            for port, data in results.items():
                assert 'service' in data
                assert 'version' in data
                assert 'exploits' in data
                assert isinstance(data['exploits'], list)

            captured = capsys.readouterr()
            assert "[CVE & EXPLOIT LOOKUP]" in captured.out

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_lookup_all_no_services(self):
        """Test lookup when no services are found"""
        lookup = CVELookup("/nonexistent/file")

        results = lookup.lookup_all()

        assert results == {}

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_get_summary_with_exploits(self):
        """Test summary generation with exploits found"""
        lookup = CVELookup("/dummy/path")

        # Set up mock exploit results
        lookup.exploits = {
            '80': {
                'service': 'http',
                'version': 'Apache httpd 2.4.52',
                'exploits': [
                    {'title': 'Exploit 1', 'path': 'path1'},
                    {'title': 'Exploit 2', 'path': 'path2'}
                ]
            },
            '3306': {
                'service': 'mysql',
                'version': 'MySQL 8.0.35',
                'exploits': [
                    {'title': 'MySQL Exploit', 'path': 'path3'}
                ]
            }
        }

        summary = lookup.get_summary()

        assert "[EXPLOIT SUMMARY]" in summary
        assert "Services with exploits: 2" in summary
        assert "Total exploits found: 3" in summary

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_get_summary_no_exploits(self):
        """Test summary generation with no exploits found"""
        lookup = CVELookup("/dummy/path")
        lookup.exploits = {}

        summary = lookup.get_summary()

        assert "No exploits found" in summary

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_generate_commands(self, temp_output_dir, nmap_service_output):
        """Test manual command generation"""
        scan_file = temp_output_dir / "service_scan.nmap"
        scan_file.write_text(nmap_service_output)

        lookup = CVELookup(str(scan_file))
        lookup.parse_services()

        commands = lookup.generate_commands()

        assert "[MANUAL CVE RESEARCH COMMANDS]" in commands
        assert 'searchsploit "Apache httpd 2.4.52"' in commands
        assert 'searchsploit "MySQL 8.0.35"' in commands
        assert '# Port 80: http' in commands
        assert '# Port 3306: mysql' in commands

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_generate_commands_no_services(self):
        """Test command generation with no services"""
        lookup = CVELookup("/dummy/path")
        lookup.services = []

        commands = lookup.generate_commands()

        assert commands == []

    @pytest.mark.unit
    @pytest.mark.exploit
    def test_exploit_output_parsing(self):
        """Test parsing different searchsploit output formats"""
        lookup = CVELookup("/dummy/path")

        test_outputs = [
            # Standard format
            ("Title One | path/to/exploit1\nTitle Two | path/to/exploit2", 2),
            # With extra spaces
            ("  Title One  |  path/to/exploit1  ", 1),
            # With header/footer lines (should be ignored)
            ("----\nExploit Title | Path\n----\nReal Exploit | real/path\n----", 1),
            # Empty result
            ("------\n------\nShellcodes: No Results", 0),
            # Malformed line (missing pipe)
            ("This is not a valid line\nValid | path", 1),
        ]

        for output, expected_count in test_outputs:
            with patch('subprocess.run') as mock_run:
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = output
                mock_run.return_value = mock_result

                exploits = lookup.search_exploits("test")
                assert len(exploits) == expected_count

    @pytest.mark.unit
    @pytest.mark.exploit
    @pytest.mark.fast
    def test_version_string_cleanup(self, temp_output_dir):
        """Test version string cleanup in parse_services"""
        test_content = """
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
3306/tcp open  mysql   MySQL 8.0.35-0ubuntu0.22.04.1 ((Ubuntu))
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
"""
        scan_file = temp_output_dir / "test.nmap"
        scan_file.write_text(test_content)

        lookup = CVELookup(str(scan_file))
        services = lookup.parse_services()

        # Check that parentheses are removed from versions
        versions = {svc[2] for svc in services}

        # Versions should have parentheses content removed
        for version in versions:
            assert '((Ubuntu))' not in version
            # But the version numbers should still be there
            if 'Apache' in version:
                assert '2.4.52' in version
            elif 'MySQL' in version:
                assert '8.0.35' in version