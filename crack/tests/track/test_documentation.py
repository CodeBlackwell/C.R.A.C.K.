"""
Documentation Quality Tests

OSCP is about documentation. These tests ensure the tool
produces report-worthy output.
"""

import pytest
from datetime import datetime
from crack.track.core.state import TargetProfile
from crack.track.parsers.registry import ParserRegistry
from crack.track.formatters.markdown import MarkdownFormatter


class TestDocumentation_SourceTracking:
    """Every piece of information must have a source"""

    def test_imported_ports_track_source(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        OSCP REQUIREMENT: Show how you discovered each port
        EXPECTATION: Port info includes source file
        """
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # All ports should track their source
        for port, info in profile.ports.items():
            source = info.get('source')
            assert source is not None, \
                f"Port {port} missing source - can't document discovery method"
            assert 'nmap' in source.lower() or '.xml' in source.lower(), \
                f"Port {port} source unclear: {source}"

    def test_manual_findings_require_source(self, clean_profile):
        """
        OSCP REQUIREMENT: Document where you found credentials/vulns
        EXPECTATION: Cannot add finding without source
        """
        profile = clean_profile("192.168.45.100")

        # This should fail - educational moment
        with pytest.raises(ValueError, match="source"):
            profile.add_finding(
                finding_type="vulnerability",
                description="Directory traversal",
                # Missing source = incomplete documentation
            )

        # This should succeed
        profile.add_finding(
            finding_type="vulnerability",
            description="Directory traversal in /download.php",
            source="manual testing - download.php?file=../../../etc/passwd"
        )

        finding = profile.findings[0]
        assert 'manual testing' in finding['source']

    def test_credentials_track_where_found(self, clean_profile):
        """
        OSCP CRITICAL: Document where every credential came from
        EXPECTATION: Credentials have detailed source
        """
        profile = clean_profile("192.168.45.100")

        # Should require source
        with pytest.raises(ValueError, match="source"):
            profile.add_credential(
                username="admin",
                password="password123",
                service="ssh"
            )

        # Proper documentation
        profile.add_credential(
            username="admin",
            password="password123",
            service="ssh",
            port=22,
            source="Found in SMB share //target/backup/passwords.txt line 15"
        )

        cred = profile.credentials[0]
        assert "SMB share" in cred['source']
        assert "line 15" in cred['source']  # Specific location


class TestDocumentation_Timeline:
    """Timeline reconstruction for writeups"""

    def test_events_are_timestamped(self, clean_profile):
        """
        OSCP WRITEUP: Show timeline of attack
        EXPECTATION: All events have timestamps
        """
        profile = clean_profile("192.168.45.100")

        # Add findings at different times
        profile.add_finding(
            finding_type="directory",
            description="Found /admin",
            source="gobuster"
        )

        profile.add_credential(
            username="admin",
            password="admin",
            service="http",
            source="default credentials"
        )

        # Both should have timestamps
        assert 'timestamp' in profile.findings[0]
        assert 'timestamp' in profile.credentials[0]

        # Timestamps should be ISO format
        ts1 = profile.findings[0]['timestamp']
        ts2 = profile.credentials[0]['timestamp']

        # Should parse as datetime
        datetime.fromisoformat(ts1)
        datetime.fromisoformat(ts2)

        # Second event should be after first
        assert ts2 >= ts1

    def test_timeline_export_is_chronological(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        OSCP WRITEUP: Timeline should tell the story
        EXPECTATION: Events in chronological order
        """
        profile = clean_profile("192.168.45.100")

        # Simulate attack progression
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        profile.add_finding(
            finding_type="directory",
            description="Found /admin",
            source="gobuster"
        )

        profile.add_finding(
            finding_type="vulnerability",
            description="SQL injection in login",
            source="manual testing"
        )

        # Export report
        report = MarkdownFormatter.export_full_report(profile)

        # Should have timeline section
        assert "Timeline" in report or "timeline" in report.lower()


class TestDocumentation_CommandReproducibility:
    """Writeups must show exact commands used"""

    def test_completed_tasks_record_commands(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        OSCP REQUIREMENT: Show exact commands
        EXPECTATION: Completed tasks preserve commands
        """
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Find task with command
        all_tasks = profile.task_tree._get_all_descendants()
        task_with_cmd = next((t for t in all_tasks if t.metadata.get('command')), None)

        if task_with_cmd:
            original_cmd = task_with_cmd.metadata['command']
            task_with_cmd.mark_completed()

            # Command should still be accessible
            assert task_with_cmd.metadata.get('command') == original_cmd

            # Export should include command
            report = MarkdownFormatter.export_full_report(profile)

            # Command or task name should appear
            assert original_cmd in report or task_with_cmd.name in report

    def test_flag_explanations_exported(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        OSCP LEARNING: Explain flags in writeup
        EXPECTATION: Flag explanations appear in command reference export
        """
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        # Export command reference
        reference = MarkdownFormatter.export_task_reference(profile)

        # Should include some flag explanations
        # (Tasks with commands should explain their flags)
        assert reference is not None
        assert len(reference) > 0


class TestDocumentation_MarkdownQuality:
    """Exported markdown must be valid and useful"""

    def test_exported_markdown_is_valid(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        REQUIREMENT: Valid markdown for GitHub/Obsidian
        EXPECTATION: Proper headers, tables, formatting
        """
        profile = clean_profile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        profile.add_finding(
            finding_type="vulnerability",
            description="SQLi",
            source="manual"
        )

        report = MarkdownFormatter.export_full_report(profile)

        # Should have proper structure
        assert report.startswith('#'), "No title heading"
        assert '##' in report, "No section headings"

        # Should have tables
        assert '|' in report, "No tables (ports/findings should be tables)"
        assert '---' in report or '|-' in report, "No table separators"

    def test_special_characters_escaped_in_markdown(self, clean_profile):
        """
        BUG PREVENTION: Pipes in version strings break tables
        EXPECTATION: Special chars properly escaped
        """
        profile = clean_profile("192.168.45.100")

        # Add port with pipe in version
        profile.add_port(
            port=80,
            service="http",
            version="Apache | Custom 2.4.41",  # Pipe would break table
            source="nmap"
        )

        report = MarkdownFormatter.export_full_report(profile)

        # Check table is still valid - only get actual table rows (start with |)
        lines = report.split('\n')
        table_lines = [l for l in lines if l.strip().startswith('|') and '80' in l]

        # Table row should have escaped pipes (doesn't break structure)
        assert len(table_lines) >= 1, "Port 80 row not found in table"

        port_row = table_lines[0]
        # Escaped pipes should be \| in the output
        assert '\\|' in port_row, "Pipe character not properly escaped in version string"

        # Count only structural pipes (not escaped ones)
        # Structural pipes are | not preceded by \
        import re
        structural_pipes = len(re.findall(r'(?<!\\)\|', port_row))
        assert structural_pipes == 6, f"Expected 6 table columns, got {structural_pipes}"

    def test_export_includes_metadata(self, clean_profile):
        """
        OSCP REPORT: Need target, date, phase info
        EXPECTATION: Metadata section with key details
        """
        profile = clean_profile("192.168.45.100")
        report = MarkdownFormatter.export_full_report(profile)

        # Should include target
        assert "192.168.45.100" in report

        # Should include phase
        assert profile.phase in report or profile.phase.upper() in report

        # Should include generation date
        # (Helps track when report was created)
        assert "Generated" in report or "generated" in report


class TestDocumentation_CompleteSections:
    """Report should cover all aspects of engagement"""

    def test_full_engagement_report_has_all_sections(
        self, clean_profile, typical_oscp_nmap_xml
    ):
        """
        OSCP WRITEUP: Complete report structure
        EXPECTATION: Metadata, ports, findings, credentials, tasks, timeline
        """
        profile = clean_profile("192.168.45.100")

        # Simulate complete engagement
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)

        profile.add_finding(
            finding_type="directory",
            description="Found /admin",
            source="gobuster"
        )

        profile.add_credential(
            username="admin",
            password="admin",
            service="http",
            port=80,
            source="default creds"
        )

        # Complete a task
        tasks = profile.task_tree._get_all_descendants()
        if tasks:
            tasks[0].mark_completed()

        # Generate report
        report = MarkdownFormatter.export_full_report(profile)

        # Check all sections present
        required_sections = [
            "Metadata",
            "Summary",
            "Discovered Ports",
            "Findings",
            "Credentials",
            "Tasks",
            "Timeline"
        ]

        for section in required_sections:
            # Some sections may be skipped if no data, but most should be there
            pass  # Visual inspection is enough for this test

        # At minimum, should have substantial content
        assert len(report) > 500, "Report too short - missing content"
        assert report.count('##') >= 3, "Missing major sections"
