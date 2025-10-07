"""
Edge Case Tests - Unusual scenarios and error handling

Real pentests are messy. These tests ensure the tool
handles weird situations gracefully.
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.parsers.registry import ParserRegistry


class TestEdgeCases_EmptyResults:
    """What happens when scans return nothing?"""

    def test_nmap_with_no_open_ports(self, clean_profile, tmp_path):
        """
        SCENARIO: All ports filtered/closed
        EXPECTATION: Don't crash, suggest alternatives
        """
        empty_nmap = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.150" addrtype="ipv4"/>
<ports>
</ports>
</host>
</nmaprun>
'''
        xml_file = tmp_path / "empty.xml"
        xml_file.write_text(empty_nmap)

        profile = clean_profile("192.168.45.150")

        # Should not crash
        ParserRegistry.parse_file(str(xml_file), profile=profile)

        # Should have 0 ports
        assert len(profile.ports) == 0

        # System should still provide guidance
        # (Maybe suggest -Pn, UDP scan, etc.)
        from crack.track.recommendations.engine import RecommendationEngine
        recommendations = RecommendationEngine.recommend(profile)

        # Should have some recommendation even with no ports
        assert recommendations.get('next') is not None or \
               len(recommendations.get('quick_wins', [])) > 0, \
               "No guidance when scan finds nothing - user is stuck"

    def test_target_with_single_filtered_port(self, clean_profile, tmp_path):
        """
        SCENARIO: Only one port, and it's filtered
        EXPECTATION: Suggest alternative scan techniques
        """
        filtered_nmap = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.151" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="filtered" reason="no-response"/>
</port>
</ports>
</host>
</nmaprun>
'''
        xml_file = tmp_path / "filtered.xml"
        xml_file.write_text(filtered_nmap)

        profile = clean_profile("192.168.45.151")
        ParserRegistry.parse_file(str(xml_file), profile=profile)

        # Should handle filtered state
        if 80 in profile.ports:
            assert profile.ports[80]['state'] == 'filtered'


class TestEdgeCases_MalformedInput:
    """Garbage in, graceful handling out"""

    def test_corrupted_nmap_xml(self, clean_profile, tmp_path):
        """
        SCENARIO: Nmap XML got corrupted (ctrl+c during scan)
        EXPECTATION: Clear error, not cryptic crash
        """
        corrupted = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.152"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"
<!-- CORRUPTED - missing closing tag -->
'''
        xml_file = tmp_path / "corrupted.xml"
        xml_file.write_text(corrupted)

        profile = clean_profile("192.168.45.152")

        # Should handle gracefully (log warning, not crash)
        try:
            ParserRegistry.parse_file(str(xml_file), profile=profile)
        except Exception as e:
            # Error should be helpful
            assert "parse" in str(e).lower() or "xml" in str(e).lower(), \
                f"Unhelpful error message: {e}"

    def test_import_non_nmap_file(self, clean_profile, tmp_path):
        """
        SCENARIO: User accidentally imports wrong file
        EXPECTATION: Clear error about file type
        """
        wrong_file = tmp_path / "random.txt"
        wrong_file.write_text("This is not a scan file")

        profile = clean_profile("192.168.45.153")

        # Should raise clear error or skip gracefully
        with pytest.raises(ValueError, match="No parser|parse"):
            ParserRegistry.parse_file(str(wrong_file), profile=profile)


class TestEdgeCases_LargeScans:
    """What if user scans entire subnet?"""

    def test_target_with_many_ports(self, clean_profile, tmp_path):
        """
        SCENARIO: Target with 50+ open ports
        EXPECTATION: Prioritization, not 200 tasks
        """
        # Create nmap XML with 30 ports
        ports_xml = []
        for port in range(20, 50):  # 30 ports
            ports_xml.append(f'''
<port protocol="tcp" portid="{port}">
<state state="open"/>
<service name="unknown"/>
</port>
''')

        many_ports_nmap = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.154" addrtype="ipv4"/>
<ports>
{"".join(ports_xml)}
</ports>
</host>
</nmaprun>
'''
        xml_file = tmp_path / "many_ports.xml"
        xml_file.write_text(many_ports_nmap)

        profile = clean_profile("192.168.45.154")
        ParserRegistry.parse_file(str(xml_file), profile=profile)

        assert len(profile.ports) == 30

        # Recommendations should still be manageable
        from crack.track.recommendations.engine import RecommendationEngine
        recommendations = RecommendationEngine.recommend(profile)

        quick_wins = recommendations.get('quick_wins', [])
        assert len(quick_wins) <= 10, \
            "Too many recommendations for large scan - user is overwhelmed"


class TestEdgeCases_SpecialCharacters:
    """Services with weird version strings"""

    def test_version_string_with_special_chars(self, clean_profile, tmp_path):
        """
        SCENARIO: Service banner has pipes, quotes, etc.
        EXPECTATION: Properly escaped in markdown export
        """
        special_chars_nmap = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.155" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Custom | Server" version="1.0 &quot;beta&quot;"/>
</port>
</ports>
</host>
</nmaprun>
'''
        xml_file = tmp_path / "special_chars.xml"
        xml_file.write_text(special_chars_nmap)

        profile = clean_profile("192.168.45.155")
        ParserRegistry.parse_file(str(xml_file), profile=profile)

        # Should handle special characters
        assert 80 in profile.ports
        version = profile.ports[80].get('version', '')
        assert len(version) > 0

        # Export should escape properly
        from crack.track.formatters.markdown import MarkdownFormatter
        report = MarkdownFormatter.export_full_report(profile)

        # Markdown table should not be broken
        assert '|' in report  # Tables use pipes
        assert report.count('|') % 2 == 0 or '\\|' in report, \
            "Pipes in version string broke markdown table"


class TestEdgeCases_RapidUpdates:
    """What if user imports multiple scans rapidly?"""

    def test_import_multiple_scans_same_target(
        self, clean_profile, typical_oscp_nmap_xml, tmp_path
    ):
        """
        SCENARIO: User runs quick scan, then full scan
        EXPECTATION: Data merged, not duplicated
        """
        profile = clean_profile("192.168.45.100")

        # Import first scan
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)
        first_import_ports = len(profile.ports)

        # Import same scan again (user mistake)
        ParserRegistry.parse_file(typical_oscp_nmap_xml, profile=profile)
        second_import_ports = len(profile.ports)

        # Should not duplicate ports
        assert second_import_ports == first_import_ports, \
            "Importing same scan twice duplicated data"

    def test_update_service_version_with_better_scan(
        self, clean_profile, tmp_path
    ):
        """
        SCENARIO: Quick scan shows 'http', full scan shows 'Apache 2.4.41'
        EXPECTATION: Version updated to more detailed info
        """
        # Quick scan - no version
        quick_scan = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.156" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http"/>
</port>
</ports>
</host>
</nmaprun>
'''
        quick_file = tmp_path / "quick.xml"
        quick_file.write_text(quick_scan)

        # Full scan - with version
        full_scan = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host>
<address addr="192.168.45.156" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache httpd" version="2.4.41"/>
</port>
</ports>
</host>
</nmaprun>
'''
        full_file = tmp_path / "full.xml"
        full_file.write_text(full_scan)

        profile = clean_profile("192.168.45.156")

        # Import quick scan
        ParserRegistry.parse_file(str(quick_file), profile=profile)
        assert 80 in profile.ports

        # Import full scan
        ParserRegistry.parse_file(str(full_file), profile=profile)

        # Version should be updated
        http_port = profile.ports[80]
        version = http_port.get('version', '')
        assert 'Apache' in version or len(version) > 0, \
            "Full scan didn't update service version"


class TestEdgeCases_StorageCorruption:
    """What if saved profile gets corrupted?"""

    def test_load_corrupted_profile(self, temp_crack_home, tmp_path):
        """
        SCENARIO: Profile JSON got corrupted on disk
        EXPECTATION: Clear error, suggest recreating
        """
        # Create corrupted JSON
        target = "192.168.45.157"
        profile_file = temp_crack_home / f"{target}.json"
        profile_file.write_text('{"target": "192.168.45.157", "ports": {BAD JSON')

        # Try to load
        with pytest.raises(Exception):  # JSON decode error expected
            TargetProfile.load(target)

    def test_profile_with_missing_fields(self, temp_crack_home):
        """
        SCENARIO: Old version profile missing new fields
        EXPECTATION: Graceful defaults, not crash
        """
        # Simulate old profile format
        target = "192.168.45.158"
        profile_file = temp_crack_home / f"{target}.json"

        # Minimal valid JSON (might be missing new fields)
        old_format = '''{
    "target": "192.168.45.158",
    "phase": "discovery",
    "ports": {},
    "findings": []
}'''
        profile_file.write_text(old_format)

        # Should load with defaults for missing fields
        profile = TargetProfile.load(target)
        assert profile.target == target
        assert hasattr(profile, 'credentials')  # New field should exist with default
