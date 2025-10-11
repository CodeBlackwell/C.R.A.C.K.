"""
Tests for dev fixture storage system

Validates:
- Fixture save/load operations
- Fixture metadata management
- Fixture listing and details
- Immutability (fixtures unchanged after load)
- Error handling (missing fixtures, invalid data)
"""

import pytest
import json
from pathlib import Path
from unittest.mock import patch

from crack.track.core.fixtures import FixtureStorage
from crack.track.core.state import TargetProfile


class TestFixtureStorage:
    """Test fixture storage operations"""

    def test_save_fixture(self, temp_crack_home, clean_profile):
        """Save profile as fixture"""
        # Create profile with data
        profile = clean_profile()
        profile.add_port(80, service="http", version="Apache 2.4.41", source="nmap")
        profile.add_finding("directory", "/admin", source="gobuster")
        profile.save()

        # Save as fixture
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            fixture_path = FixtureStorage.save_fixture("192.168.45.100", "test-fixture", "Test description")

            # Verify fixture file exists
            assert fixture_path.exists()

            # Verify fixture metadata
            with open(fixture_path, 'r') as f:
                data = json.load(f)

            assert '_fixture_metadata' in data
            metadata = data['_fixture_metadata']
            assert metadata['name'] == "test-fixture"
            assert metadata['description'] == "Test description"
            assert metadata['source_target'] == "192.168.45.100"
            assert metadata['port_count'] == 1
            assert metadata['finding_count'] == 1

    def test_load_fixture(self, temp_crack_home, clean_profile):
        """Load fixture to target profile"""
        # Create and save fixture
        profile = clean_profile()
        profile.add_port(80, service="http", version="Apache 2.4.41", source="nmap")
        profile.add_finding("vulnerability", "SQLi in id parameter", source="sqlmap")
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "sql-vuln", "SQLi fixture")

            # Load fixture to different target
            FixtureStorage.load_fixture("sql-vuln", "192.168.45.200")

            # Verify target profile was created
            loaded_profile = TargetProfile.load("192.168.45.200")
            assert loaded_profile is not None
            assert loaded_profile.target == "192.168.45.200"
            assert len(loaded_profile.ports) == 1
            assert 80 in loaded_profile.ports
            assert len(loaded_profile.findings) == 1

    def test_load_fixture_updates_timestamps(self, temp_crack_home, clean_profile):
        """Loading fixture updates 'updated' timestamp"""
        import time

        # Create and save fixture
        profile = clean_profile()
        profile.save()
        original_updated = profile.updated

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "time-test", "Timestamp test")

            # Wait a moment
            time.sleep(0.1)

            # Load fixture
            FixtureStorage.load_fixture("time-test", "192.168.45.100")

            # Verify timestamp updated
            loaded_profile = TargetProfile.load("192.168.45.100")
            assert loaded_profile.updated != original_updated

    def test_list_fixtures(self, temp_crack_home, clean_profile):
        """List all available fixtures"""
        # Create multiple fixtures
        for i in range(3):
            profile = clean_profile(f"192.168.45.{100+i}")
            profile.add_port(80 + i, service=f"service{i}", source="nmap")
            profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture(f"192.168.45.{100}", "fixture1", "Fixture 1")
            FixtureStorage.save_fixture(f"192.168.45.{101}", "fixture2", "Fixture 2")
            FixtureStorage.save_fixture(f"192.168.45.{102}", "fixture3", "Fixture 3")

            # List fixtures
            fixtures = FixtureStorage.list_fixtures()

            # Verify count and metadata
            assert len(fixtures) == 3
            assert fixtures[0]['name'] == 'fixture1'
            assert fixtures[1]['name'] == 'fixture2'
            assert fixtures[2]['name'] == 'fixture3'

            # Verify metadata fields
            for fixture in fixtures:
                assert 'name' in fixture
                assert 'description' in fixture
                assert 'phase' in fixture
                assert 'ports' in fixture
                assert 'findings' in fixture
                assert 'tasks' in fixture

    def test_list_fixtures_empty(self, temp_crack_home):
        """List fixtures when none exist"""
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            fixtures = FixtureStorage.list_fixtures()
            assert fixtures == []

    def test_get_fixture_details(self, temp_crack_home, clean_profile):
        """Get detailed fixture info"""
        # Create fixture
        profile = clean_profile()
        profile.add_port(80, service="http", version="Apache 2.4.41", source="nmap")
        profile.add_port(443, service="https", version="nginx 1.18.0", source="nmap")
        profile.add_finding("directory", "/admin", source="gobuster")
        profile.add_credential("admin", "password123", service="http", port=80, source="config.php")
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "detailed-test", "Detailed fixture")

            # Get details
            details = FixtureStorage.get_fixture_details("detailed-test")

            # Verify structure
            assert 'name' in details
            assert 'metadata' in details
            assert 'profile' in details

            # Verify profile summary
            profile_info = details['profile']
            assert profile_info['phase'] == 'discovery'
            assert '80 (http)' in profile_info['port_summary']
            assert '443 (https)' in profile_info['port_summary']
            assert profile_info['credential_count'] == 1

    def test_delete_fixture(self, temp_crack_home, clean_profile):
        """Delete fixture"""
        # Create fixture
        profile = clean_profile()
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "delete-me", "To be deleted")

            # Verify exists
            assert FixtureStorage.exists("delete-me")

            # Delete
            FixtureStorage.delete_fixture("delete-me")

            # Verify deleted
            assert not FixtureStorage.exists("delete-me")

    def test_exists(self, temp_crack_home, clean_profile):
        """Check fixture existence"""
        profile = clean_profile()
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            # Non-existent fixture
            assert not FixtureStorage.exists("nonexistent")

            # Create fixture
            FixtureStorage.save_fixture("192.168.45.100", "exists-test", "Existence test")

            # Verify exists
            assert FixtureStorage.exists("exists-test")

    def test_save_fixture_missing_profile(self, temp_crack_home):
        """Save fixture from non-existent profile fails"""
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            with pytest.raises(ValueError, match="does not exist"):
                FixtureStorage.save_fixture("192.168.45.999", "nonexistent", "Should fail")

    def test_load_fixture_missing(self, temp_crack_home):
        """Load non-existent fixture fails"""
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            with pytest.raises(ValueError, match="not found"):
                FixtureStorage.load_fixture("nonexistent", "192.168.45.100")

    def test_get_fixture_details_missing(self, temp_crack_home):
        """Get details of non-existent fixture fails"""
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            with pytest.raises(ValueError, match="not found"):
                FixtureStorage.get_fixture_details("nonexistent")

    def test_delete_fixture_missing(self, temp_crack_home):
        """Delete non-existent fixture fails"""
        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            with pytest.raises(ValueError, match="not found"):
                FixtureStorage.delete_fixture("nonexistent")

    def test_fixture_immutability(self, temp_crack_home, clean_profile):
        """Loading fixture doesn't modify original fixture file"""
        # Create fixture
        profile = clean_profile()
        profile.add_port(80, service="http", source="nmap")
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "immutable-test", "Immutability test")

            # Read original fixture
            fixture_path = FixtureStorage.get_fixture_path("immutable-test")
            with open(fixture_path, 'r') as f:
                original_data = json.load(f)

            # Load fixture
            FixtureStorage.load_fixture("immutable-test", "192.168.45.200")

            # Modify loaded profile
            loaded_profile = TargetProfile.load("192.168.45.200")
            loaded_profile.add_port(443, service="https", source="manual")
            loaded_profile.save()

            # Read fixture again
            with open(fixture_path, 'r') as f:
                current_data = json.load(f)

            # Verify fixture unchanged
            assert original_data == current_data

    def test_count_tasks_recursive(self, temp_crack_home):
        """Task counter handles nested task trees"""
        task_tree = {
            "id": "root",
            "name": "Root",
            "children": [
                {
                    "id": "child1",
                    "name": "Child 1",
                    "children": [
                        {"id": "grandchild1", "name": "Grandchild 1", "children": []},
                        {"id": "grandchild2", "name": "Grandchild 2", "children": []}
                    ]
                },
                {
                    "id": "child2",
                    "name": "Child 2",
                    "children": []
                }
            ]
        }

        count = FixtureStorage._count_tasks(task_tree)
        assert count == 5  # root + child1 + child2 + grandchild1 + grandchild2

    def test_sanitize_fixture_name(self, temp_crack_home, clean_profile):
        """Fixture names are sanitized for filesystem"""
        profile = clean_profile()
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            # Save with problematic name
            FixtureStorage.save_fixture("192.168.45.100", "test/fixture:name", "Sanitized name")

            # Verify sanitized filename
            fixture_path = FixtureStorage.get_fixture_path("test/fixture:name")
            assert fixture_path.name == "test_fixture_name.json"

    def test_fixture_metadata_fallback(self, temp_crack_home, clean_profile):
        """List fixtures handles missing metadata gracefully"""
        # Create fixture
        profile = clean_profile()
        profile.add_port(80, service="http", source="nmap")
        profile.save()

        with patch.object(FixtureStorage, 'FIXTURES_DIR', temp_crack_home.parent / 'fixtures'):
            FixtureStorage.save_fixture("192.168.45.100", "meta-test", "Metadata test")

            # Manually remove metadata
            fixture_path = FixtureStorage.get_fixture_path("meta-test")
            with open(fixture_path, 'r') as f:
                data = json.load(f)

            data.pop('_fixture_metadata', None)

            with open(fixture_path, 'w') as f:
                json.dump(data, f, indent=2)

            # List fixtures (should handle missing metadata)
            fixtures = FixtureStorage.list_fixtures()
            assert len(fixtures) == 1
            assert fixtures[0]['phase'] == 'discovery'  # Falls back to profile data
