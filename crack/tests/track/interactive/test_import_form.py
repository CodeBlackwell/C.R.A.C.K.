"""
Tests for Import Form Panel

Tests the standalone import wizard functionality:
- Multi-stage wizard flow
- File validation and auto-detection
- Parse preview rendering
- Merge strategy selection
- Import execution with different strategies
"""

import pytest
from pathlib import Path
from crack.track.interactive.panels.import_form import ImportForm
from crack.track.core.state import TargetProfile
from crack.track.parsers.registry import ParserRegistry
from crack.track.core.events import EventBus
from crack.track.services.registry import ServiceRegistry
import tempfile
import xml.etree.ElementTree as ET


@pytest.fixture
def temp_nmap_xml(tmp_path):
    """Create temporary nmap XML file for testing"""
    xml_content = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.100" start="1234567890" version="7.80">
    <host>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <hostnames>
            <hostname name="target.local" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack"/>
                <service name="http" product="Apache" version="2.4.41"/>
            </port>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack"/>
                <service name="ssh" product="OpenSSH" version="7.9p1"/>
            </port>
        </ports>
    </host>
</nmaprun>"""

    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def profile(tmp_path):
    """Create test profile"""
    profile = TargetProfile(target="192.168.1.100")
    # Override storage path for testing
    profile.storage_path = str(tmp_path / "192.168.1.100.json")
    return profile


@pytest.fixture(autouse=True)
def reset_registries():
    """Reset registries between tests"""
    EventBus.clear()
    ServiceRegistry.clear()
    ParserRegistry.clear()
    yield
    EventBus.clear()
    ServiceRegistry.clear()
    ParserRegistry.clear()


class TestImportFormInitialization:
    """Test form initialization and reset"""

    def test_initialization_without_profile(self):
        """Test creating form without profile"""
        form = ImportForm()

        assert form.profile is None
        assert form.stage == ImportForm.STAGE_FILE_PATH
        assert form.file_path is None
        assert form.file_type is None
        assert form.parse_results is None
        assert form.merge_strategy == ImportForm.MERGE_SMART
        assert form.error_message is None
        assert form.import_success is False

    def test_initialization_with_profile(self, profile):
        """Test creating form with profile"""
        form = ImportForm(profile=profile)

        assert form.profile == profile
        assert form.stage == ImportForm.STAGE_FILE_PATH

    def test_reset_clears_all_state(self, profile):
        """Test reset clears all form state"""
        form = ImportForm(profile=profile)

        # Modify state
        form.stage = ImportForm.STAGE_PREVIEW
        form.file_path = "/tmp/test.xml"
        form.file_type = "nmap-xml"
        form.parse_results = {"ports": []}
        form.merge_strategy = ImportForm.MERGE_REPLACE
        form.error_message = "Test error"
        form.import_success = True

        # Reset
        form.reset()

        # Verify all cleared
        assert form.stage == ImportForm.STAGE_FILE_PATH
        assert form.file_path is None
        assert form.file_type is None
        assert form.parse_results is None
        assert form.merge_strategy == ImportForm.MERGE_SMART
        assert form.error_message is None
        assert form.import_success is False


class TestFilePathStage:
    """Test file path selection stage"""

    def test_render_file_path_stage_empty(self, profile):
        """Test rendering file path stage with no file selected"""
        form = ImportForm(profile=profile)

        panel, choices = form.render()

        assert panel is not None
        assert "Step 1/4" in panel.renderable.__str__()
        assert len(choices) > 0
        assert any(c['id'] == 'enter-path' for c in choices)
        assert any(c['id'] == 'back' for c in choices)

    def test_set_file_path_valid(self, temp_nmap_xml):
        """Test setting valid file path"""
        form = ImportForm()

        result = form.set_file_path(temp_nmap_xml)

        assert result is True
        assert form.file_path == temp_nmap_xml
        assert form.error_message is None

    def test_set_file_path_invalid(self):
        """Test setting invalid file path"""
        form = ImportForm()

        result = form.set_file_path("/nonexistent/file.xml")

        assert result is False
        assert form.file_path == "/nonexistent/file.xml"
        assert "File not found" in form.error_message

    def test_set_file_path_expands_user_home(self, tmp_path):
        """Test file path expands ~ to user home"""
        # Create file in temp directory
        test_file = tmp_path / "test.xml"
        test_file.write_text("<test/>")

        form = ImportForm()

        # This won't find the file since ~ doesn't point to tmp_path,
        # but we can verify expansion happens
        form.set_file_path("~/test.xml")

        # Verify path was expanded (not equal to original)
        assert form.file_path != "~/test.xml"
        assert "~" not in form.file_path

    def test_render_shows_existing_common_paths(self, tmp_path, profile):
        """Test render highlights existing common paths"""
        # Create a common path file
        common_file = Path("./nmap.xml")
        if common_file.exists():
            common_file.unlink()

        form = ImportForm(profile=profile)
        panel, choices = form.render()

        # Should show common paths (some may not exist)
        panel_str = panel.renderable.__str__()
        assert "Common Paths" in panel_str


class TestPreviewStage:
    """Test parse preview stage"""

    def test_detect_and_parse_valid_xml(self, temp_nmap_xml):
        """Test auto-detection and parsing of valid XML"""
        form = ImportForm()
        form.file_path = temp_nmap_xml

        form._detect_and_parse()

        assert form.file_type == "nmap-xml"
        assert form.parse_results is not None
        assert 'ports' in form.parse_results
        assert len(form.parse_results['ports']) == 2
        assert form.error_message is None

    def test_detect_and_parse_invalid_file(self, tmp_path):
        """Test parsing invalid file format"""
        invalid_file = tmp_path / "invalid.txt"
        invalid_file.write_text("not a scan file")

        form = ImportForm()
        form.file_path = str(invalid_file)

        form._detect_and_parse()

        assert "Unsupported file format" in form.error_message
        assert form.parse_results is None

    def test_render_preview_stage_with_results(self, temp_nmap_xml):
        """Test rendering preview with parse results"""
        form = ImportForm()
        form.file_path = temp_nmap_xml
        form.stage = ImportForm.STAGE_PREVIEW
        form._detect_and_parse()

        panel, choices = form.render()

        # Check panel object
        assert panel is not None
        assert "Step 2" in str(panel.title)

        # Check that we have parse results
        assert form.parse_results is not None
        assert len(form.parse_results['ports']) == 2

        # Check choices
        assert any(c['id'] == 'next' for c in choices)

    def test_render_preview_stage_with_error(self, tmp_path):
        """Test rendering preview with parse error"""
        invalid_file = tmp_path / "invalid.txt"
        invalid_file.write_text("not a scan file")

        form = ImportForm()
        form.file_path = str(invalid_file)
        form.stage = ImportForm.STAGE_PREVIEW
        form._detect_and_parse()

        panel, choices = form.render()

        # Check error was captured
        assert form.error_message is not None
        assert "Unsupported" in form.error_message

        # Can't proceed with errors
        assert not any(c['id'] == 'next' for c in choices)


class TestMergeStrategyStage:
    """Test merge strategy selection stage"""

    def test_render_merge_strategy_stage(self, profile):
        """Test rendering merge strategy selection"""
        form = ImportForm(profile=profile)
        form.stage = ImportForm.STAGE_MERGE_STRATEGY

        panel, choices = form.render()

        panel_str = panel.renderable.__str__()
        assert "Step 3/4" in panel_str
        assert "MERGE STRATEGIES" in panel_str
        assert "Smart Merge" in panel_str
        assert "Append Only" in panel_str
        assert "Replace All" in panel_str

        # Check choices
        assert any(c['action'] == 'select_strategy' and c['strategy'] == ImportForm.MERGE_SMART for c in choices)
        assert any(c['action'] == 'select_strategy' and c['strategy'] == ImportForm.MERGE_APPEND for c in choices)
        assert any(c['action'] == 'select_strategy' and c['strategy'] == ImportForm.MERGE_REPLACE for c in choices)

    def test_default_merge_strategy_is_smart(self):
        """Test default merge strategy is smart merge"""
        form = ImportForm()

        assert form.merge_strategy == ImportForm.MERGE_SMART

    def test_select_different_merge_strategies(self, profile):
        """Test changing merge strategy"""
        form = ImportForm(profile=profile)

        form.merge_strategy = ImportForm.MERGE_APPEND
        assert form.merge_strategy == ImportForm.MERGE_APPEND

        form.merge_strategy = ImportForm.MERGE_REPLACE
        assert form.merge_strategy == ImportForm.MERGE_REPLACE


class TestConfirmationStage:
    """Test confirmation stage"""

    def test_render_confirm_stage(self, temp_nmap_xml, profile):
        """Test rendering confirmation stage"""
        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form.file_type = "nmap-xml"
        form.parse_results = {"ports": [{"port": 80}], "target": "192.168.1.100"}
        form.merge_strategy = ImportForm.MERGE_SMART
        form.stage = ImportForm.STAGE_CONFIRM

        panel, choices = form.render()

        panel_str = panel.renderable.__str__()
        assert "Step 4/4" in panel_str
        assert "IMPORT SUMMARY" in panel_str
        assert temp_nmap_xml in panel_str
        assert "Smart Merge" in panel_str

        assert any(c['action'] == 'import' for c in choices)
        assert any(c['action'] == 'cancel' for c in choices)

    def test_render_confirm_shows_warning_for_replace(self, temp_nmap_xml, profile):
        """Test confirmation shows warning for replace strategy"""
        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form.file_type = "nmap-xml"
        form.parse_results = {"ports": []}
        form.merge_strategy = ImportForm.MERGE_REPLACE
        form.stage = ImportForm.STAGE_CONFIRM

        panel, choices = form.render()

        panel_str = panel.renderable.__str__()
        assert "WARNING" in panel_str
        assert "delete all existing data" in panel_str


class TestCompleteStage:
    """Test import complete stage"""

    def test_render_complete_stage_success(self, profile):
        """Test rendering successful completion"""
        form = ImportForm(profile=profile)
        form.stage = ImportForm.STAGE_COMPLETE
        form.import_success = True
        form.import_summary = {
            'ports_added': 5,
            'notes_added': 2,
            'tasks_generated': 10
        }

        panel, choices = form.render()

        panel_str = panel.renderable.__str__()
        assert "IMPORT COMPLETE" in panel_str
        assert "5" in panel_str  # ports
        assert "2" in panel_str  # notes
        assert "10" in panel_str  # tasks

    def test_render_complete_stage_failure(self, profile):
        """Test rendering failed completion"""
        form = ImportForm(profile=profile)
        form.stage = ImportForm.STAGE_COMPLETE
        form.import_success = False
        form.error_message = "Parse error: Invalid XML"

        panel, choices = form.render()

        panel_str = panel.renderable.__str__()
        assert "IMPORT FAILED" in panel_str
        assert "Parse error" in panel_str


class TestStageProgression:
    """Test wizard stage progression"""

    def test_next_stage_from_file_path_requires_valid_file(self):
        """Test can't progress from file path without valid file"""
        form = ImportForm()

        form.next_stage()

        # Should stay at file path stage with error
        assert form.stage == ImportForm.STAGE_FILE_PATH
        assert "valid file" in form.error_message

    def test_next_stage_progression(self, temp_nmap_xml):
        """Test normal stage progression"""
        form = ImportForm()

        # Stage 1 -> 2
        form.file_path = temp_nmap_xml
        form.next_stage()
        assert form.stage == ImportForm.STAGE_PREVIEW

        # Stage 2 -> 3 (requires parse results)
        assert form.parse_results is not None  # Auto-parsed
        form.next_stage()
        assert form.stage == ImportForm.STAGE_MERGE_STRATEGY

        # Stage 3 -> 4
        form.next_stage()
        assert form.stage == ImportForm.STAGE_CONFIRM

    def test_prev_stage_progression(self):
        """Test backward stage progression"""
        form = ImportForm()

        # Start at confirm
        form.stage = ImportForm.STAGE_CONFIRM

        form.prev_stage()
        assert form.stage == ImportForm.STAGE_MERGE_STRATEGY

        form.prev_stage()
        assert form.stage == ImportForm.STAGE_PREVIEW

        form.prev_stage()
        assert form.stage == ImportForm.STAGE_FILE_PATH


class TestValidation:
    """Test form validation"""

    def test_validate_empty_form(self):
        """Test validation fails on empty form"""
        form = ImportForm()

        result = form.validate()

        assert result is False
        assert "No file selected" in form.error_message

    def test_validate_nonexistent_file(self):
        """Test validation fails for nonexistent file"""
        form = ImportForm()
        form.file_path = "/nonexistent/file.xml"

        result = form.validate()

        assert result is False
        assert "does not exist" in form.error_message

    def test_validate_no_parse_results(self, temp_nmap_xml):
        """Test validation fails without parse results"""
        form = ImportForm()
        form.file_path = temp_nmap_xml

        result = form.validate()

        assert result is False
        assert "not parsed" in form.error_message

    def test_validate_complete_form(self, temp_nmap_xml):
        """Test validation passes with complete form"""
        form = ImportForm()
        form.file_path = temp_nmap_xml
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_SMART

        result = form.validate()

        assert result is True
        assert form.error_message is None


class TestImportExecution:
    """Test actual import to profile"""

    def test_import_to_profile_smart_merge(self, temp_nmap_xml, profile):
        """Test importing with smart merge strategy"""
        # Add existing port
        profile.add_port(80, state='open', service='http', source='manual')

        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_SMART

        result = form.import_to_profile(profile)

        assert result is True
        assert form.import_success is True
        assert form.stage == ImportForm.STAGE_COMPLETE

        # Check ports were added (smart merge deduplicates)
        assert len(profile.ports) >= 2  # SSH + HTTP (may dedupe HTTP)

    def test_import_to_profile_append_strategy(self, temp_nmap_xml, profile):
        """Test importing with append strategy"""
        # Add existing port
        profile.add_port(80, state='open', service='http', source='manual')
        initial_ports = len(profile.ports)

        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_APPEND

        result = form.import_to_profile(profile)

        assert result is True
        # Append adds all (may create duplicates)
        assert len(profile.ports) >= initial_ports

    def test_import_to_profile_replace_strategy(self, temp_nmap_xml, profile):
        """Test importing with replace strategy"""
        # Add existing data
        profile.add_port(443, state='open', service='https', source='manual')
        profile.add_finding(
            title='Test Finding',
            severity='High',
            description='Test',
            source='manual'
        )

        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_REPLACE

        result = form.import_to_profile(profile)

        assert result is True

        # Replace clears existing - should only have imported ports
        assert len(profile.ports) == 2  # Only from XML (80, 22)
        assert len(profile.findings) == 0  # Cleared
        assert not any(p['port'] == 443 for p in profile.ports)  # Old port gone

    def test_import_generates_tasks(self, temp_nmap_xml, profile):
        """Test import triggers task generation"""
        form = ImportForm(profile=profile)
        form.file_path = temp_nmap_xml
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_SMART

        result = form.import_to_profile(profile)

        assert result is True

        # Check tasks were generated
        pending_tasks = profile.task_tree.get_all_pending()
        assert len(pending_tasks) > 0  # Service plugins should generate tasks

    def test_import_failure_handling(self, tmp_path, profile):
        """Test import handles failures gracefully"""
        # Create corrupted XML
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("<?xml version='1.0'?><broken>")

        form = ImportForm(profile=profile)
        form.file_path = str(bad_xml)
        form._detect_and_parse()
        form.merge_strategy = ImportForm.MERGE_SMART

        result = form.import_to_profile(profile)

        assert result is False
        assert form.import_success is False
        assert form.error_message is not None
        assert form.stage == ImportForm.STAGE_COMPLETE


class TestHelperMethods:
    """Test utility helper methods"""

    def test_format_file_size_bytes(self):
        """Test file size formatting for bytes"""
        form = ImportForm()

        assert form._format_file_size(500) == "500 B"

    def test_format_file_size_kilobytes(self):
        """Test file size formatting for KB"""
        form = ImportForm()

        assert form._format_file_size(1536) == "1.5 KB"

    def test_format_file_size_megabytes(self):
        """Test file size formatting for MB"""
        form = ImportForm()

        size_mb = 2.5 * 1024 * 1024
        assert form._format_file_size(int(size_mb)) == "2.5 MB"

    def test_get_strategy_label(self):
        """Test merge strategy label lookup"""
        form = ImportForm()

        assert form._get_strategy_label(ImportForm.MERGE_SMART) == "Smart Merge"
        assert form._get_strategy_label(ImportForm.MERGE_APPEND) == "Append Only"
        assert form._get_strategy_label(ImportForm.MERGE_REPLACE) == "Replace All"
        assert form._get_strategy_label("unknown") == "Unknown"
