"""
Tests for cheatsheet system
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from crack.reference.core.cheatsheet_registry import (
    CheatsheetRegistry,
    Cheatsheet,
    CheatsheetScenario,
    CheatsheetSection,
    EducationalHeader
)
from crack.reference.core import HybridCommandRegistry, ReferenceTheme, ConfigManager
from crack.reference.cli.cheatsheet import CheatsheetCLI


class TestCheatsheetDataModels:
    """Test cheatsheet data classes"""

    def test_educational_header_creation(self):
        """Test EducationalHeader creation"""
        header = EducationalHeader(
            how_to_recognize=["Pattern 1", "Pattern 2"],
            when_to_look_for=["Situation 1", "Situation 2"]
        )

        assert len(header.how_to_recognize) == 2
        assert len(header.when_to_look_for) == 2
        assert "Pattern 1" in header.how_to_recognize
        assert "Situation 1" in header.when_to_look_for

    def test_cheatsheet_scenario_creation(self):
        """Test CheatsheetScenario creation"""
        scenario = CheatsheetScenario(
            title="Test Scenario",
            context="Test context",
            approach="Test approach",
            commands=["cmd-1", "cmd-2"],
            expected_outcome="Success",
            why_this_works="Technical explanation"
        )

        assert scenario.title == "Test Scenario"
        assert len(scenario.commands) == 2
        assert "cmd-1" in scenario.commands

    def test_cheatsheet_section_creation(self):
        """Test CheatsheetSection creation"""
        section = CheatsheetSection(
            title="Phase 1",
            notes="Test notes",
            commands=["cmd-1", "cmd-2", "cmd-3"]
        )

        assert section.title == "Phase 1"
        assert len(section.commands) == 3

    def test_cheatsheet_from_dict(self):
        """Test Cheatsheet creation from dictionary"""
        data = {
            "id": "test-sheet",
            "name": "Test Sheet",
            "description": "Test description",
            "educational_header": {
                "how_to_recognize": ["Pattern 1"],
                "when_to_look_for": ["Situation 1"]
            },
            "scenarios": [{
                "title": "Scenario 1",
                "context": "Context",
                "approach": "Approach",
                "commands": ["cmd-1"],
                "expected_outcome": "Outcome",
                "why_this_works": "Explanation"
            }],
            "sections": [{
                "title": "Phase 1",
                "notes": "Notes",
                "commands": ["cmd-1", "cmd-2"]
            }],
            "tags": ["TEST", "OSCP:HIGH"]
        }

        sheet = Cheatsheet.from_dict(data)

        assert sheet.id == "test-sheet"
        assert sheet.name == "Test Sheet"
        assert len(sheet.scenarios) == 1
        assert len(sheet.sections) == 1
        assert "TEST" in sheet.tags

    def test_cheatsheet_get_all_command_refs(self):
        """Test extracting all command references from cheatsheet"""
        sheet = Cheatsheet(
            id="test",
            name="Test",
            description="Test",
            educational_header=EducationalHeader(
                how_to_recognize=["Test"],
                when_to_look_for=["Test"]
            ),
            scenarios=[
                CheatsheetScenario(
                    title="S1",
                    context="C",
                    approach="A",
                    commands=["cmd-1", "cmd-2"],
                    expected_outcome="O",
                    why_this_works="W"
                ),
                CheatsheetScenario(
                    title="S2",
                    context="C",
                    approach="A",
                    commands=["cmd-2", "cmd-3"],
                    expected_outcome="O",
                    why_this_works="W"
                )
            ],
            sections=[
                CheatsheetSection(
                    title="P1",
                    notes="N",
                    commands=["cmd-4", "cmd-5"]
                )
            ],
            tags=[]
        )

        refs = sheet.get_all_command_refs()

        # Should be unique and sorted
        assert refs == ["cmd-1", "cmd-2", "cmd-3", "cmd-4", "cmd-5"]


class TestCheatsheetRegistry:
    """Test CheatsheetRegistry functionality"""

    @pytest.fixture
    def temp_cheatsheets_dir(self, tmp_path):
        """Create temporary cheatsheets directory with test data"""
        cheatsheets_dir = tmp_path / "reference" / "data" / "cheatsheets"
        cheatsheets_dir.mkdir(parents=True)

        # Create test cheatsheet
        test_sheet = {
            "id": "test-cheatsheet",
            "name": "Test Cheatsheet",
            "description": "For testing",
            "educational_header": {
                "how_to_recognize": ["Pattern 1", "Pattern 2"],
                "when_to_look_for": ["Situation 1", "Situation 2"]
            },
            "scenarios": [{
                "title": "Test Scenario",
                "context": "Test context",
                "approach": "Test approach",
                "commands": ["cmd-1"],
                "expected_outcome": "Success",
                "why_this_works": "Works because"
            }] * 3,  # 3 scenarios
            "sections": [{
                "title": "Phase 1",
                "notes": "Notes",
                "commands": ["cmd-1", "cmd-2"]
            }],
            "tags": ["TEST", "OSCP:HIGH"]
        }

        with open(cheatsheets_dir / "test-cheatsheet.json", "w") as f:
            json.dump(test_sheet, f)

        return tmp_path / "reference"

    def test_registry_initialization(self, temp_cheatsheets_dir):
        """Test registry initializes and loads cheatsheets"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))

        assert len(registry.cheatsheets) >= 1
        assert "test-cheatsheet" in registry.cheatsheets

    def test_get_cheatsheet(self, temp_cheatsheets_dir):
        """Test retrieving cheatsheet by ID"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))
        sheet = registry.get_cheatsheet("test-cheatsheet")

        assert sheet is not None
        assert sheet.id == "test-cheatsheet"
        assert sheet.name == "Test Cheatsheet"

    def test_get_nonexistent_cheatsheet(self, temp_cheatsheets_dir):
        """Test retrieving non-existent cheatsheet returns None"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))
        sheet = registry.get_cheatsheet("nonexistent")

        assert sheet is None

    def test_list_cheatsheets(self, temp_cheatsheets_dir):
        """Test listing all cheatsheets"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))
        sheets = registry.list_cheatsheets()

        assert len(sheets) >= 1
        assert any(s.id == "test-cheatsheet" for s in sheets)

    def test_search_cheatsheets(self, temp_cheatsheets_dir):
        """Test searching cheatsheets"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))

        # Search by name
        results = registry.search_cheatsheets("Test")
        assert len(results) >= 1

        # Search by tag
        results = registry.search_cheatsheets("OSCP")
        assert len(results) >= 1

        # Search with no results
        results = registry.search_cheatsheets("ZZZZZ")
        assert len(results) == 0

    def test_filter_by_tags(self, temp_cheatsheets_dir):
        """Test filtering cheatsheets by tags"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))

        results = registry.filter_by_tags(["TEST"])
        assert len(results) >= 1

        results = registry.filter_by_tags(["OSCP:HIGH"])
        assert len(results) >= 1

        results = registry.filter_by_tags(["NONEXISTENT"])
        assert len(results) == 0

    def test_get_stats(self, temp_cheatsheets_dir):
        """Test registry statistics"""
        registry = CheatsheetRegistry(base_path=str(temp_cheatsheets_dir))
        stats = registry.get_stats()

        assert "total_cheatsheets" in stats
        assert "total_scenarios" in stats
        assert "total_sections" in stats
        assert "total_command_references" in stats
        assert "cheatsheet_ids" in stats

        assert stats["total_cheatsheets"] >= 1
        assert stats["total_scenarios"] >= 3  # 3 scenarios in test data
        assert "test-cheatsheet" in stats["cheatsheet_ids"]


class TestCheatsheetCLI:
    """Test CheatsheetCLI functionality"""

    @pytest.fixture
    def mock_registries(self):
        """Create mock registries for testing"""
        theme = ReferenceTheme()
        command_registry = Mock()
        cheatsheet_registry = Mock()

        # Mock cheatsheet
        mock_sheet = Cheatsheet(
            id="test-sheet",
            name="Test Sheet",
            description="Test description",
            educational_header=EducationalHeader(
                how_to_recognize=["Pattern 1", "Pattern 2"],
                when_to_look_for=["Situation 1", "Situation 2"]
            ),
            scenarios=[
                CheatsheetScenario(
                    title="Scenario 1: Test",
                    context="Test context",
                    approach="Test approach",
                    commands=["cmd-1"],
                    expected_outcome="Success",
                    why_this_works="Works because"
                )
            ],
            sections=[
                CheatsheetSection(
                    title="Phase 1: Testing",
                    notes="Test notes",
                    commands=["cmd-1", "cmd-2"]
                )
            ],
            tags=["TEST"]
        )

        cheatsheet_registry.get_cheatsheet.return_value = mock_sheet
        cheatsheet_registry.list_cheatsheets.return_value = [mock_sheet]

        # Mock command
        mock_command = Mock()
        mock_command.id = "cmd-1"
        mock_command.name = "Test Command"
        mock_command.command = "test <ARG>"
        mock_command.description = "Test description"
        mock_command.success_indicators = ["Success"]
        mock_command.failure_indicators = ["Failure"]

        command_registry.get_command.return_value = mock_command

        return {
            "theme": theme,
            "command_registry": command_registry,
            "cheatsheet_registry": cheatsheet_registry
        }

    def test_cli_initialization(self, mock_registries):
        """Test CheatsheetCLI initialization"""
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        assert cli.cheatsheet_registry is not None
        assert cli.command_registry is not None
        assert cli.theme is not None

    def test_list_cheatsheets(self, mock_registries, capsys):
        """Test listing cheatsheets"""
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        cli.list_cheatsheets()
        captured = capsys.readouterr()

        assert "Available Cheatsheets" in captured.out
        assert "test-sheet" in captured.out
        assert "Test Sheet" in captured.out

    def test_show_cheatsheet(self, mock_registries, capsys):
        """Test showing cheatsheet details"""
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        cli.show_cheatsheet("test-sheet")
        captured = capsys.readouterr()

        assert "Test Sheet" in captured.out
        assert "HOW TO RECOGNIZE" in captured.out
        assert "WHEN TO LOOK FOR" in captured.out
        assert "REAL-WORLD SCENARIOS" in captured.out
        assert "Pattern 1" in captured.out
        assert "Situation 1" in captured.out

    def test_show_nonexistent_cheatsheet(self, mock_registries, capsys):
        """Test showing non-existent cheatsheet"""
        mock_registries["cheatsheet_registry"].get_cheatsheet.return_value = None

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        cli.show_cheatsheet("nonexistent")
        captured = capsys.readouterr()

        assert "Cheatsheet not found" in captured.out

    def test_collect_all_commands(self, mock_registries):
        """Test collecting all commands from cheatsheet"""
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        sheet = mock_registries["cheatsheet_registry"].get_cheatsheet("test-sheet")
        commands = cli._collect_all_commands(sheet)

        assert len(commands) == 2
        assert "cmd-1" in commands
        assert "cmd-2" in commands

    def test_wrap_text(self, mock_registries):
        """Test text wrapping utility"""
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_registries["cheatsheet_registry"],
            command_registry=mock_registries["command_registry"],
            theme=mock_registries["theme"]
        )

        text = "This is a long text that needs to be wrapped to fit within a specific width"
        wrapped = cli._wrap_text(text, width=20)

        assert len(wrapped) > 1
        assert all(len(line) <= 20 for line in wrapped)


class TestRealCheatsheets:
    """Test actual cheatsheet JSON files"""

    def test_rfi_lfi_cheatsheet_exists(self):
        """Test RFI/LFI cheatsheet file exists and is valid"""
        cheatsheet_path = Path("reference/data/cheatsheets/rfi-lfi-evaluation.json")
        assert cheatsheet_path.exists(), "RFI/LFI cheatsheet file should exist"

        with open(cheatsheet_path) as f:
            data = json.load(f)

        assert data["id"] == "rfi-lfi-evaluation"
        assert "educational_header" in data
        assert "scenarios" in data
        assert "sections" in data
        assert len(data["scenarios"]) >= 3

    def test_quick_wins_cheatsheet_exists(self):
        """Test Quick Wins cheatsheet file exists and is valid"""
        cheatsheet_path = Path("reference/data/cheatsheets/quick-wins.json")
        assert cheatsheet_path.exists(), "Quick Wins cheatsheet file should exist"

        with open(cheatsheet_path) as f:
            data = json.load(f)

        assert data["id"] == "quick-wins"
        assert "educational_header" in data
        assert "scenarios" in data
        assert "sections" in data
        assert len(data["scenarios"]) >= 3

    def test_cheatsheet_schema_compliance(self):
        """Test that cheatsheets comply with schema"""
        cheatsheet_dir = Path("reference/data/cheatsheets")
        if not cheatsheet_dir.exists():
            pytest.skip("Cheatsheets directory not found")

        for cheatsheet_file in cheatsheet_dir.glob("*.json"):
            with open(cheatsheet_file) as f:
                data = json.load(f)

            # Required top-level fields
            assert "id" in data
            assert "name" in data
            assert "description" in data
            assert "educational_header" in data
            assert "scenarios" in data
            assert "sections" in data

            # Educational header
            header = data["educational_header"]
            assert "how_to_recognize" in header
            assert "when_to_look_for" in header
            assert len(header["how_to_recognize"]) >= 2
            assert len(header["when_to_look_for"]) >= 2

            # Scenarios
            assert len(data["scenarios"]) >= 3
            for scenario in data["scenarios"]:
                assert "title" in scenario
                assert "context" in scenario
                assert "approach" in scenario
                assert "commands" in scenario
                assert "expected_outcome" in scenario
                assert "why_this_works" in scenario

            # Sections
            assert len(data["sections"]) >= 1
            for section in data["sections"]:
                assert "title" in section
                assert "notes" in section
                assert "commands" in section
                assert len(section["commands"]) >= 1
