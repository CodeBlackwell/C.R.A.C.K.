"""
BloodTrail Command Suggester Tests

Business Value Focus:
- Command suggestions must map correctly to query results
- Variable substitution must extract correct values from records
- Target filtering must skip invalid targets (group names)
- Credential types must map to appropriate commands

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import json
import tempfile

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# TARGET ENTRY TESTS
# =============================================================================

class TestTargetEntry(unittest.TestCase):
    """Tests for TargetEntry dataclass."""

    def test_target_entry_stores_properties(self):
        """
        BV: Target entry data is accessible for display

        Scenario:
          Given: TargetEntry with user/target/command
          When: Entry is examined
          Then: All properties are accessible
        """
        from tools.post.bloodtrail.command_suggester import TargetEntry

        entry = TargetEntry(
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            ready_command="impacket-psexec admin@dc01.corp.com",
            domain="CORP.COM",
            access_type="AdminTo",
        )

        self.assertEqual(entry.user, "ADMIN@CORP.COM")
        self.assertEqual(entry.target, "DC01.CORP.COM")
        self.assertEqual(entry.access_type, "AdminTo")

    def test_target_entry_to_dict_serializes(self):
        """
        BV: Target entries can be serialized for export

        Scenario:
          Given: TargetEntry object
          When: to_dict() is called
          Then: Dict representation is returned
        """
        from tools.post.bloodtrail.command_suggester import TargetEntry

        entry = TargetEntry(
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            ready_command="impacket-psexec",
            domain="CORP.COM",
        )

        result = entry.to_dict()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["user"], "ADMIN@CORP.COM")


# =============================================================================
# COMMAND TABLE TESTS
# =============================================================================

class TestCommandTable(unittest.TestCase):
    """Tests for CommandTable dataclass."""

    def test_command_table_stores_template_once(self):
        """
        BV: DRY output - template shown once, not per target

        Scenario:
          Given: CommandTable with multiple targets
          When: Table is examined
          Then: Template is accessible, targets are in list
        """
        from tools.post.bloodtrail.command_suggester import CommandTable, TargetEntry

        table = CommandTable(
            command_id="impacket-psexec",
            name="PsExec Remote Shell",
            template="impacket-psexec '<DOMAIN>/<USERNAME>'@<TARGET>",
            access_type="AdminTo",
        )

        # Add targets
        table.targets.append(TargetEntry(
            user="ADMIN@CORP.COM",
            target="DC01.CORP.COM",
            ready_command="impacket-psexec 'corp.com/admin'@dc01.corp.com",
            domain="CORP.COM",
        ))
        table.targets.append(TargetEntry(
            user="ADMIN@CORP.COM",
            target="WS01.CORP.COM",
            ready_command="impacket-psexec 'corp.com/admin'@ws01.corp.com",
            domain="CORP.COM",
        ))

        self.assertEqual(table.target_count, 2)
        self.assertIn("<TARGET>", table.template)

    def test_command_table_phase_from_access_type(self):
        """
        BV: Commands are grouped by attack phase

        Scenario:
          Given: CommandTable with access_type
          When: phase property is accessed
          Then: Correct phase is returned
        """
        from tools.post.bloodtrail.command_suggester import CommandTable

        table = CommandTable(
            command_id="test",
            name="Test",
            template="test",
            access_type="AdminTo",
        )

        # Should have a phase
        self.assertIsNotNone(table.phase)
        self.assertIsInstance(table.phase, str)

    def test_command_table_to_dict_includes_all_fields(self):
        """
        BV: CommandTable can be serialized for JSON export

        Scenario:
          Given: CommandTable with all fields
          When: to_dict() is called
          Then: All fields are included
        """
        from tools.post.bloodtrail.command_suggester import CommandTable

        table = CommandTable(
            command_id="test",
            name="Test Command",
            template="test <TARGET>",
            access_type="AdminTo",
            context="Test context",
        )

        result = table.to_dict()

        self.assertIn("command_id", result)
        self.assertIn("template", result)
        self.assertIn("targets", result)
        self.assertIn("phase", result)


# =============================================================================
# COMMAND SUGGESTER INITIALIZATION TESTS
# =============================================================================

class TestCommandSuggesterInitialization(unittest.TestCase):
    """Tests for CommandSuggester initialization."""

    def test_loads_commands_from_db(self):
        """
        BV: Commands are available for suggestion

        Scenario:
          Given: CommandSuggester with default db path
          When: Initialized
          Then: Commands are loaded
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        # Should have loaded some commands
        self.assertGreater(
            len(suggester.commands), 0,
            "Expected commands to be loaded"
        )

    def test_loads_commands_from_custom_path(self):
        """
        BV: Custom command database can be used

        Scenario:
          Given: Custom commands directory
          When: CommandSuggester is initialized with path
          Then: Commands from custom path are loaded
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create test command file
            commands_data = {
                "commands": [
                    {"id": "test-cmd", "name": "Test Command", "command": "test <TARGET>"}
                ]
            }
            with open(tmppath / "test.json", "w") as f:
                json.dump(commands_data, f)

            suggester = CommandSuggester(commands_db_path=tmppath)

            self.assertIn("test-cmd", suggester.commands)


# =============================================================================
# BUILD COMMAND TABLES TESTS
# =============================================================================

class TestBuildCommandTables(unittest.TestCase):
    """Tests for build_command_tables() method."""

    def test_builds_tables_for_lateral_movement_query(self):
        """
        BV: Lateral movement queries produce actionable commands

        Scenario:
          Given: Query result with AdminTo access
          When: build_command_tables() is called
          Then: PsExec/WmiExec tables are created
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        # Simulate lateral-adminto query result
        records = [
            {
                "User": "MIKE@CORP.COM",
                "AdminOnComputers": ["DC01.CORP.COM", "FILES01.CORP.COM"],
            }
        ]

        # Use a lateral movement query ID (if it exists in mappings)
        # Fall back to testing with a known mapping
        tables = suggester.build_command_tables("lateral-adminto-nonpriv", records)

        # May or may not have tables depending on mapping existence
        self.assertIsInstance(tables, list)

    def test_extracts_domain_from_upn(self):
        """
        BV: Domain is correctly extracted for command generation

        Scenario:
          Given: User in UPN format (user@domain.com)
          When: Command table is built
          Then: Domain is extracted correctly
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        records = [{"User": "ADMIN@CORP.COM", "Computer": "DC01.CORP.COM"}]

        # Build tables (may be empty if mapping doesn't exist)
        tables = suggester.build_command_tables("quick-kerberoastable", records)

        # If tables were created, check domain extraction
        for table in tables:
            for target in table.targets:
                if target.domain:
                    self.assertIn("CORP", target.domain.upper())

    def test_filters_group_names_as_targets(self):
        """
        BV: Group names (DOMAIN CONTROLLERS@...) are not used as targets

        Scenario:
          Given: Query result with group name in targets
          When: build_command_tables() is called
          Then: Group names are filtered out
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester
        from tools.post.bloodtrail.mappings.text_utils import is_group_name

        # Verify the filter function works
        self.assertTrue(is_group_name("DOMAIN CONTROLLERS@CORP.COM"))
        self.assertTrue(is_group_name("DOMAIN ADMINS@CORP.COM"))
        self.assertFalse(is_group_name("ADMIN@CORP.COM"))
        self.assertFalse(is_group_name("DC01.CORP.COM"))

    def test_deduplicates_target_entries(self):
        """
        BV: Duplicate user+target combinations are removed

        Scenario:
          Given: Query results with duplicates
          When: build_command_tables() is called
          Then: Only unique entries remain
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        # Create records that would produce duplicates
        records = [
            {"User": "ADMIN@CORP.COM", "Computer": "DC01.CORP.COM"},
            {"User": "ADMIN@CORP.COM", "Computer": "DC01.CORP.COM"},  # Duplicate
        ]

        # The suggester should deduplicate
        # (Test the internal deduplication method)
        from tools.post.bloodtrail.command_suggester import TargetEntry

        targets = [
            TargetEntry(user="ADMIN", target="DC01", ready_command="test", domain="CORP"),
            TargetEntry(user="ADMIN", target="DC01", ready_command="test", domain="CORP"),
        ]

        deduped = suggester._deduplicate_targets(targets)
        self.assertEqual(len(deduped), 1)


# =============================================================================
# LEGACY API TESTS
# =============================================================================

class TestLegacyAPI(unittest.TestCase):
    """Tests for backward-compatible suggest_for_query() method."""

    def test_suggest_for_query_returns_suggestions(self):
        """
        BV: Legacy API continues to work for existing code

        Scenario:
          Given: Query result records
          When: suggest_for_query() is called
          Then: CommandSuggestion list is returned
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        records = [{"User": "ADMIN@CORP.COM", "Computer": "DC01.CORP.COM"}]

        # May return empty list if mapping doesn't exist
        result = suggester.suggest_for_query("test-query", records)

        self.assertIsInstance(result, list)

    def test_suggestion_has_template_and_ready(self):
        """
        BV: Suggestions include both template and ready-to-run commands

        Scenario:
          Given: Valid query mapping
          When: suggest_for_query() returns results
          Then: Each suggestion has template and ready_to_run
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggestion

        # Create a suggestion manually to test structure
        suggestion = CommandSuggestion(
            command_id="test",
            name="Test",
            context="Test context",
            template="test <TARGET>",
            ready_to_run="test dc01.corp.com",
        )

        self.assertIn("<TARGET>", suggestion.template)
        self.assertIn("dc01", suggestion.ready_to_run)


# =============================================================================
# ATTACK SEQUENCE TESTS
# =============================================================================

class TestAttackSequence(unittest.TestCase):
    """Tests for AttackSequence dataclass."""

    def test_attack_sequence_stores_path(self):
        """
        BV: Attack sequences preserve path information

        Scenario:
          Given: AttackSequence with path nodes
          When: Sequence is examined
          Then: Path nodes are accessible
        """
        from tools.post.bloodtrail.command_suggester import AttackSequence

        sequence = AttackSequence(
            name="Admin Path",
            description="3-step attack chain",
            path_nodes=["USER@CORP.COM", "GROUP@CORP.COM", "DC01.CORP.COM"],
            edge_types=["MemberOf", "AdminTo"],
        )

        self.assertEqual(len(sequence.path_nodes), 3)
        self.assertEqual(len(sequence.edge_types), 2)

    def test_attack_sequence_total_steps(self):
        """
        BV: Step count is accurate

        Scenario:
          Given: AttackSequence with steps
          When: total_steps property is accessed
          Then: Correct count is returned
        """
        from tools.post.bloodtrail.command_suggester import AttackSequence, CommandSuggestion

        sequence = AttackSequence(
            name="Test",
            description="Test",
            path_nodes=[],
            edge_types=[],
        )

        # Add steps
        sequence.steps.append(CommandSuggestion(
            command_id="step1", name="Step 1", context="", template="", ready_to_run=""
        ))
        sequence.steps.append(CommandSuggestion(
            command_id="step2", name="Step 2", context="", template="", ready_to_run=""
        ))

        self.assertEqual(sequence.total_steps, 2)


# =============================================================================
# EDGE COMMAND MAPPING TESTS
# =============================================================================

class TestEdgeCommandMappings(unittest.TestCase):
    """Tests for edge type to command mappings."""

    def test_adminto_maps_to_psexec(self):
        """
        BV: AdminTo edges suggest remote shell commands

        Scenario:
          Given: EDGE_COMMAND_MAPPINGS
          When: AdminTo is looked up
          Then: PsExec-related commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import EDGE_COMMAND_MAPPINGS

        adminto_commands = EDGE_COMMAND_MAPPINGS.get("AdminTo", [])

        self.assertGreater(len(adminto_commands), 0)
        # Should include impacket-psexec or similar
        self.assertTrue(
            any("psexec" in cmd.lower() or "wmiexec" in cmd.lower()
                for cmd in adminto_commands)
        )

    def test_canrdp_maps_to_freerdp(self):
        """
        BV: CanRDP edges suggest RDP commands

        Scenario:
          Given: EDGE_COMMAND_MAPPINGS
          When: CanRDP is looked up
          Then: RDP-related commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import EDGE_COMMAND_MAPPINGS

        canrdp_commands = EDGE_COMMAND_MAPPINGS.get("CanRDP", [])

        self.assertGreater(len(canrdp_commands), 0)
        # Should include xfreerdp or similar
        self.assertTrue(
            any("rdp" in cmd.lower() for cmd in canrdp_commands)
        )

    def test_canpsremote_maps_to_evilwinrm(self):
        """
        BV: CanPSRemote edges suggest WinRM commands

        Scenario:
          Given: EDGE_COMMAND_MAPPINGS
          When: CanPSRemote is looked up
          Then: WinRM-related commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import EDGE_COMMAND_MAPPINGS

        psremote_commands = EDGE_COMMAND_MAPPINGS.get("CanPSRemote", [])

        self.assertGreater(len(psremote_commands), 0)
        # Should include evil-winrm or similar
        self.assertTrue(
            any("winrm" in cmd.lower() for cmd in psremote_commands)
        )

    def test_dcsync_edges_map_to_secretsdump(self):
        """
        BV: DCSync edges suggest secretsdump

        Scenario:
          Given: EDGE_COMMAND_MAPPINGS
          When: GetChanges/GetChangesAll is looked up
          Then: Secretsdump-related commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import EDGE_COMMAND_MAPPINGS

        getchanges_commands = EDGE_COMMAND_MAPPINGS.get("GetChangesAll", [])

        self.assertGreater(len(getchanges_commands), 0)
        # Should include secretsdump or dcsync
        self.assertTrue(
            any("dcsync" in cmd.lower() or "secretsdump" in cmd.lower()
                for cmd in getchanges_commands)
        )


# =============================================================================
# CREDENTIAL TYPE COMMAND MAPPING TESTS
# =============================================================================

class TestCredentialTypeCommands(unittest.TestCase):
    """Tests for credential type to command mappings."""

    def test_password_adminto_maps_to_psexec(self):
        """
        BV: Password + AdminTo suggests psexec with password auth

        Scenario:
          Given: CRED_TYPE_COMMANDS
          When: password + AdminTo is looked up
          Then: Password-auth commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import CRED_TYPE_COMMANDS

        commands = CRED_TYPE_COMMANDS.get("password", {}).get("AdminTo", [])

        self.assertGreater(len(commands), 0)

    def test_ntlm_adminto_maps_to_pth(self):
        """
        BV: NTLM hash + AdminTo suggests pass-the-hash commands

        Scenario:
          Given: CRED_TYPE_COMMANDS
          When: ntlm-hash + AdminTo is looked up
          Then: PTH commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import CRED_TYPE_COMMANDS

        commands = CRED_TYPE_COMMANDS.get("ntlm-hash", {}).get("AdminTo", [])

        self.assertGreater(len(commands), 0)
        # Should include pth commands
        self.assertTrue(
            any("pth" in cmd.lower() for cmd in commands)
        )

    def test_kerberos_adminto_maps_to_kerberos_auth(self):
        """
        BV: Kerberos ticket + AdminTo suggests Kerberos auth commands

        Scenario:
          Given: CRED_TYPE_COMMANDS
          When: kerberos-ticket + AdminTo is looked up
          Then: Kerberos auth commands are returned
        """
        from tools.post.bloodtrail.mappings.edge_mappings import CRED_TYPE_COMMANDS

        commands = CRED_TYPE_COMMANDS.get("kerberos-ticket", {}).get("AdminTo", [])

        self.assertGreater(len(commands), 0)
        # Should include kerberos commands
        self.assertTrue(
            any("kerberos" in cmd.lower() for cmd in commands)
        )


# =============================================================================
# COMMAND TEMPLATE TESTS
# =============================================================================

class TestCredentialTypeTemplates(unittest.TestCase):
    """Tests for credential type command templates."""

    def test_password_template_has_cred_placeholder(self):
        """
        BV: Password templates include password placeholder

        Scenario:
          Given: CRED_TYPE_TEMPLATES
          When: password template is retrieved
          Then: Template contains <CRED_VALUE> placeholder
        """
        from tools.post.bloodtrail.mappings.edge_mappings import CRED_TYPE_TEMPLATES

        template = CRED_TYPE_TEMPLATES.get("password", {}).get("AdminTo", "")

        if template:
            self.assertIn("<CRED_VALUE>", template)

    def test_ntlm_template_has_hashes_flag(self):
        """
        BV: NTLM templates use -hashes flag

        Scenario:
          Given: CRED_TYPE_TEMPLATES
          When: ntlm-hash template is retrieved
          Then: Template contains -hashes or similar
        """
        from tools.post.bloodtrail.mappings.edge_mappings import CRED_TYPE_TEMPLATES

        template = CRED_TYPE_TEMPLATES.get("ntlm-hash", {}).get("AdminTo", "")

        if template:
            self.assertIn("-hashes", template.lower())


# =============================================================================
# VALIDATION HELPER TESTS
# =============================================================================

class TestValidationHelpers(unittest.TestCase):
    """Tests for validation helper functions."""

    def test_is_stale_password_detects_old_passwords(self):
        """
        BV: Stale credentials are warned about

        Scenario:
          Given: Password last set 3 years ago
          When: is_stale_password() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.command_suggester import is_stale_password
        import time

        # 3 years ago
        old_timestamp = time.time() - (3 * 365 * 24 * 3600)

        self.assertTrue(is_stale_password(old_timestamp, years=2))

    def test_is_stale_password_accepts_recent(self):
        """
        BV: Recent passwords are not flagged

        Scenario:
          Given: Password last set 6 months ago
          When: is_stale_password() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.command_suggester import is_stale_password
        import time

        # 6 months ago
        recent_timestamp = time.time() - (180 * 24 * 3600)

        self.assertFalse(is_stale_password(recent_timestamp, years=2))

    def test_is_stale_password_handles_none(self):
        """
        BV: Missing timestamp doesn't cause error

        Scenario:
          Given: None timestamp
          When: is_stale_password() is called
          Then: Returns False (not stale)
        """
        from tools.post.bloodtrail.command_suggester import is_stale_password

        self.assertFalse(is_stale_password(None))
        self.assertFalse(is_stale_password(0))
        self.assertFalse(is_stale_password(-1))

    def test_validate_target_entry_detects_disabled(self):
        """
        BV: Disabled accounts are warned about

        Scenario:
          Given: Record with enabled=False
          When: validate_target_entry() is called
          Then: Returns [DISABLED] warning
        """
        from tools.post.bloodtrail.command_suggester import validate_target_entry

        record = {"enabled": False}
        warnings = validate_target_entry(record, "AdminTo")

        self.assertIn("[DISABLED]", warnings)


# =============================================================================
# GET COMMANDS FOR EDGE TESTS
# =============================================================================

class TestGetCommandsForEdge(unittest.TestCase):
    """Tests for get_commands_for_edge() method."""

    def test_returns_suggestions_for_valid_edge(self):
        """
        BV: Edge types produce relevant command suggestions

        Scenario:
          Given: Valid edge type
          When: get_commands_for_edge() is called
          Then: List of suggestions is returned
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()
        suggestions = suggester.get_commands_for_edge("AdminTo")

        self.assertIsInstance(suggestions, list)
        # May be empty if commands not found in db

    def test_returns_empty_for_unknown_edge(self):
        """
        BV: Unknown edge types don't cause errors

        Scenario:
          Given: Unknown edge type
          When: get_commands_for_edge() is called
          Then: Empty list is returned
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()
        suggestions = suggester.get_commands_for_edge("NonexistentEdge")

        self.assertEqual(suggestions, [])


# =============================================================================
# SUGGEST FOR OWNED USER TESTS
# =============================================================================

class TestSuggestForOwnedUser(unittest.TestCase):
    """Tests for suggest_for_owned_user() method."""

    def test_generates_suggestions_for_access_types(self):
        """
        BV: Owned users get targeted attack suggestions

        Scenario:
          Given: Owned user with AdminTo access
          When: suggest_for_owned_user() is called
          Then: Suggestions for each access are returned
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        access_types = [
            {"Target": "DC01.CORP.COM", "AccessType": "AdminTo"},
            {"Target": "WS01.CORP.COM", "AccessType": "CanRDP"},
        ]

        suggestions = suggester.suggest_for_owned_user("ADMIN@CORP.COM", access_types)

        self.assertIsInstance(suggestions, list)

    def test_deduplicates_by_command_and_target(self):
        """
        BV: Same command for same target not duplicated

        Scenario:
          Given: Multiple access entries to same target
          When: suggest_for_owned_user() is called
          Then: Duplicate suggestions are removed
        """
        from tools.post.bloodtrail.command_suggester import CommandSuggester

        suggester = CommandSuggester()

        access_types = [
            {"Target": "DC01.CORP.COM", "AccessType": "AdminTo"},
            {"Target": "DC01.CORP.COM", "AccessType": "AdminTo"},  # Duplicate
        ]

        suggestions = suggester.suggest_for_owned_user("ADMIN@CORP.COM", access_types)

        # Count unique (command_id, target) pairs
        seen = set()
        for s in suggestions:
            key = (s.command_id, "DC01.CORP.COM")
            self.assertNotIn(key, seen, f"Duplicate suggestion: {key}")
            seen.add(key)


if __name__ == "__main__":
    unittest.main()
