"""
BloodTrail Lateral Movement Mappings Tests

Business Value Focus:
- LATERAL_TECHNIQUES data structure must be well-formed for command suggestion
- get_techniques_for_access() must return correct techniques for each access type
- get_technique_command() must return appropriate command templates for credential types
- needs_overpass_the_hash() must correctly identify Kerberos-only targets
- CREDENTIAL_CONVERSION and TICKET_ATTACKS must provide hash-to-ticket workflows

Ownership: tests/tools/post/bloodtrail/mappings/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from typing import List, Dict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# LATERAL_TECHNIQUES DATA STRUCTURE TESTS
# =============================================================================

class TestLateralTechniquesStructure(unittest.TestCase):
    """Tests for LATERAL_TECHNIQUES dict structure validation."""

    def test_lateral_techniques_is_dict(self):
        """
        BV: Data structure is accessible for command suggestion

        Scenario:
          Given: LATERAL_TECHNIQUES constant
          When: Type is checked
          Then: It is a dictionary
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        self.assertIsInstance(LATERAL_TECHNIQUES, dict)

    def test_lateral_techniques_has_expected_access_types(self):
        """
        BV: All major lateral movement access types are supported

        Scenario:
          Given: LATERAL_TECHNIQUES dict
          When: Keys are examined
          Then: AdminTo, CanPSRemote, CanRDP, ExecuteDCOM are present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        expected_access_types = ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM"]

        for access_type in expected_access_types:
            self.assertIn(
                access_type,
                LATERAL_TECHNIQUES,
                f"Expected access type '{access_type}' not in LATERAL_TECHNIQUES"
            )

    def test_each_access_type_has_techniques_list(self):
        """
        BV: Each access type provides technique options

        Scenario:
          Given: LATERAL_TECHNIQUES dict
          When: Each value is examined
          Then: Each value is a list of TechniqueInfo objects
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES
        from tools.post.bloodtrail.mappings.base import TechniqueInfo

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            self.assertIsInstance(
                techniques, list,
                f"{access_type} should map to a list"
            )
            for technique in techniques:
                self.assertIsInstance(
                    technique, TechniqueInfo,
                    f"Each technique for {access_type} should be TechniqueInfo"
                )

    def test_technique_info_has_required_fields(self):
        """
        BV: TechniqueInfo objects have all fields for display

        Scenario:
          Given: Any TechniqueInfo in LATERAL_TECHNIQUES
          When: Fields are accessed
          Then: All required fields are present and non-empty
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        required_fields = [
            "name", "command_templates", "ports", "requirements",
            "noise_level", "advantages", "disadvantages", "oscp_relevance"
        ]

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            for technique in techniques:
                for field in required_fields:
                    self.assertTrue(
                        hasattr(technique, field),
                        f"TechniqueInfo missing field '{field}'"
                    )
                # Name should not be empty
                self.assertTrue(
                    technique.name,
                    f"Technique name should not be empty"
                )

    def test_command_templates_is_dict_with_cred_types(self):
        """
        BV: Command templates are organized by credential type

        Scenario:
          Given: TechniqueInfo.command_templates
          When: Structure is examined
          Then: It maps credential types to command strings
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            for technique in techniques:
                self.assertIsInstance(
                    technique.command_templates, dict,
                    f"{technique.name} command_templates should be dict"
                )
                # Should have at least one credential type
                self.assertGreater(
                    len(technique.command_templates), 0,
                    f"{technique.name} should have at least one command template"
                )
                # Each value should be a string
                for cred_type, template in technique.command_templates.items():
                    self.assertIsInstance(
                        template, str,
                        f"{technique.name}[{cred_type}] should be string"
                    )

    def test_ports_is_list_of_integers(self):
        """
        BV: Port requirements are valid port numbers

        Scenario:
          Given: TechniqueInfo.ports
          When: Values are examined
          Then: All are valid port integers (0-65535)
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            for technique in techniques:
                self.assertIsInstance(
                    technique.ports, list,
                    f"{technique.name} ports should be list"
                )
                for port in technique.ports:
                    self.assertIsInstance(port, int)
                    self.assertGreaterEqual(port, 0)
                    self.assertLessEqual(port, 65535)

    def test_noise_level_is_valid(self):
        """
        BV: Noise level helps users choose stealthy techniques

        Scenario:
          Given: TechniqueInfo.noise_level
          When: Value is examined
          Then: It is one of low/medium/high
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        valid_noise_levels = {"low", "medium", "high"}

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            for technique in techniques:
                self.assertIn(
                    technique.noise_level, valid_noise_levels,
                    f"{technique.name} noise_level should be low/medium/high"
                )

    def test_oscp_relevance_is_valid(self):
        """
        BV: OSCP relevance helps exam preparation

        Scenario:
          Given: TechniqueInfo.oscp_relevance
          When: Value is examined
          Then: It is one of low/medium/high
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        valid_relevance = {"low", "medium", "high"}

        for access_type, techniques in LATERAL_TECHNIQUES.items():
            for technique in techniques:
                self.assertIn(
                    technique.oscp_relevance, valid_relevance,
                    f"{technique.name} oscp_relevance should be low/medium/high"
                )


# =============================================================================
# ADMINTO TECHNIQUES TESTS
# =============================================================================

class TestAdminToTechniques(unittest.TestCase):
    """Tests for AdminTo access type techniques."""

    def test_adminto_has_six_techniques(self):
        """
        BV: AdminTo provides multiple technique options

        Scenario:
          Given: LATERAL_TECHNIQUES["AdminTo"]
          When: Count is checked
          Then: 6 techniques are available
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        self.assertEqual(
            len(techniques), 6,
            "AdminTo should have 6 techniques"
        )

    def test_adminto_includes_psexec(self):
        """
        BV: PsExec is available for AdminTo access

        Scenario:
          Given: AdminTo techniques
          When: Technique names are examined
          Then: PsExec variant is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("psexec" in name.lower() for name in technique_names),
            "AdminTo should include PsExec technique"
        )

    def test_adminto_includes_wmiexec(self):
        """
        BV: WMIExec is available for AdminTo access

        Scenario:
          Given: AdminTo techniques
          When: Technique names are examined
          Then: WMIExec variant is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("wmiexec" in name.lower() for name in technique_names),
            "AdminTo should include WMIExec technique"
        )

    def test_adminto_includes_smbexec(self):
        """
        BV: SMBExec is available for AdminTo access

        Scenario:
          Given: AdminTo techniques
          When: Technique names are examined
          Then: SMBExec variant is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("smbexec" in name.lower() for name in technique_names),
            "AdminTo should include SMBExec technique"
        )

    def test_adminto_includes_evilwinrm(self):
        """
        BV: Evil-WinRM is available for AdminTo access

        Scenario:
          Given: AdminTo techniques
          When: Technique names are examined
          Then: Evil-WinRM is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("evil-winrm" in name.lower() or "winrm" in name.lower()
                for name in technique_names),
            "AdminTo should include Evil-WinRM technique"
        )

    def test_adminto_psexec_supports_password_and_hash(self):
        """
        BV: PsExec works with both password and NTLM hash

        Scenario:
          Given: PsExec technique from AdminTo
          When: Command templates are examined
          Then: Both password and ntlm-hash templates exist
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("AdminTo", [])
        psexec = next((t for t in techniques if "psexec" in t.name.lower()), None)

        self.assertIsNotNone(psexec, "PsExec technique should exist")
        self.assertIn("password", psexec.command_templates)
        self.assertIn("ntlm-hash", psexec.command_templates)


# =============================================================================
# CANPSREMOTE TECHNIQUES TESTS
# =============================================================================

class TestCanPSRemoteTechniques(unittest.TestCase):
    """Tests for CanPSRemote access type techniques."""

    def test_canpsremote_has_two_techniques(self):
        """
        BV: CanPSRemote provides WinRM technique options

        Scenario:
          Given: LATERAL_TECHNIQUES["CanPSRemote"]
          When: Count is checked
          Then: 2 techniques are available
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanPSRemote", [])
        self.assertEqual(
            len(techniques), 2,
            "CanPSRemote should have 2 techniques"
        )

    def test_canpsremote_includes_evilwinrm(self):
        """
        BV: Evil-WinRM is primary for CanPSRemote

        Scenario:
          Given: CanPSRemote techniques
          When: First technique is examined
          Then: Evil-WinRM is first (default)
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanPSRemote", [])
        self.assertGreater(len(techniques), 0)

        first = techniques[0]
        self.assertIn("evil-winrm", first.name.lower())

    def test_canpsremote_uses_port_5985(self):
        """
        BV: CanPSRemote techniques target WinRM ports

        Scenario:
          Given: CanPSRemote techniques
          When: Port requirements are examined
          Then: Port 5985 or 5986 is required
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanPSRemote", [])

        for technique in techniques:
            self.assertTrue(
                5985 in technique.ports or 5986 in technique.ports,
                f"{technique.name} should require WinRM port 5985/5986"
            )


# =============================================================================
# CANRDP TECHNIQUES TESTS
# =============================================================================

class TestCanRDPTechniques(unittest.TestCase):
    """Tests for CanRDP access type techniques."""

    def test_canrdp_has_two_techniques(self):
        """
        BV: CanRDP provides RDP tool options

        Scenario:
          Given: LATERAL_TECHNIQUES["CanRDP"]
          When: Count is checked
          Then: 2 techniques are available
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanRDP", [])
        self.assertEqual(
            len(techniques), 2,
            "CanRDP should have 2 techniques"
        )

    def test_canrdp_includes_xfreerdp(self):
        """
        BV: xfreerdp is available for RDP

        Scenario:
          Given: CanRDP techniques
          When: Technique names are examined
          Then: xfreerdp is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanRDP", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("xfreerdp" in name.lower() for name in technique_names),
            "CanRDP should include xfreerdp technique"
        )

    def test_canrdp_includes_rdesktop(self):
        """
        BV: rdesktop is available as fallback

        Scenario:
          Given: CanRDP techniques
          When: Technique names are examined
          Then: rdesktop is present
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanRDP", [])
        technique_names = [t.name for t in techniques]

        self.assertTrue(
            any("rdesktop" in name.lower() for name in technique_names),
            "CanRDP should include rdesktop technique"
        )

    def test_canrdp_uses_port_3389(self):
        """
        BV: CanRDP techniques target RDP port

        Scenario:
          Given: CanRDP techniques
          When: Port requirements are examined
          Then: Port 3389 is required
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("CanRDP", [])

        for technique in techniques:
            self.assertIn(
                3389, technique.ports,
                f"{technique.name} should require RDP port 3389"
            )


# =============================================================================
# EXECUTEDCOM TECHNIQUES TESTS
# =============================================================================

class TestExecuteDCOMTechniques(unittest.TestCase):
    """Tests for ExecuteDCOM access type techniques."""

    def test_executedcom_has_one_technique(self):
        """
        BV: ExecuteDCOM provides DCOM execution option

        Scenario:
          Given: LATERAL_TECHNIQUES["ExecuteDCOM"]
          When: Count is checked
          Then: 1 technique is available
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("ExecuteDCOM", [])
        self.assertEqual(
            len(techniques), 1,
            "ExecuteDCOM should have 1 technique"
        )

    def test_executedcom_uses_mmc20_object(self):
        """
        BV: DCOM uses MMC20 Application object

        Scenario:
          Given: ExecuteDCOM technique
          When: Command template is examined
          Then: MMC20 object is specified
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("ExecuteDCOM", [])
        technique = techniques[0]

        # Check if any template mentions MMC20
        templates_str = " ".join(technique.command_templates.values())
        self.assertIn(
            "mmc20", templates_str.lower(),
            "ExecuteDCOM should use MMC20 object"
        )

    def test_executedcom_uses_port_135(self):
        """
        BV: ExecuteDCOM requires RPC port

        Scenario:
          Given: ExecuteDCOM techniques
          When: Port requirements are examined
          Then: Port 135 is required
        """
        from tools.post.bloodtrail.mappings.lateral import LATERAL_TECHNIQUES

        techniques = LATERAL_TECHNIQUES.get("ExecuteDCOM", [])

        for technique in techniques:
            self.assertIn(
                135, technique.ports,
                f"{technique.name} should require RPC port 135"
            )


# =============================================================================
# CREDENTIAL CONVERSION TESTS
# =============================================================================

class TestCredentialConversion(unittest.TestCase):
    """Tests for CREDENTIAL_CONVERSION dict (hash-to-ticket workflows)."""

    def test_credential_conversion_is_dict(self):
        """
        BV: Credential conversion techniques are accessible

        Scenario:
          Given: CREDENTIAL_CONVERSION constant
          When: Type is checked
          Then: It is a dictionary
        """
        from tools.post.bloodtrail.mappings.lateral import CREDENTIAL_CONVERSION

        self.assertIsInstance(CREDENTIAL_CONVERSION, dict)

    def test_overpass_the_hash_exists(self):
        """
        BV: Overpass-the-hash is available for NTLM to TGT conversion

        Scenario:
          Given: CREDENTIAL_CONVERSION
          When: overpass-the-hash is looked up
          Then: TechniqueInfo is returned
        """
        from tools.post.bloodtrail.mappings.lateral import CREDENTIAL_CONVERSION
        from tools.post.bloodtrail.mappings.base import TechniqueInfo

        self.assertIn("overpass-the-hash", CREDENTIAL_CONVERSION)
        technique = CREDENTIAL_CONVERSION["overpass-the-hash"]
        self.assertIsInstance(technique, TechniqueInfo)

    def test_overpass_the_hash_uses_kerberos_port(self):
        """
        BV: Overpass-the-hash requires Kerberos access

        Scenario:
          Given: overpass-the-hash technique
          When: Port requirements are examined
          Then: Port 88 (Kerberos) is required
        """
        from tools.post.bloodtrail.mappings.lateral import CREDENTIAL_CONVERSION

        technique = CREDENTIAL_CONVERSION["overpass-the-hash"]
        self.assertIn(88, technique.ports)

    def test_overpass_the_hash_has_ntlm_template(self):
        """
        BV: Overpass-the-hash accepts NTLM hash input

        Scenario:
          Given: overpass-the-hash technique
          When: Command templates are examined
          Then: ntlm-hash template exists
        """
        from tools.post.bloodtrail.mappings.lateral import CREDENTIAL_CONVERSION

        technique = CREDENTIAL_CONVERSION["overpass-the-hash"]
        self.assertIn("ntlm-hash", technique.command_templates)


# =============================================================================
# TICKET ATTACKS TESTS
# =============================================================================

class TestTicketAttacks(unittest.TestCase):
    """Tests for TICKET_ATTACKS dict (pass-the-ticket workflows)."""

    def test_ticket_attacks_is_dict(self):
        """
        BV: Ticket attack techniques are accessible

        Scenario:
          Given: TICKET_ATTACKS constant
          When: Type is checked
          Then: It is a dictionary
        """
        from tools.post.bloodtrail.mappings.lateral import TICKET_ATTACKS

        self.assertIsInstance(TICKET_ATTACKS, dict)

    def test_ticket_attacks_has_expected_keys(self):
        """
        BV: Standard ticket operations are available

        Scenario:
          Given: TICKET_ATTACKS
          When: Keys are examined
          Then: export, pass-the-ticket, convert are present
        """
        from tools.post.bloodtrail.mappings.lateral import TICKET_ATTACKS

        expected_keys = ["export-tickets", "pass-the-ticket", "convert-kirbi-ccache"]

        for key in expected_keys:
            self.assertIn(
                key, TICKET_ATTACKS,
                f"Expected ticket attack '{key}' not in TICKET_ATTACKS"
            )

    def test_pass_the_ticket_has_kerberos_template(self):
        """
        BV: Pass-the-ticket provides ccache export command

        Scenario:
          Given: pass-the-ticket technique
          When: Command template is examined
          Then: KRB5CCNAME export is present
        """
        from tools.post.bloodtrail.mappings.lateral import TICKET_ATTACKS

        technique = TICKET_ATTACKS["pass-the-ticket"]
        template = technique.command_templates.get("kerberos-ticket", "")

        self.assertIn(
            "KRB5CCNAME", template,
            "pass-the-ticket should set KRB5CCNAME"
        )

    def test_convert_kirbi_ccache_exists(self):
        """
        BV: Ticket format conversion is available

        Scenario:
          Given: TICKET_ATTACKS
          When: convert-kirbi-ccache is looked up
          Then: TechniqueInfo with ticketConverter is returned
        """
        from tools.post.bloodtrail.mappings.lateral import TICKET_ATTACKS

        technique = TICKET_ATTACKS["convert-kirbi-ccache"]
        template = technique.command_templates.get("kirbi-file", "")

        self.assertIn(
            "ticketConverter", template,
            "convert-kirbi-ccache should use impacket-ticketConverter"
        )


# =============================================================================
# GET_TECHNIQUES_FOR_ACCESS TESTS
# =============================================================================

class TestGetTechniquesForAccess(unittest.TestCase):
    """Tests for get_techniques_for_access() function."""

    def test_returns_list_for_valid_access_type(self):
        """
        BV: Valid access types return technique list

        Scenario:
          Given: Valid access type
          When: get_techniques_for_access() is called
          Then: List of TechniqueInfo is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_techniques_for_access
        from tools.post.bloodtrail.mappings.base import TechniqueInfo

        result = get_techniques_for_access("AdminTo")

        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        for item in result:
            self.assertIsInstance(item, TechniqueInfo)

    def test_returns_empty_list_for_invalid_access_type(self):
        """
        BV: Invalid access types return empty list (no error)

        Scenario:
          Given: Invalid/unknown access type
          When: get_techniques_for_access() is called
          Then: Empty list is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_techniques_for_access

        result = get_techniques_for_access("NonexistentAccessType")

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_returns_correct_techniques_for_canrdp(self):
        """
        BV: CanRDP returns RDP-specific techniques

        Scenario:
          Given: CanRDP access type
          When: get_techniques_for_access() is called
          Then: xfreerdp/rdesktop techniques are returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_techniques_for_access

        result = get_techniques_for_access("CanRDP")

        self.assertGreater(len(result), 0)
        # All techniques should target port 3389
        for technique in result:
            self.assertIn(3389, technique.ports)


# =============================================================================
# GET_TECHNIQUE_COMMAND TESTS
# =============================================================================

class TestGetTechniqueCommand(unittest.TestCase):
    """Tests for get_technique_command() function."""

    def test_returns_template_for_valid_params(self):
        """
        BV: Valid parameters return command template

        Scenario:
          Given: Valid access type, cred type, and technique index
          When: get_technique_command() is called
          Then: Command template string is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("AdminTo", "password", 0)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_returns_none_for_invalid_access_type(self):
        """
        BV: Invalid access type returns None

        Scenario:
          Given: Invalid access type
          When: get_technique_command() is called
          Then: None is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("InvalidAccess", "password", 0)

        self.assertIsNone(result)

    def test_returns_none_for_invalid_cred_type(self):
        """
        BV: Invalid credential type returns None

        Scenario:
          Given: Valid access type but invalid credential type
          When: get_technique_command() is called
          Then: None is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("AdminTo", "invalid-cred-type", 0)

        self.assertIsNone(result)

    def test_returns_none_for_out_of_range_index(self):
        """
        BV: Out of range technique index returns None

        Scenario:
          Given: Valid params but technique index too high
          When: get_technique_command() is called
          Then: None is returned
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("AdminTo", "password", 999)

        self.assertIsNone(result)

    def test_ntlm_hash_template_has_hashes_flag(self):
        """
        BV: NTLM hash commands use -hashes flag

        Scenario:
          Given: AdminTo with ntlm-hash credential
          When: get_technique_command() is called
          Then: Template contains -hashes flag
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("AdminTo", "ntlm-hash", 0)

        self.assertIsNotNone(result)
        self.assertIn("-hashes", result.lower())

    def test_kerberos_template_has_krb5ccname(self):
        """
        BV: Kerberos commands set KRB5CCNAME environment

        Scenario:
          Given: AdminTo with kerberos-ticket credential
          When: get_technique_command() is called
          Then: Template contains KRB5CCNAME
        """
        from tools.post.bloodtrail.mappings.lateral import get_technique_command

        result = get_technique_command("AdminTo", "kerberos-ticket", 0)

        self.assertIsNotNone(result)
        self.assertIn("KRB5CCNAME", result)


# =============================================================================
# NEEDS_OVERPASS_THE_HASH TESTS
# =============================================================================

class TestNeedsOverpassTheHash(unittest.TestCase):
    """Tests for needs_overpass_the_hash() function."""

    def test_returns_false_for_password(self):
        """
        BV: Passwords do not need conversion

        Scenario:
          Given: Password credential type
          When: needs_overpass_the_hash() is called
          Then: False is returned
        """
        from tools.post.bloodtrail.mappings.lateral import needs_overpass_the_hash

        result = needs_overpass_the_hash("password", [88, 445])

        self.assertFalse(result)

    def test_returns_false_for_kerberos_ticket(self):
        """
        BV: Kerberos tickets do not need conversion

        Scenario:
          Given: Kerberos ticket credential type
          When: needs_overpass_the_hash() is called
          Then: False is returned
        """
        from tools.post.bloodtrail.mappings.lateral import needs_overpass_the_hash

        result = needs_overpass_the_hash("kerberos-ticket", [88])

        self.assertFalse(result)

    def test_returns_false_when_smb_available(self):
        """
        BV: NTLM hash can use SMB directly

        Scenario:
          Given: NTLM hash and port 445 open
          When: needs_overpass_the_hash() is called
          Then: False is returned (direct hash auth works)
        """
        from tools.post.bloodtrail.mappings.lateral import needs_overpass_the_hash

        result = needs_overpass_the_hash("ntlm-hash", [445, 88])

        self.assertFalse(result)

    def test_returns_true_when_kerberos_only(self):
        """
        BV: NTLM hash needs conversion when only Kerberos available

        Scenario:
          Given: NTLM hash, port 88 open, port 445 closed
          When: needs_overpass_the_hash() is called
          Then: True is returned (need to convert to TGT)
        """
        from tools.post.bloodtrail.mappings.lateral import needs_overpass_the_hash

        result = needs_overpass_the_hash("ntlm-hash", [88])

        self.assertTrue(result)

    def test_returns_false_when_no_kerberos(self):
        """
        BV: Cannot convert if Kerberos unavailable

        Scenario:
          Given: NTLM hash, no port 88
          When: needs_overpass_the_hash() is called
          Then: False is returned (conversion not possible)
        """
        from tools.post.bloodtrail.mappings.lateral import needs_overpass_the_hash

        result = needs_overpass_the_hash("ntlm-hash", [135, 5985])

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
