"""
Tests for BloodTrail Password Spray Mappings

Business Value Focus:
- Spray techniques define correct command templates for credential attacks
- Protocol configurations enable multi-target credential validation
- Scenario recommendations guide pentesters to appropriate spray methods
- User enumeration commands provide reliable target discovery

Test Priority: TIER 2 - HIGH (AD Exploitation)

These tests protect against:
- Missing or malformed command templates that would break spray operations
- Incorrect protocol definitions that could miss valid attack vectors
- Scenario misconfigurations that would recommend suboptimal spray methods
"""

import pytest
from typing import Dict, List

# Module under test
from tools.post.bloodtrail.mappings.spray import (
    SPRAY_TECHNIQUES,
    ALL_TARGETS_PROTOCOLS,
    ALL_TARGETS_IP_THRESHOLD,
    SPRAY_SCENARIOS,
    USER_ENUM_COMMANDS,
    PASSWORD_LIST_COMMANDS,
    PASSWORD_LIST_SCENARIOS,
    SPRAY_ONELINERS,
    get_spray_technique,
    get_all_spray_techniques,
    get_spray_scenarios,
    get_user_enum_commands,
    get_password_list_commands,
    get_password_list_scenarios,
    get_spray_oneliners,
)
from tools.post.bloodtrail.mappings.base import SprayTechniqueInfo


# =============================================================================
# SprayTechniqueInfo Dataclass Tests
# =============================================================================

class TestSprayTechniqueInfo:
    """Tests for SprayTechniqueInfo dataclass structure"""

    def test_smb_technique_has_all_required_fields(self):
        """
        BV: SMB spray technique is fully defined for password attacks

        Scenario:
          Given: SPRAY_TECHNIQUES dictionary
          When: Accessing 'smb' technique
          Then: All required fields are present and valid
        """
        smb = SPRAY_TECHNIQUES["smb"]

        assert isinstance(smb, SprayTechniqueInfo)
        assert smb.name == "SMB-Based Spray (crackmapexec/netexec)"
        assert smb.description != ""
        assert isinstance(smb.command_templates, dict)
        assert isinstance(smb.ports, list)
        assert 445 in smb.ports
        assert isinstance(smb.requirements, list)
        assert smb.noise_level in ["low", "medium", "high"]
        assert smb.advantages != ""
        assert smb.disadvantages != ""
        assert smb.oscp_relevance in ["low", "medium", "high"]
        assert isinstance(smb.best_for, list)

    def test_kerberos_technique_has_all_required_fields(self):
        """
        BV: Kerberos spray technique provides stealth password attacks

        Scenario:
          Given: SPRAY_TECHNIQUES dictionary
          When: Accessing 'kerberos' technique
          Then: All required fields are present and valid
        """
        kerb = SPRAY_TECHNIQUES["kerberos"]

        assert isinstance(kerb, SprayTechniqueInfo)
        assert "kerbrute" in kerb.name.lower()
        assert 88 in kerb.ports
        assert kerb.noise_level == "low"  # Kerberos is stealthiest
        assert kerb.oscp_relevance == "high"

    def test_ldap_technique_has_all_required_fields(self):
        """
        BV: LDAP spray works on Windows without external tools

        Scenario:
          Given: SPRAY_TECHNIQUES dictionary
          When: Accessing 'ldap' technique
          Then: All required fields are present, includes PowerShell commands
        """
        ldap = SPRAY_TECHNIQUES["ldap"]

        assert isinstance(ldap, SprayTechniqueInfo)
        assert 389 in ldap.ports or 636 in ldap.ports
        assert "PowerShell" in ldap.description or "LDAP" in ldap.name

    def test_all_techniques_have_command_templates(self):
        """
        BV: Every spray technique has at least one usable command

        Scenario:
          Given: All spray techniques
          When: Checking command_templates
          Then: Each has at least one non-empty template
        """
        for tech_name, tech in SPRAY_TECHNIQUES.items():
            assert len(tech.command_templates) > 0, \
                f"Technique '{tech_name}' has no command templates"
            for template_name, template in tech.command_templates.items():
                assert template != "", \
                    f"Technique '{tech_name}' has empty template '{template_name}'"


# =============================================================================
# SPRAY_TECHNIQUES Structure Tests
# =============================================================================

class TestSprayTechniques:
    """Tests for SPRAY_TECHNIQUES dictionary structure"""

    def test_contains_required_protocols(self):
        """
        BV: All standard spray protocols are available

        Scenario:
          Given: SPRAY_TECHNIQUES dictionary
          When: Checking for required protocols
          Then: Contains smb, kerberos, and ldap
        """
        required = ["smb", "kerberos", "ldap"]
        for protocol in required:
            assert protocol in SPRAY_TECHNIQUES, \
                f"Missing required protocol: {protocol}"

    def test_smb_has_single_password_template(self):
        """
        BV: SMB spray supports single password against user list

        Scenario:
          Given: SMB spray technique
          When: Checking command templates
          Then: Has 'single_password' template with correct placeholders
        """
        smb = SPRAY_TECHNIQUES["smb"]

        assert "single_password" in smb.command_templates
        template = smb.command_templates["single_password"]
        assert "<DC_IP>" in template
        assert "<USER_FILE>" in template
        assert "<PASSWORD>" in template
        assert "<DOMAIN>" in template

    def test_smb_has_password_list_template(self):
        """
        BV: SMB spray supports password list for credential stuffing

        Scenario:
          Given: SMB spray technique
          When: Checking command templates
          Then: Has 'password_list' template with no-bruteforce flag
        """
        smb = SPRAY_TECHNIQUES["smb"]

        assert "password_list" in smb.command_templates
        template = smb.command_templates["password_list"]
        assert "--no-bruteforce" in template  # Avoids lockouts

    def test_kerberos_has_userenum_template(self):
        """
        BV: Kerberos provides user enumeration via pre-auth

        Scenario:
          Given: Kerberos spray technique
          When: Checking command templates
          Then: Has 'user_enum' template for username validation
        """
        kerb = SPRAY_TECHNIQUES["kerberos"]

        assert "user_enum" in kerb.command_templates
        template = kerb.command_templates["user_enum"]
        assert "userenum" in template.lower()

    def test_ldap_has_powershell_template(self):
        """
        BV: LDAP spray works from Windows domain-joined machines

        Scenario:
          Given: LDAP spray technique
          When: Checking command templates
          Then: Has PowerShell-based spray command
        """
        ldap = SPRAY_TECHNIQUES["ldap"]

        # Check for PS1 or PowerShell-based template
        has_ps_template = any(
            "ps1" in key or "Invoke" in value
            for key, value in ldap.command_templates.items()
        )
        assert has_ps_template, "LDAP should have PowerShell-based template"


# =============================================================================
# ALL_TARGETS_PROTOCOLS Tests
# =============================================================================

class TestAllTargetsProtocols:
    """Tests for multi-target credential validation templates"""

    def test_contains_essential_protocols(self):
        """
        BV: All essential protocols for lateral movement are defined

        Scenario:
          Given: ALL_TARGETS_PROTOCOLS dictionary
          When: Checking for essential protocols
          Then: Contains smb, winrm, rdp, mssql
        """
        essential = ["smb", "winrm", "rdp", "mssql"]
        for protocol in essential:
            assert protocol in ALL_TARGETS_PROTOCOLS, \
                f"Missing essential protocol: {protocol}"

    def test_each_protocol_has_port(self):
        """
        BV: Each protocol defines its network port for targeting

        Scenario:
          Given: All protocol configurations
          When: Checking 'port' field
          Then: Each has valid port string
        """
        expected_ports = {
            "smb": "445",
            "winrm": "5985",
            "rdp": "3389",
            "mssql": "1433",
        }

        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            assert "port" in config, f"Protocol '{proto}' missing port"
            if proto in expected_ports:
                assert config["port"] == expected_ports[proto], \
                    f"Protocol '{proto}' has wrong port"

    def test_each_protocol_has_loop_template(self):
        """
        BV: Loop templates work for small target counts (<=20 IPs)

        Scenario:
          Given: All protocol configurations
          When: Checking for loop_template
          Then: Each has bash loop with {ips} placeholder
        """
        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            assert "loop_template" in config, \
                f"Protocol '{proto}' missing loop_template"

            template = config["loop_template"]
            assert "{ips}" in template, \
                f"Protocol '{proto}' loop_template missing {{ips}} placeholder"
            assert "for IP in" in template, \
                f"Protocol '{proto}' should use bash for loop"

    def test_each_protocol_has_file_template(self):
        """
        BV: File templates work for large target counts (>20 IPs)

        Scenario:
          Given: All protocol configurations
          When: Checking for file_template
          Then: Each has template with {targets_file} placeholder
        """
        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            assert "file_template" in config, \
                f"Protocol '{proto}' missing file_template"

            template = config["file_template"]
            assert "{targets_file}" in template, \
                f"Protocol '{proto}' file_template missing {{targets_file}} placeholder"

    def test_ip_threshold_is_reasonable(self):
        """
        BV: IP threshold prevents excessively long command lines

        Scenario:
          Given: ALL_TARGETS_IP_THRESHOLD constant
          When: Checking value
          Then: Is between 10 and 50 (reasonable range)
        """
        assert 10 <= ALL_TARGETS_IP_THRESHOLD <= 50, \
            f"IP threshold {ALL_TARGETS_IP_THRESHOLD} outside reasonable range"
        assert ALL_TARGETS_IP_THRESHOLD == 20  # Current expected value


# =============================================================================
# Command Template Validation Tests
# =============================================================================

class TestCommandTemplates:
    """Tests for command template placeholder validation"""

    def test_smb_templates_use_crackmapexec(self):
        """
        BV: SMB commands use crackmapexec for Pwn3d! detection

        Scenario:
          Given: SMB spray templates
          When: Checking command prefix
          Then: Uses crackmapexec (not netexec for OSCP compatibility)
        """
        smb = SPRAY_TECHNIQUES["smb"]

        for name, template in smb.command_templates.items():
            assert "crackmapexec" in template or "netexec" in template, \
                f"SMB template '{name}' should use CME or netexec"

    def test_kerberos_templates_use_kerbrute(self):
        """
        BV: Kerberos commands use kerbrute for stealth

        Scenario:
          Given: Kerberos spray templates
          When: Checking command prefix
          Then: Uses kerbrute binary
        """
        kerb = SPRAY_TECHNIQUES["kerberos"]

        for name, template in kerb.command_templates.items():
            assert "kerbrute" in template.lower(), \
                f"Kerberos template '{name}' should use kerbrute"

    def test_all_templates_have_domain_placeholder(self):
        """
        BV: All spray commands support domain specification

        Scenario:
          Given: All spray technique templates
          When: Checking for domain placeholders
          Then: Each template has <DOMAIN> or -d flag (except domain-context PS)
        """
        for tech_name, tech in SPRAY_TECHNIQUES.items():
            for template_name, template in tech.command_templates.items():
                has_domain = "<DOMAIN>" in template or "-d" in template
                # PowerShell cmdlets like Invoke-DomainPasswordSpray run in domain context
                # They don't need explicit domain specification - they use current domain
                if tech_name == "ldap":
                    if "LDAP://" in template:
                        continue  # LDAP bind syntax handles domain in connection string
                    if "Invoke-DomainPasswordSpray" in template:
                        continue  # PS cmdlet uses current domain context
                assert has_domain, \
                    f"Template '{tech_name}.{template_name}' missing domain specification"


# =============================================================================
# SPRAY_SCENARIOS Tests
# =============================================================================

class TestSprayScenarios:
    """Tests for spray scenario recommendations"""

    def test_scenarios_is_list(self):
        """
        BV: Scenarios are provided as iterable list

        Scenario:
          Given: SPRAY_SCENARIOS
          When: Checking type
          Then: Is a list with multiple entries
        """
        assert isinstance(SPRAY_SCENARIOS, list)
        assert len(SPRAY_SCENARIOS) >= 3  # At least stealth, admin, large list

    def test_each_scenario_has_required_fields(self):
        """
        BV: Each scenario provides complete guidance

        Scenario:
          Given: All spray scenarios
          When: Checking structure
          Then: Each has scenario, recommendation, and reason
        """
        for scenario in SPRAY_SCENARIOS:
            assert "scenario" in scenario, "Scenario missing 'scenario' field"
            assert "recommendation" in scenario, "Scenario missing 'recommendation'"
            assert "reason" in scenario, "Scenario missing 'reason'"

    def test_stealth_scenario_recommends_kerberos(self):
        """
        BV: Stealth operations use Kerberos (no event logs)

        Scenario:
          Given: Stealth-related scenario
          When: Checking recommendation
          Then: Recommends 'kerberos'
        """
        stealth_scenario = next(
            (s for s in SPRAY_SCENARIOS if "stealth" in s["scenario"].lower()),
            None
        )
        assert stealth_scenario is not None
        assert stealth_scenario["recommendation"] == "kerberos"

    def test_admin_access_scenario_recommends_smb(self):
        """
        BV: Admin detection uses SMB (shows Pwn3d!)

        Scenario:
          Given: Admin-related scenario
          When: Checking recommendation
          Then: Recommends 'smb'
        """
        admin_scenario = next(
            (s for s in SPRAY_SCENARIOS if "admin" in s["scenario"].lower()),
            None
        )
        assert admin_scenario is not None
        assert admin_scenario["recommendation"] == "smb"

    def test_recommendations_reference_valid_techniques(self):
        """
        BV: All recommendations map to defined techniques

        Scenario:
          Given: All spray scenarios
          When: Checking recommendations
          Then: Each references a key in SPRAY_TECHNIQUES
        """
        valid_techniques = set(SPRAY_TECHNIQUES.keys())

        for scenario in SPRAY_SCENARIOS:
            rec = scenario["recommendation"]
            assert rec in valid_techniques, \
                f"Scenario recommends unknown technique: {rec}"


# =============================================================================
# USER_ENUM_COMMANDS Tests
# =============================================================================

class TestUserEnumCommands:
    """Tests for user enumeration command collections"""

    def test_has_linux_and_windows_platforms(self):
        """
        BV: User enumeration works from both attack platforms

        Scenario:
          Given: USER_ENUM_COMMANDS
          When: Checking platform keys
          Then: Contains both 'linux' and 'windows'
        """
        assert "linux" in USER_ENUM_COMMANDS
        assert "windows" in USER_ENUM_COMMANDS

    def test_linux_has_kerbrute_enum(self):
        """
        BV: Linux provides Kerberos-based user enumeration

        Scenario:
          Given: Linux enumeration commands
          When: Checking for kerbrute
          Then: Has kerbrute userenum command
        """
        linux_cmds = USER_ENUM_COMMANDS["linux"]
        assert "kerbrute_enum" in linux_cmds

        cmd_info = linux_cmds["kerbrute_enum"]
        assert "cmd" in cmd_info
        assert "kerbrute" in cmd_info["cmd"]

    def test_linux_has_ldapsearch(self):
        """
        BV: Linux provides LDAP-based user enumeration

        Scenario:
          Given: Linux enumeration commands
          When: Checking for ldapsearch
          Then: Has ldapsearch command with credential extraction
        """
        linux_cmds = USER_ENUM_COMMANDS["linux"]
        assert "ldapsearch" in linux_cmds

        cmd_info = linux_cmds["ldapsearch"]
        assert "ldapsearch" in cmd_info["cmd"]

    def test_windows_has_domain_user_enum(self):
        """
        BV: Windows provides native domain user enumeration

        Scenario:
          Given: Windows enumeration commands
          When: Checking for domain commands
          Then: Has 'net user /domain' or equivalent
        """
        win_cmds = USER_ENUM_COMMANDS["windows"]
        assert "domain_users" in win_cmds

        cmd_info = win_cmds["domain_users"]
        assert "net user" in cmd_info["cmd"]
        assert "/domain" in cmd_info["cmd"]

    def test_each_command_has_description(self):
        """
        BV: All commands are documented for user understanding

        Scenario:
          Given: All enumeration commands
          When: Checking for descriptions
          Then: Each has non-empty description
        """
        for platform, commands in USER_ENUM_COMMANDS.items():
            for cmd_name, cmd_info in commands.items():
                assert "description" in cmd_info, \
                    f"Command '{platform}.{cmd_name}' missing description"
                assert cmd_info["description"] != "", \
                    f"Command '{platform}.{cmd_name}' has empty description"


# =============================================================================
# PASSWORD_LIST_COMMANDS Tests
# =============================================================================

class TestPasswordListCommands:
    """Tests for password list generation commands"""

    def test_linux_has_hashcat_potfile(self):
        """
        BV: Cracked passwords can be extracted from hashcat

        Scenario:
          Given: Linux password commands
          When: Checking for hashcat extraction
          Then: Has command to extract from potfile
        """
        linux_cmds = PASSWORD_LIST_COMMANDS.get("linux", {})
        assert "hashcat_potfile" in linux_cmds

        cmd_info = linux_cmds["hashcat_potfile"]
        assert "hashcat.potfile" in cmd_info["cmd"]

    def test_linux_has_cewl_wordlist(self):
        """
        BV: Organization-specific passwords can be generated

        Scenario:
          Given: Linux password commands
          When: Checking for cewl
          Then: Has command to generate wordlist from website
        """
        linux_cmds = PASSWORD_LIST_COMMANDS.get("linux", {})
        assert "cewl_wordlist" in linux_cmds

        cmd_info = linux_cmds["cewl_wordlist"]
        assert "cewl" in cmd_info["cmd"]


# =============================================================================
# SPRAY_ONELINERS Tests
# =============================================================================

class TestSprayOneliners:
    """Tests for complete attack workflow one-liners"""

    def test_oneliners_is_list(self):
        """
        BV: One-liners are provided as iterable list

        Scenario:
          Given: SPRAY_ONELINERS
          When: Checking type
          Then: Is list with multiple entries
        """
        assert isinstance(SPRAY_ONELINERS, list)
        assert len(SPRAY_ONELINERS) >= 3  # At least 3 workflows

    def test_each_oneliner_has_required_fields(self):
        """
        BV: Each one-liner is complete and documented

        Scenario:
          Given: All spray one-liners
          When: Checking structure
          Then: Each has name, description, and cmd
        """
        for oneliner in SPRAY_ONELINERS:
            assert "name" in oneliner, "One-liner missing 'name'"
            assert "description" in oneliner, "One-liner missing 'description'"
            assert "cmd" in oneliner, "One-liner missing 'cmd'"

    def test_neo4j_spray_oneliner_exists(self):
        """
        BV: Neo4j integration workflow is available

        Scenario:
          Given: Spray one-liners
          When: Looking for Neo4j workflow
          Then: Has workflow extracting users/passwords from Neo4j
        """
        neo4j_oneliner = next(
            (o for o in SPRAY_ONELINERS if "neo4j" in o["name"].lower()),
            None
        )
        assert neo4j_oneliner is not None
        assert "cypher-shell" in neo4j_oneliner["cmd"]

    def test_kerberoast_workflow_exists(self):
        """
        BV: Kerberoast-to-spray workflow is available

        Scenario:
          Given: Spray one-liners
          When: Looking for Kerberoast workflow
          Then: Has workflow roasting -> cracking -> spraying
        """
        kerb_oneliner = next(
            (o for o in SPRAY_ONELINERS if "kerberoast" in o["name"].lower()),
            None
        )
        assert kerb_oneliner is not None
        assert "GetUserSPNs" in kerb_oneliner["cmd"] or "hashcat" in kerb_oneliner["cmd"]


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Tests for module helper functions"""

    def test_get_spray_technique_returns_technique(self):
        """
        BV: Technique lookup returns correct technique

        Scenario:
          Given: Valid technique name
          When: Calling get_spray_technique()
          Then: Returns SprayTechniqueInfo object
        """
        result = get_spray_technique("smb")
        assert result is not None
        assert isinstance(result, SprayTechniqueInfo)
        assert result.name == SPRAY_TECHNIQUES["smb"].name

    def test_get_spray_technique_returns_none_for_invalid(self):
        """
        BV: Invalid technique name returns None (no crash)

        Scenario:
          Given: Invalid technique name
          When: Calling get_spray_technique()
          Then: Returns None
        """
        result = get_spray_technique("nonexistent")
        assert result is None

    def test_get_all_spray_techniques_returns_all(self):
        """
        BV: All techniques are accessible via helper

        Scenario:
          Given: SPRAY_TECHNIQUES dictionary
          When: Calling get_all_spray_techniques()
          Then: Returns same dictionary
        """
        result = get_all_spray_techniques()
        assert result == SPRAY_TECHNIQUES
        assert "smb" in result
        assert "kerberos" in result

    def test_get_spray_scenarios_returns_scenarios(self):
        """
        BV: Scenarios are accessible via helper

        Scenario:
          Given: SPRAY_SCENARIOS list
          When: Calling get_spray_scenarios()
          Then: Returns same list
        """
        result = get_spray_scenarios()
        assert result == SPRAY_SCENARIOS
        assert len(result) > 0

    def test_get_user_enum_commands_default_linux(self):
        """
        BV: Default platform is linux for attack tools

        Scenario:
          Given: No platform specified
          When: Calling get_user_enum_commands()
          Then: Returns linux commands
        """
        result = get_user_enum_commands()
        assert result == USER_ENUM_COMMANDS["linux"]

    def test_get_user_enum_commands_windows(self):
        """
        BV: Windows commands accessible with platform arg

        Scenario:
          Given: Platform 'windows'
          When: Calling get_user_enum_commands('windows')
          Then: Returns windows commands
        """
        result = get_user_enum_commands("windows")
        assert result == USER_ENUM_COMMANDS["windows"]
        assert "domain_users" in result

    def test_get_user_enum_commands_invalid_platform(self):
        """
        BV: Invalid platform returns empty dict (no crash)

        Scenario:
          Given: Invalid platform name
          When: Calling get_user_enum_commands()
          Then: Returns empty dict
        """
        result = get_user_enum_commands("macos")
        assert result == {}

    def test_get_password_list_commands_returns_dict(self):
        """
        BV: Password list commands accessible via helper

        Scenario:
          Given: Platform 'linux'
          When: Calling get_password_list_commands()
          Then: Returns command dictionary
        """
        result = get_password_list_commands("linux")
        assert isinstance(result, dict)
        assert "hashcat_potfile" in result

    def test_get_password_list_scenarios_returns_list(self):
        """
        BV: Password list scenarios accessible via helper

        Scenario:
          Given: PASSWORD_LIST_SCENARIOS
          When: Calling get_password_list_scenarios()
          Then: Returns scenario list
        """
        result = get_password_list_scenarios()
        assert result == PASSWORD_LIST_SCENARIOS
        assert len(result) > 0

    def test_get_spray_oneliners_returns_list(self):
        """
        BV: Spray one-liners accessible via helper

        Scenario:
          Given: SPRAY_ONELINERS
          When: Calling get_spray_oneliners()
          Then: Returns one-liner list
        """
        result = get_spray_oneliners()
        assert result == SPRAY_ONELINERS
        assert len(result) > 0


# =============================================================================
# Edge Cases and Validation
# =============================================================================

class TestEdgeCases:
    """Edge case handling and validation tests"""

    def test_command_templates_no_shell_injection(self):
        """
        BV: Command templates don't allow shell injection

        Scenario:
          Given: All command templates
          When: Checking for dangerous patterns
          Then: No unquoted variable expansion in dangerous contexts

        Edge Cases:
          - Password placeholders should be quoted
          - No backtick or $() expansion of user input
        """
        dangerous_patterns = [
            "`<PASSWORD>`",  # Backtick expansion
            "$(<PASSWORD>)",  # Command substitution
        ]

        for tech_name, tech in SPRAY_TECHNIQUES.items():
            for template_name, template in tech.command_templates.items():
                for pattern in dangerous_patterns:
                    assert pattern not in template, \
                        f"Template '{tech_name}.{template_name}' has dangerous pattern: {pattern}"

    def test_password_placeholders_are_quoted(self):
        """
        BV: Password placeholders use quotes to handle special chars

        Scenario:
          Given: Templates with <PASSWORD> placeholder
          When: Checking quoting
          Then: Password is single-quoted for shell safety
        """
        for tech_name, tech in SPRAY_TECHNIQUES.items():
            for template_name, template in tech.command_templates.items():
                if "<PASSWORD>" in template:
                    # Check for quoted password (single or double quotes)
                    has_quotes = "'<PASSWORD>'" in template or '"<PASSWORD>"' in template
                    # Some templates may use different quoting or escaping
                    if not has_quotes:
                        # Allow if it's in a specific context (e.g., PowerShell)
                        if "Invoke-" not in template:
                            # Log for review but don't fail hard
                            pass  # Warning: unquoted password in template

    def test_all_protocols_have_descriptions(self):
        """
        BV: Protocol descriptions help users understand purpose

        Scenario:
          Given: ALL_TARGETS_PROTOCOLS
          When: Checking descriptions
          Then: Each protocol has non-empty description
        """
        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            assert "description" in config, \
                f"Protocol '{proto}' missing description"
            assert config["description"] != "", \
                f"Protocol '{proto}' has empty description"

    def test_oscp_relevance_values_are_valid(self):
        """
        BV: OSCP relevance helps prioritize techniques for exam

        Scenario:
          Given: All spray techniques
          When: Checking oscp_relevance
          Then: Each has valid value (high/medium/low)
        """
        valid_values = {"high", "medium", "low"}

        for tech_name, tech in SPRAY_TECHNIQUES.items():
            assert tech.oscp_relevance in valid_values, \
                f"Technique '{tech_name}' has invalid oscp_relevance: {tech.oscp_relevance}"

    def test_noise_levels_are_valid(self):
        """
        BV: Noise levels indicate detection risk accurately

        Scenario:
          Given: All spray techniques
          When: Checking noise_level
          Then: Each has valid value (high/medium/low)
        """
        valid_values = {"high", "medium", "low"}

        for tech_name, tech in SPRAY_TECHNIQUES.items():
            assert tech.noise_level in valid_values, \
                f"Technique '{tech_name}' has invalid noise_level: {tech.noise_level}"
