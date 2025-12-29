"""
Tests for Autospray Result Parser

Business Value Focus:
- Parse spray tool output to identify successful authentications
- Support multiple tools (CrackMapExec, NetExec, Kerbrute, Hydra)
- Detect admin access for privilege escalation

Test Priority: TIER 1 - CRITICAL (Core Credential Discovery)
"""

import pytest
from tools.post.bloodtrail.autospray.result_parser import (
    ResultParser, ParsedResult, SprayTool
)


# =============================================================================
# Sample Tool Output
# =============================================================================

# CrackMapExec/NetExec SMB output
CME_OUTPUT = """SMB         192.168.50.70   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:corp.com) (signing:True) (SMBv1:False)
SMB         192.168.50.70   445    DC01             [-] corp.com\\wronguser:BadPassword STATUS_LOGON_FAILURE
SMB         192.168.50.70   445    DC01             [+] corp.com\\pete:Summer2024! (Pwn3d!)
SMB         192.168.50.70   445    DC01             [+] corp.com\\john:Password1!
"""

# NetExec output with admin
NETEXEC_OUTPUT = """SMB         192.168.1.100   445    TARGET           [*] Windows Server 2019 x64 (name:TARGET) (domain:CORP) (signing:True)
SMB         192.168.1.100   445    TARGET           [+] CORP\\admin:AdminPass123! (Pwn3d!)
SMB         192.168.1.100   445    TARGET           [+] CORP\\regularuser:UserPass!
"""

# Kerbrute output
KERBRUTE_OUTPUT = """
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/

Version: v1.0.3 (9dad6e1) - 12/25/24 - Ronnie Flathers @ropnop

2024/12/25 10:00:00 >  Using KDC(s):
2024/12/25 10:00:00 >   192.168.50.70:88

2024/12/25 10:00:01 >  [+] VALID LOGIN:	 pete@corp.com:Summer2024!
2024/12/25 10:00:01 >  [+] VALID LOGIN:	 jen@corp.com:Password1!
2024/12/25 10:00:02 >  Done! Tested 100 passwords for 50 users with 2 valid logins
"""

# Hydra output
HYDRA_OUTPUT = """Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

[DATA] max 16 tasks per 1 server, overall 16 tasks, 5 login tries (l:5/p:1), ~1 try per task
[445][smb] host: 192.168.50.70   login: Administrator   password: AdminPass!
[445][smb] host: 192.168.50.70   login: testuser   password: TestPass123
"""

# Mixed/failed output (no successful logins)
FAILED_OUTPUT = """SMB         192.168.50.70   445    DC01             [-] corp.com\\user1:Password1 STATUS_LOGON_FAILURE
SMB         192.168.50.70   445    DC01             [-] corp.com\\user2:Password1 STATUS_LOGON_FAILURE
SMB         192.168.50.70   445    DC01             [-] corp.com\\user3:Password1 STATUS_LOGON_FAILURE
"""


# =============================================================================
# CrackMapExec/NetExec Parsing Tests
# =============================================================================

class TestCMEParsing:
    """Tests for CrackMapExec/NetExec output parsing"""

    def test_parse_cme_success(self):
        """
        BV: Parse CME successful authentication

        Scenario:
          Given: CME output with successful login
          When: parse_output() is called
          Then: Credentials extracted
        """
        results = ResultParser.parse_output(CME_OUTPUT, SprayTool.CRACKMAPEXEC)

        assert len(results) == 2

    def test_parse_cme_extracts_username(self):
        """
        BV: Extract username from CME output

        Scenario:
          Given: CME successful login line
          When: parse_line() is called
          Then: Username extracted
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\pete:Summer2024! (Pwn3d!)"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.username == "pete"

    def test_parse_cme_extracts_password(self):
        """
        BV: Extract password from CME output

        Scenario:
          Given: CME successful login line
          When: parse_line() is called
          Then: Password extracted
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\pete:Summer2024!"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.password == "Summer2024!"

    def test_parse_cme_extracts_target(self):
        """
        BV: Extract target IP from CME output

        Scenario:
          Given: CME successful login line
          When: parse_line() is called
          Then: Target IP extracted
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\pete:Summer2024!"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.target == "192.168.50.70"

    def test_parse_cme_extracts_domain(self):
        """
        BV: Extract domain from CME output

        Scenario:
          Given: CME output with domain\\user
          When: parse_line() is called
          Then: Domain extracted
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\pete:Summer2024!"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.domain == "corp.com"

    def test_parse_cme_detects_admin(self):
        """
        BV: Detect admin access (Pwn3d!)

        Scenario:
          Given: CME output with (Pwn3d!) marker
          When: parse_line() is called
          Then: is_admin is True
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\admin:Pass123! (Pwn3d!)"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.is_admin is True

    def test_parse_cme_non_admin(self):
        """
        BV: Non-admin user detected correctly

        Scenario:
          Given: CME output without (Pwn3d!)
          When: parse_line() is called
          Then: is_admin is False
        """
        line = "SMB         192.168.50.70   445    DC01             [+] corp.com\\user:Pass123!"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is not None
        assert result.is_admin is False

    def test_parse_cme_ignores_failed(self):
        """
        BV: Skip failed login attempts

        Scenario:
          Given: CME output with [-] failed login
          When: parse_line() is called
          Then: Returns None
        """
        line = "SMB         192.168.50.70   445    DC01             [-] corp.com\\user:BadPass STATUS_LOGON_FAILURE"
        result = ResultParser.parse_line(line, SprayTool.CRACKMAPEXEC)

        assert result is None


# =============================================================================
# Kerbrute Parsing Tests
# =============================================================================

class TestKerbruteParsing:
    """Tests for Kerbrute output parsing"""

    def test_parse_kerbrute_success(self):
        """
        BV: Parse Kerbrute successful authentication

        Scenario:
          Given: Kerbrute output with valid logins
          When: parse_output() is called
          Then: Credentials extracted
        """
        results = ResultParser.parse_output(KERBRUTE_OUTPUT, SprayTool.KERBRUTE)

        assert len(results) == 2

    def test_parse_kerbrute_extracts_username(self):
        """
        BV: Extract username from Kerbrute output

        Scenario:
          Given: Kerbrute VALID LOGIN line
          When: parse_line() is called
          Then: Username extracted
        """
        line = "2024/12/25 10:00:01 >  [+] VALID LOGIN:	 pete@corp.com:Summer2024!"
        result = ResultParser.parse_line(line, SprayTool.KERBRUTE)

        assert result is not None
        assert result.username == "pete"

    def test_parse_kerbrute_extracts_domain(self):
        """
        BV: Extract domain from Kerbrute output

        Scenario:
          Given: Kerbrute user@domain format
          When: parse_line() is called
          Then: Domain extracted
        """
        line = "[+] VALID LOGIN:	 pete@corp.com:Summer2024!"
        result = ResultParser.parse_line(line, SprayTool.KERBRUTE)

        assert result is not None
        assert result.domain == "corp.com"


# =============================================================================
# Hydra Parsing Tests
# =============================================================================

class TestHydraParsing:
    """Tests for Hydra output parsing"""

    def test_parse_hydra_success(self):
        """
        BV: Parse Hydra successful authentication

        Scenario:
          Given: Hydra output with successful logins
          When: parse_output() is called
          Then: Credentials extracted
        """
        results = ResultParser.parse_output(HYDRA_OUTPUT, SprayTool.HYDRA)

        assert len(results) == 2

    def test_parse_hydra_extracts_username(self):
        """
        BV: Extract username from Hydra output

        Scenario:
          Given: Hydra success line
          When: parse_line() is called
          Then: Username extracted
        """
        line = "[445][smb] host: 192.168.50.70   login: Administrator   password: AdminPass!"
        result = ResultParser.parse_line(line, SprayTool.HYDRA)

        assert result is not None
        assert result.username == "Administrator"

    def test_parse_hydra_extracts_target(self):
        """
        BV: Extract target from Hydra output

        Scenario:
          Given: Hydra success line
          When: parse_line() is called
          Then: Target IP extracted
        """
        line = "[445][smb] host: 192.168.50.70   login: testuser   password: TestPass!"
        result = ResultParser.parse_line(line, SprayTool.HYDRA)

        assert result is not None
        assert result.target == "192.168.50.70"


# =============================================================================
# Tool Detection Tests
# =============================================================================

class TestToolDetection:
    """Tests for automatic tool detection"""

    def test_detect_cme_from_output(self):
        """
        BV: Auto-detect CrackMapExec from output

        Scenario:
          Given: CME output
          When: detect_tool_from_output() is called
          Then: Returns CRACKMAPEXEC
        """
        result = ResultParser.detect_tool_from_output(CME_OUTPUT)

        assert result == SprayTool.CRACKMAPEXEC

    def test_detect_netexec_from_output(self):
        """
        BV: Auto-detect NetExec from output

        Scenario:
          Given: NetExec output with netexec indicator
          When: detect_tool_from_output() is called
          Then: Returns NETEXEC
        """
        output = "netexec smb 192.168.1.100 445 [+] CORP\\admin:Pass!"
        result = ResultParser.detect_tool_from_output(output)

        assert result == SprayTool.NETEXEC

    def test_detect_kerbrute_from_output(self):
        """
        BV: Auto-detect Kerbrute from output

        Scenario:
          Given: Kerbrute output
          When: detect_tool_from_output() is called
          Then: Returns KERBRUTE
        """
        result = ResultParser.detect_tool_from_output(KERBRUTE_OUTPUT)

        assert result == SprayTool.KERBRUTE

    def test_detect_hydra_from_output(self):
        """
        BV: Auto-detect Hydra from output

        Scenario:
          Given: Hydra output (without SMB port)
          When: detect_tool_from_output() is called
          Then: Returns HYDRA
        """
        # Use Hydra-specific output without 445 (which triggers CME detection)
        hydra_only = """Hydra v9.4 (c) 2022 by van Hauser/THC
[22][ssh] host: 192.168.1.100   login: admin   password: Pass123!
"""
        result = ResultParser.detect_tool_from_output(hydra_only)

        assert result == SprayTool.HYDRA


# =============================================================================
# ParsedResult Tests
# =============================================================================

class TestParsedResult:
    """Tests for ParsedResult dataclass"""

    def test_str_with_domain(self):
        """
        BV: String representation with domain

        Scenario:
          Given: ParsedResult with domain
          When: Converting to string
          Then: Shows domain\\user format
        """
        result = ParsedResult(
            username="admin",
            password="Pass123!",
            target="192.168.1.100",
            domain="CORP"
        )

        assert str(result) == "CORP\\admin:Pass123!@192.168.1.100"

    def test_str_without_domain(self):
        """
        BV: String representation without domain

        Scenario:
          Given: ParsedResult without domain
          When: Converting to string
          Then: Shows user format only
        """
        result = ParsedResult(
            username="admin",
            password="Pass123!",
            target="192.168.1.100"
        )

        assert str(result) == "admin:Pass123!@192.168.1.100"

    def test_str_with_admin(self):
        """
        BV: String shows admin marker

        Scenario:
          Given: ParsedResult with is_admin=True
          When: Converting to string
          Then: Shows (ADMIN) marker
        """
        result = ParsedResult(
            username="admin",
            password="Pass123!",
            target="192.168.1.100",
            is_admin=True
        )

        assert "(ADMIN)" in str(result)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_output(self):
        """
        BV: Handle empty output gracefully

        Scenario:
          Given: Empty string
          When: parse_output() is called
          Then: Returns empty list
        """
        results = ResultParser.parse_output("", SprayTool.CRACKMAPEXEC)

        assert results == []

    def test_failed_only_output(self):
        """
        BV: Handle output with no successes

        Scenario:
          Given: Output with only failed logins
          When: parse_output() is called
          Then: Returns empty list
        """
        results = ResultParser.parse_output(FAILED_OUTPUT, SprayTool.CRACKMAPEXEC)

        assert results == []

    def test_deduplicates_users(self):
        """
        BV: Avoid duplicate usernames in results

        Scenario:
          Given: Output with same user twice
          When: parse_output() is called
          Then: User appears once
        """
        duplicate_output = """SMB  192.168.1.100   445    DC01  [+] CORP\\admin:Pass1!
SMB  192.168.1.100   445    DC01  [+] CORP\\admin:Pass1!
"""
        results = ResultParser.parse_output(duplicate_output, SprayTool.CRACKMAPEXEC)

        assert len(results) == 1

    def test_parse_empty_line(self):
        """
        BV: Handle empty lines gracefully

        Scenario:
          Given: Empty line
          When: parse_line() is called
          Then: Returns None
        """
        result = ResultParser.parse_line("", SprayTool.CRACKMAPEXEC)

        assert result is None

    def test_undetectable_tool(self):
        """
        BV: Handle unrecognized output

        Scenario:
          Given: Output that doesn't match any tool
          When: detect_tool_from_output() is called
          Then: Returns None
        """
        result = ResultParser.detect_tool_from_output("random text with no patterns")

        assert result is None
