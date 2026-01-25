"""
Tests for OutputParser module.

Tests parsing of common pentesting tool outputs:
- AS-REP roast (GetNPUsers)
- Kerberoast (GetUserSPNs)
- Hashcat
- John the Ripper
- Evil-WinRM
- CrackMapExec
- Secretsdump
- BloodHound-python
"""

import pytest
from tools.post.bloodtrail.wizard.output_parser import OutputParser, ParseResult


class TestParseASREPOutput:
    """Tests for AS-REP hash extraction."""

    def test_extracts_hash_from_getnpusers_output(self):
        """Should extract AS-REP hash from GetNPUsers output."""
        output = """
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:ac08796d119473bbc064db26faebd459$24f53874cd3a831a351af72d873ea7c93cfea5b10cb39c73f0af32b1920c43e8b70c99a4b17d7b9cd50a45dee5c5d01498b80d415aada30f6e235aa9d0b04649450a9e7dc9f425dba8c03a6f11d54c9c242c8a84eac636127d23ca2d3dcbcea12f1cccba84b6c048da75598ec38c232371c94dc8b0c8f82f3dbd85b8a5ac356d866ed31d356c11f7d5d96379c7497748bf868784683d373a8f117d3e20d859c1bcb247497d9584d17e52e1174a90a5e7226989635c3d9cfe810ae9737c9bcd4f66e4f3229f2088ff63bacb9544d16e0125ee82ae60614ba61c7e9951b153698ced17ff7a6d4d
"""
        result = OutputParser.parse_asrep_output(output)

        assert result.success is True
        assert "hash" in result.extracted_data
        assert result.extracted_data["hash"].startswith("$krb5asrep$23$")
        assert result.extracted_data["hash_type"] == "asrep"
        assert result.extracted_data["username"] == "svc-alfresco"
        assert result.next_action == "crack_hash"

    def test_returns_failure_when_no_hash_found(self):
        """Should return failure when no hash in output."""
        output = """
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for admin
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
"""
        result = OutputParser.parse_asrep_output(output)

        assert result.success is False
        assert result.extracted_data == {}


class TestParseKerberoastOutput:
    """Tests for Kerberoast TGS hash extraction."""

    def test_extracts_tgs_hash(self):
        """Should extract TGS-REP hash from GetUserSPNs output."""
        output = """
$krb5tgs$23$*sqlservice$HTB.LOCAL$http/web.htb.local*$abc123def456...
"""
        result = OutputParser.parse_kerberoast_output(output)

        assert result.success is True
        assert "hash" in result.extracted_data
        assert result.extracted_data["hash"].startswith("$krb5tgs$")
        assert result.extracted_data["hash_type"] == "kerberoast"
        assert result.next_action == "crack_hash"


class TestParseHashcatOutput:
    """Tests for hashcat cracked password extraction."""

    def test_extracts_cracked_password(self):
        """Should extract password from hashcat cracked output."""
        output = """
$krb5asrep$23$svc-alfresco@HTB.LOCAL:salt$hash:s3rvice
"""
        result = OutputParser.parse_hashcat_output(output)

        assert result.success is True
        assert result.extracted_data["password"] == "s3rvice"
        assert result.next_action == "test_cracked_credential"

    def test_detects_cracked_status(self):
        """Should detect when hashcat shows Cracked status."""
        output = """
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
"""
        result = OutputParser.parse_hashcat_output(output)

        assert result.success is True
        assert result.extracted_data.get("needs_show") is True

    def test_returns_failure_when_exhausted(self):
        """Should return failure when wordlist exhausted."""
        output = """
Session..........: hashcat
Status...........: Exhausted
"""
        result = OutputParser.parse_hashcat_output(output)

        assert result.success is False


class TestParseJohnOutput:
    """Tests for John the Ripper output parsing."""

    def test_extracts_cracked_password_john_format(self):
        """Should extract password from John's output format."""
        output = """
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP)
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
Session completed.
"""
        result = OutputParser.parse_john_output(output)

        assert result.success is True
        assert result.extracted_data["password"] == "s3rvice"


class TestParseWinRMOutput:
    """Tests for evil-winrm output parsing."""

    def test_detects_successful_shell(self):
        """Should detect successful WinRM shell connection."""
        output = """
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\\Users\\svc-alfresco\\Documents>
"""
        result = OutputParser.parse_winrm_output(output)

        assert result.success is True
        assert result.extracted_data["access_level"] == "user"
        assert result.extracted_data["shell_type"] == "winrm"
        assert result.next_action == "collect_bloodhound"

    def test_detects_auth_failure(self):
        """Should detect authentication failure."""
        output = """
Evil-WinRM shell v3.7
Error: WinRM::WinRMAuthorizationError
"""
        result = OutputParser.parse_winrm_output(output)

        assert result.success is False
        assert result.extracted_data.get("error") == "auth_failed"


class TestParseCrackMapExecOutput:
    """Tests for CrackMapExec output parsing."""

    def test_detects_valid_credential(self):
        """Should detect valid but non-admin credential."""
        output = """
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016
SMB         10.10.10.161    445    FOREST           [+] HTB.LOCAL\\svc-alfresco:s3rvice
"""
        result = OutputParser.parse_crackmapexec_output(output)

        assert result.success is True
        assert result.extracted_data["access_level"] == "user"
        assert result.extracted_data["pwned"] is False

    def test_detects_pwned_admin(self):
        """Should detect admin access with Pwn3d!."""
        output = """
SMB         10.10.10.161    445    FOREST           [+] HTB.LOCAL\\admin:password (Pwn3d!)
"""
        result = OutputParser.parse_crackmapexec_output(output)

        assert result.success is True
        assert result.extracted_data["access_level"] == "admin"
        assert result.extracted_data["pwned"] is True

    def test_detects_invalid_credential(self):
        """Should detect invalid credentials."""
        output = """
SMB         10.10.10.161    445    FOREST           [-] HTB.LOCAL\\user:wrongpass STATUS_LOGON_FAILURE
"""
        result = OutputParser.parse_crackmapexec_output(output)

        assert result.success is False
        assert result.extracted_data.get("error") == "invalid_creds"


class TestParseSecretsdumpOutput:
    """Tests for secretsdump output parsing."""

    def test_extracts_administrator_hash(self):
        """Should extract Administrator NTLM hash."""
        output = """
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
"""
        result = OutputParser.parse_secretsdump_output(output)

        assert result.success is True
        assert result.extracted_data["admin_hash"] == "32693b11e6aa90eb43d32c72a07ceea6"
        assert "aad3b435b51404eeaad3b435b51404ee" in result.extracted_data["full_hash"]
        assert result.next_action == "pass_the_hash"


class TestParseBloodhoundOutput:
    """Tests for bloodhound-python output parsing."""

    def test_detects_successful_collection(self):
        """Should detect successful BloodHound collection."""
        output = """
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP
INFO: Writing users.json
INFO: Writing computers.json
INFO: Writing groups.json
INFO: Done in 00:00:45
"""
        result = OutputParser.parse_bloodhound_output(output)

        assert result.success is True
        assert result.extracted_data["collection_complete"] is True
        assert result.extracted_data["json_files"] >= 3


class TestParseOutputAutoDetect:
    """Tests for auto-detection of parser."""

    def test_selects_asrep_parser_for_getnpusers(self):
        """Should auto-select AS-REP parser for GetNPUsers command."""
        command = "impacket-GetNPUsers HTB.LOCAL/user -no-pass"
        output = "$krb5asrep$23$user@HTB.LOCAL:hash..."

        result = OutputParser.parse_output(command, output)

        assert result.success is True
        assert result.extracted_data.get("hash_type") == "asrep"

    def test_selects_hashcat_parser_for_hashcat_command(self):
        """Should auto-select hashcat parser."""
        command = "hashcat -m 18200 hash.txt rockyou.txt"
        output = "$krb5asrep$23$user@HTB.LOCAL:salt:password123"

        result = OutputParser.parse_output(command, output)

        assert result.success is True

    def test_selects_cme_parser_for_crackmapexec(self):
        """Should auto-select CME parser."""
        command = "crackmapexec smb 10.10.10.161 -u user -p pass"
        output = "[+] DOMAIN\\user:pass"

        result = OutputParser.parse_output(command, output)

        assert result.success is True

    def test_uses_attack_type_hint(self):
        """Should use attack_type hint for parser selection."""
        output = "$krb5asrep$23$user@HTB.LOCAL:hash..."

        result = OutputParser.parse_output(
            command="",
            output=output,
            attack_type="asrep_roast"
        )

        assert result.success is True
        assert result.extracted_data.get("hash_type") == "asrep"
