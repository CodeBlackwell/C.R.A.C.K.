"""
Tests for Pwned Tracker Data Models

Business Value Focus:
- Track compromised users with credentials
- Model machine access paths
- Store pwned operation results

Test Priority: TIER 2 - HIGH (AD Exploitation)
"""

import pytest
from datetime import datetime
from tools.post.bloodtrail.pwned_tracker import (
    MachineAccess,
    PwnedUser,
    PwnedResult,
    EDGE_TO_PRIVILEGE,
    DOMAIN_ADMIN_EDGES,
    CRED_TYPES,
)


# =============================================================================
# MachineAccess Tests
# =============================================================================

class TestMachineAccess:
    """Tests for MachineAccess dataclass"""

    def test_basic_creation(self):
        """
        BV: Create MachineAccess with required fields

        Scenario:
          Given: Computer name and access info
          When: Creating MachineAccess
          Then: Object created with fields
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
        )

        assert access.computer == "DC01.CORP.COM"
        assert "AdminTo" in access.access_types
        assert access.privilege_level == "local-admin"

    def test_default_sessions_empty(self):
        """
        BV: Sessions default to empty

        Scenario:
          Given: MachineAccess without sessions
          When: Checking sessions
          Then: Empty list
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
        )

        assert access.sessions == []

    def test_sessions_with_privileged_users(self):
        """
        BV: Track privileged sessions

        Scenario:
          Given: MachineAccess with sessions
          When: Checking sessions
          Then: Contains privileged users
        """
        access = MachineAccess(
            computer="CLIENT01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
            sessions=["ADMIN@CORP.COM", "DA@CORP.COM"],
        )

        assert len(access.sessions) == 2
        assert "ADMIN@CORP.COM" in access.sessions

    def test_multiple_access_types(self):
        """
        BV: Track multiple access types

        Scenario:
          Given: Machine with multiple access
          When: Creating MachineAccess
          Then: All types tracked
        """
        access = MachineAccess(
            computer="SERVER01.CORP.COM",
            access_types=["AdminTo", "CanRDP", "CanPSRemote"],
            privilege_level="local-admin",
        )

        assert len(access.access_types) == 3
        assert "CanRDP" in access.access_types

    def test_computer_ip_optional(self):
        """
        BV: Computer IP is optional

        Scenario:
          Given: MachineAccess without IP
          When: Checking computer_ip
          Then: None
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
        )

        assert access.computer_ip is None

    def test_computer_ip_set(self):
        """
        BV: Track resolved IP

        Scenario:
          Given: MachineAccess with IP
          When: Checking computer_ip
          Then: Contains IP
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
            computer_ip="192.168.1.10",
        )

        assert access.computer_ip == "192.168.1.10"


# =============================================================================
# PwnedUser Tests
# =============================================================================

class TestPwnedUser:
    """Tests for PwnedUser dataclass"""

    def test_basic_creation(self):
        """
        BV: Create PwnedUser with required fields

        Scenario:
          Given: User name and timestamp
          When: Creating PwnedUser
          Then: Object created
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.name == "PETE@CORP.COM"
        assert user.pwned_at is not None

    def test_default_cred_lists(self):
        """
        BV: Credential lists default to empty

        Scenario:
          Given: PwnedUser without creds
          When: Checking cred lists
          Then: Empty lists
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.cred_types == []
        assert user.cred_values == []

    def test_cred_type_property(self):
        """
        BV: cred_type returns primary type

        Scenario:
          Given: PwnedUser with multiple creds
          When: Getting cred_type
          Then: Returns first type
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password", "ntlm-hash"],
            cred_values=["Summer2024!", "abc123hash"],
        )

        assert user.cred_type == "password"

    def test_cred_type_default(self):
        """
        BV: cred_type defaults to password

        Scenario:
          Given: PwnedUser without creds
          When: Getting cred_type
          Then: Returns 'password'
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.cred_type == "password"

    def test_cred_value_property(self):
        """
        BV: cred_value returns primary value

        Scenario:
          Given: PwnedUser with creds
          When: Getting cred_value
          Then: Returns first value
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password"],
            cred_values=["Summer2024!"],
        )

        assert user.cred_value == "Summer2024!"

    def test_cred_value_default(self):
        """
        BV: cred_value defaults to empty

        Scenario:
          Given: PwnedUser without creds
          When: Getting cred_value
          Then: Returns empty string
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.cred_value == ""

    def test_get_credential(self):
        """
        BV: Get credential by type

        Scenario:
          Given: PwnedUser with multiple creds
          When: Getting specific type
          Then: Returns matching value
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password", "ntlm-hash"],
            cred_values=["Summer2024!", "abc123hash"],
        )

        assert user.get_credential("ntlm-hash") == "abc123hash"
        assert user.get_credential("password") == "Summer2024!"

    def test_get_credential_not_found(self):
        """
        BV: get_credential returns None for missing

        Scenario:
          Given: PwnedUser
          When: Getting unknown type
          Then: Returns None
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password"],
            cred_values=["test"],
        )

        assert user.get_credential("kerberos-ticket") is None

    def test_has_credential_type(self):
        """
        BV: Check if user has credential type

        Scenario:
          Given: PwnedUser with creds
          When: Checking has_credential_type
          Then: Returns True/False correctly
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password", "ntlm-hash"],
            cred_values=["Summer2024!", "abc123hash"],
        )

        assert user.has_credential_type("password") is True
        assert user.has_credential_type("ntlm-hash") is True
        assert user.has_credential_type("certificate") is False

    def test_username_property(self):
        """
        BV: Extract username from UPN

        Scenario:
          Given: PwnedUser with UPN format
          When: Getting username
          Then: Returns part before @
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.username == "PETE"

    def test_username_no_at(self):
        """
        BV: Username without @ returns full name

        Scenario:
          Given: Name without @
          When: Getting username
          Then: Returns full name
        """
        user = PwnedUser(
            name="ADMINISTRATOR",
            pwned_at=datetime.now(),
        )

        assert user.username == "ADMINISTRATOR"

    def test_domain_property(self):
        """
        BV: Extract domain from UPN

        Scenario:
          Given: PwnedUser with UPN
          When: Getting domain
          Then: Returns part after @
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
        )

        assert user.domain == "CORP.COM"

    def test_domain_no_at(self):
        """
        BV: Domain returns empty without @

        Scenario:
          Given: Name without @
          When: Getting domain
          Then: Returns empty string
        """
        user = PwnedUser(
            name="ADMINISTRATOR",
            pwned_at=datetime.now(),
        )

        assert user.domain == ""

    def test_source_machine(self):
        """
        BV: Track source machine

        Scenario:
          Given: PwnedUser with source
          When: Checking source_machine
          Then: Contains machine name
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            source_machine="CLIENT75.CORP.COM",
        )

        assert user.source_machine == "CLIENT75.CORP.COM"

    def test_notes(self):
        """
        BV: Track compromise notes

        Scenario:
          Given: PwnedUser with notes
          When: Checking notes
          Then: Contains note text
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            notes="From SAM dump via mimikatz",
        )

        assert "SAM dump" in user.notes

    def test_access_list(self):
        """
        BV: Track machine access

        Scenario:
          Given: PwnedUser with access
          When: Checking access
          Then: Contains MachineAccess objects
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
        )

        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            access=[access],
        )

        assert len(user.access) == 1
        assert user.access[0].computer == "DC01.CORP.COM"

    def test_domain_level_access(self):
        """
        BV: Track domain admin status

        Scenario:
          Given: PwnedUser with domain access
          When: Checking domain_level_access
          Then: Returns 'domain-admin'
        """
        user = PwnedUser(
            name="DA@CORP.COM",
            pwned_at=datetime.now(),
            domain_level_access="domain-admin",
        )

        assert user.domain_level_access == "domain-admin"

    def test_gmsa_access(self):
        """
        BV: Track gMSA access

        Scenario:
          Given: PwnedUser with gMSA access
          When: Checking gmsa_access
          Then: Contains service accounts
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            gmsa_access=["GMSA_SQL@CORP.COM", "GMSA_WEB@CORP.COM"],
        )

        assert len(user.gmsa_access) == 2
        assert "GMSA_SQL@CORP.COM" in user.gmsa_access


# =============================================================================
# PwnedResult Tests
# =============================================================================

class TestPwnedResult:
    """Tests for PwnedResult dataclass"""

    def test_success_result(self):
        """
        BV: Create successful result

        Scenario:
          Given: Successful operation
          When: Creating PwnedResult
          Then: success=True with user
        """
        result = PwnedResult(
            success=True,
            user="PETE@CORP.COM",
        )

        assert result.success is True
        assert result.user == "PETE@CORP.COM"
        assert result.error is None

    def test_failure_result(self):
        """
        BV: Create failure result

        Scenario:
          Given: Failed operation
          When: Creating PwnedResult
          Then: success=False with error
        """
        result = PwnedResult(
            success=False,
            error="User not found in BloodHound",
        )

        assert result.success is False
        assert "not found" in result.error

    def test_result_with_access(self):
        """
        BV: Result includes access paths

        Scenario:
          Given: Result with access
          When: Checking access
          Then: Contains MachineAccess
        """
        access = MachineAccess(
            computer="DC01.CORP.COM",
            access_types=["AdminTo"],
            privilege_level="local-admin",
        )

        result = PwnedResult(
            success=True,
            user="PETE@CORP.COM",
            access=[access],
        )

        assert len(result.access) == 1
        assert result.access[0].computer == "DC01.CORP.COM"

    def test_result_with_domain_access(self):
        """
        BV: Result includes domain level

        Scenario:
          Given: Result with domain access
          When: Checking domain_level_access
          Then: Contains privilege level
        """
        result = PwnedResult(
            success=True,
            user="DA@CORP.COM",
            domain_level_access="domain-admin",
        )

        assert result.domain_level_access == "domain-admin"


# =============================================================================
# Constants Tests
# =============================================================================

class TestConstants:
    """Tests for module constants"""

    def test_edge_to_privilege_has_adminto(self):
        """
        BV: AdminTo maps to local-admin

        Scenario:
          Given: EDGE_TO_PRIVILEGE
          When: Checking AdminTo
          Then: Maps to 'local-admin'
        """
        assert EDGE_TO_PRIVILEGE["AdminTo"] == "local-admin"

    def test_edge_to_privilege_has_canrdp(self):
        """
        BV: CanRDP maps to user-level

        Scenario:
          Given: EDGE_TO_PRIVILEGE
          When: Checking CanRDP
          Then: Maps to 'user-level'
        """
        assert EDGE_TO_PRIVILEGE["CanRDP"] == "user-level"

    def test_edge_to_privilege_has_dcom(self):
        """
        BV: ExecuteDCOM maps to dcom-exec

        Scenario:
          Given: EDGE_TO_PRIVILEGE
          When: Checking ExecuteDCOM
          Then: Maps to 'dcom-exec'
        """
        assert EDGE_TO_PRIVILEGE["ExecuteDCOM"] == "dcom-exec"

    def test_domain_admin_edges_has_dcsync(self):
        """
        BV: DCSync is domain admin edge

        Scenario:
          Given: DOMAIN_ADMIN_EDGES
          When: Checking for DCSync
          Then: Contains DCSync
        """
        assert "DCSync" in DOMAIN_ADMIN_EDGES

    def test_domain_admin_edges_has_genericall(self):
        """
        BV: GenericAll is domain admin edge

        Scenario:
          Given: DOMAIN_ADMIN_EDGES
          When: Checking for GenericAll
          Then: Contains GenericAll
        """
        assert "GenericAll" in DOMAIN_ADMIN_EDGES

    def test_cred_types_includes_password(self):
        """
        BV: CRED_TYPES includes password

        Scenario:
          Given: CRED_TYPES
          When: Checking contents
          Then: Contains 'password'
        """
        assert "password" in CRED_TYPES

    def test_cred_types_includes_ntlm(self):
        """
        BV: CRED_TYPES includes ntlm-hash

        Scenario:
          Given: CRED_TYPES
          When: Checking contents
          Then: Contains 'ntlm-hash'
        """
        assert "ntlm-hash" in CRED_TYPES

    def test_cred_types_includes_kerberos(self):
        """
        BV: CRED_TYPES includes kerberos-ticket

        Scenario:
          Given: CRED_TYPES
          When: Checking contents
          Then: Contains 'kerberos-ticket'
        """
        assert "kerberos-ticket" in CRED_TYPES

    def test_cred_types_includes_certificate(self):
        """
        BV: CRED_TYPES includes certificate

        Scenario:
          Given: CRED_TYPES
          When: Checking contents
          Then: Contains 'certificate'
        """
        assert "certificate" in CRED_TYPES


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_pwned_user_mismatched_arrays(self):
        """
        BV: Handle mismatched cred arrays

        Scenario:
          Given: More types than values
          When: Getting credential
          Then: Handles gracefully
        """
        user = PwnedUser(
            name="PETE@CORP.COM",
            pwned_at=datetime.now(),
            cred_types=["password", "ntlm-hash"],
            cred_values=["only-one"],  # Missing second value
        )

        # Should not crash
        result = user.get_credential("ntlm-hash")
        assert result is None  # Index out of bounds caught

    def test_empty_access_list(self):
        """
        BV: Empty access list is valid

        Scenario:
          Given: User with no machine access
          When: Checking access
          Then: Empty list, no error
        """
        user = PwnedUser(
            name="LIMITED@CORP.COM",
            pwned_at=datetime.now(),
            access=[],
        )

        assert user.access == []

    def test_machine_access_empty_sessions(self):
        """
        BV: Access with no sessions

        Scenario:
          Given: MachineAccess without sessions
          When: Checking sessions
          Then: Empty list
        """
        access = MachineAccess(
            computer="SERVER.CORP.COM",
            access_types=["CanRDP"],
            privilege_level="user-level",
            sessions=[],
        )

        assert access.sessions == []
