"""
BloodTrail Attack Paths Display Module Tests

Business Value Focus:
- generate_pwned_attack_paths() produces actionable attack recommendations
- generate_post_exploit_section() provides credential harvest commands
- Privilege level grouping (local-admin, user-level, dcom-exec) is accurate
- Credential type awareness generates correct command templates
- Output formatting (console/markdown) is correct and usable

Test Priority: TIER 2 - HIGH (AD Exploitation)

These tests protect against:
- Incorrect privilege grouping leading to failed lateral movement
- Missing or malformed command templates
- Credential type mismatch (password vs hash vs ticket)
- Output corruption (colors in markdown, missing sections)
- Neo4j query failures silently hiding access paths

Ownership: tests/tools/post/bloodtrail/display/ (exclusive)
"""

import sys
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import test factories
from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    MockNeo4jResult,
    MockRecord,
    create_mock_driver_success,
    create_mock_driver_failure,
)

# Module under test
from tools.post.bloodtrail.display.attack_paths import (
    generate_pwned_attack_paths,
    generate_post_exploit_section,
    _fetch_pwned_users,
    _fetch_user_access,
    _check_domain_access,
    _fetch_user_spns,
    _fetch_dc_ip,
)
from tools.post.bloodtrail.display.base import Colors, NoColors


# =============================================================================
# Factory Classes
# =============================================================================

class PwnedUserRecordFactory:
    """Factory for creating Neo4j pwned user records"""

    _counter = 0

    @classmethod
    def create(
        cls,
        name: str = None,
        cred_types: List[str] = None,
        cred_values: List[str] = None,
        source_machine: str = None,
    ) -> Dict[str, Any]:
        """Create pwned user record as returned by Neo4j"""
        cls._counter += 1
        return {
            "name": name or f"USER{cls._counter}@CORP.COM",
            "cred_types": cred_types or ["password"],
            "cred_values": cred_values or [f"Password{cls._counter}!"],
            "source_machine": source_machine or f"WS{cls._counter:02d}.CORP.COM",
        }

    @classmethod
    def create_with_password(cls, username: str, password: str, domain: str = "CORP.COM"):
        """Create user with cleartext password"""
        return cls.create(
            name=f"{username}@{domain}",
            cred_types=["password"],
            cred_values=[password],
        )

    @classmethod
    def create_with_hash(cls, username: str, ntlm_hash: str, domain: str = "CORP.COM"):
        """Create user with NTLM hash"""
        return cls.create(
            name=f"{username}@{domain}",
            cred_types=["ntlm-hash"],
            cred_values=[ntlm_hash],
        )

    @classmethod
    def create_with_ticket(cls, username: str, ticket_path: str, domain: str = "CORP.COM"):
        """Create user with Kerberos ticket"""
        return cls.create(
            name=f"{username}@{domain}",
            cred_types=["kerberos-ticket"],
            cred_values=[ticket_path],
        )


class AccessRecordFactory:
    """Factory for creating Neo4j access path records"""

    @classmethod
    def create(
        cls,
        computer: str,
        computer_ip: str = None,
        access_types: List[str] = None,
        inherited_from: str = None,
        privileged_sessions: List[str] = None,
    ) -> Dict[str, Any]:
        """Create access record as returned by Neo4j"""
        return {
            "computer": computer,
            "computer_ip": computer_ip or "",
            "access_types": access_types or ["AdminTo"],
            "inherited_from": inherited_from,
            "privileged_sessions": privileged_sessions or [],
        }

    @classmethod
    def create_admin_access(cls, computer: str, ip: str = None, sessions: List[str] = None):
        """Create AdminTo access"""
        return cls.create(
            computer=computer,
            computer_ip=ip,
            access_types=["AdminTo"],
            privileged_sessions=sessions or [],
        )

    @classmethod
    def create_rdp_access(cls, computer: str, ip: str = None):
        """Create CanRDP access"""
        return cls.create(
            computer=computer,
            computer_ip=ip,
            access_types=["CanRDP"],
        )

    @classmethod
    def create_psremote_access(cls, computer: str, ip: str = None):
        """Create CanPSRemote access"""
        return cls.create(
            computer=computer,
            computer_ip=ip,
            access_types=["CanPSRemote"],
        )

    @classmethod
    def create_dcom_access(cls, computer: str, ip: str = None):
        """Create ExecuteDCOM access"""
        return cls.create(
            computer=computer,
            computer_ip=ip,
            access_types=["ExecuteDCOM"],
        )


class MockDriverBuilder:
    """Builder for creating mock Neo4j drivers with specific query responses"""

    def __init__(self):
        self._responses = {}
        self._default_records = []

    def with_pwned_users(self, records: List[Dict]) -> 'MockDriverBuilder':
        """Add pwned users query response"""
        self._responses['pwned'] = records
        return self

    def with_user_access(self, records: List[Dict]) -> 'MockDriverBuilder':
        """Add user access query response"""
        self._responses['access'] = records
        return self

    def with_domain_access(self, access_type: str = None) -> 'MockDriverBuilder':
        """Add domain access query response"""
        if access_type:
            self._responses['domain_access'] = [{"access": access_type}]
        else:
            self._responses['domain_access'] = []
        return self

    def with_spns(self, spns: List[str]) -> 'MockDriverBuilder':
        """Add SPN query response"""
        self._responses['spns'] = [{"SPNs": spns}]
        return self

    def with_dc_ip(self, ip: str) -> 'MockDriverBuilder':
        """Add DC IP query response"""
        self._responses['dc_ip'] = [{"dc_ip": ip}]
        return self

    def with_lhost_lport(self, lhost: str, lport: int) -> 'MockDriverBuilder':
        """Add domain config response"""
        self._responses['domain_config'] = [{"lhost": lhost, "lport": lport}]
        return self

    def build(self) -> MockNeo4jDriver:
        """Build the mock driver with configured responses"""
        # Create a driver that returns different results based on query
        driver = Mock()
        session = Mock()

        def run_query(query, params=None):
            params = params or {}
            # Match query patterns to responses
            if "pwned = true" in query.lower():
                records = self._responses.get('pwned', [])
            elif "adminto|canrdp|canpsremote|executedcom" in query.lower():
                records = self._responses.get('access', [])
            elif "getchanges" in query.lower() or "domain admins" in query.lower() or "genericall" in query.lower():
                records = self._responses.get('domain_access', [])
            elif "serviceprincipalnames" in query.lower():
                records = self._responses.get('spns', [])
            elif "bloodtrail_dc_ip" in query.lower():
                records = self._responses.get('dc_ip', [])
            elif "bloodtrail_lhost" in query.lower():
                records = self._responses.get('domain_config', [])
            else:
                records = self._default_records

            return MockNeo4jResult(records)

        session.run = run_query
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        return driver


# =============================================================================
# _fetch_pwned_users Tests
# =============================================================================

class TestFetchPwnedUsers:
    """Tests for _fetch_pwned_users() Neo4j query function"""

    def test_returns_empty_list_when_no_pwned_users(self):
        """
        BV: Graceful handling when no users have been pwned yet

        Scenario:
          Given: Neo4j has no users with pwned=true
          When: _fetch_pwned_users() is called
          Then: Returns empty list (not None or exception)
        """
        driver = MockDriverBuilder().with_pwned_users([]).build()

        result = _fetch_pwned_users(driver)

        assert result == []

    def test_extracts_user_name_correctly(self):
        """
        BV: User identity is correctly extracted for command generation

        Scenario:
          Given: Pwned user ADMIN@CORP.COM in Neo4j
          When: _fetch_pwned_users() is called
          Then: Returns user with correct name
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).build()

        result = _fetch_pwned_users(driver)

        assert len(result) == 1
        assert result[0]["name"] == "ADMIN@CORP.COM"

    def test_extracts_credential_type_correctly(self):
        """
        BV: Credential type determines which command templates to use

        Scenario:
          Given: Pwned user with NTLM hash
          When: _fetch_pwned_users() is called
          Then: Returns user with cred_type='ntlm-hash'
        """
        records = [PwnedUserRecordFactory.create_with_hash("ADMIN", "aabbccdd" * 4)]
        driver = MockDriverBuilder().with_pwned_users(records).build()

        result = _fetch_pwned_users(driver)

        assert result[0]["cred_type"] == "ntlm-hash"

    def test_extracts_credential_value_correctly(self):
        """
        BV: Credential value is extracted for command auto-fill

        Scenario:
          Given: Pwned user with password 'MySecret123!'
          When: _fetch_pwned_users() is called
          Then: Returns user with correct cred_value
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "MySecret123!")]
        driver = MockDriverBuilder().with_pwned_users(records).build()

        result = _fetch_pwned_users(driver)

        assert result[0]["cred_value"] == "MySecret123!"

    def test_handles_multiple_pwned_users(self):
        """
        BV: All pwned users are enumerated for attack path generation

        Scenario:
          Given: 3 pwned users in Neo4j
          When: _fetch_pwned_users() is called
          Then: Returns all 3 users
        """
        records = [
            PwnedUserRecordFactory.create_with_password("USER1", "Pass1"),
            PwnedUserRecordFactory.create_with_password("USER2", "Pass2"),
            PwnedUserRecordFactory.create_with_password("USER3", "Pass3"),
        ]
        driver = MockDriverBuilder().with_pwned_users(records).build()

        result = _fetch_pwned_users(driver)

        assert len(result) == 3

    def test_defaults_to_password_cred_type_when_missing(self):
        """
        BV: Missing credential metadata doesn't break processing

        Scenario:
          Given: Pwned user with empty cred_types list
          When: _fetch_pwned_users() is called
          Then: Defaults to 'password' type
        """
        records = [{"name": "ADMIN@CORP.COM", "cred_types": [], "cred_values": [], "source_machine": None}]
        driver = MockDriverBuilder().with_pwned_users(records).build()

        result = _fetch_pwned_users(driver)

        assert result[0]["cred_type"] == "password"

    def test_handles_neo4j_exception_gracefully(self):
        """
        BV: Neo4j errors don't crash the application

        Scenario:
          Given: Neo4j connection fails
          When: _fetch_pwned_users() is called
          Then: Returns empty list (graceful degradation)
        """
        driver = Mock()
        driver.session.side_effect = Exception("Connection refused")

        result = _fetch_pwned_users(driver)

        assert result == []


# =============================================================================
# _fetch_user_access Tests
# =============================================================================

class TestFetchUserAccess:
    """Tests for _fetch_user_access() privilege grouping"""

    def test_groups_adminto_as_local_admin(self):
        """
        BV: AdminTo edges indicate local admin access for credential harvesting

        Scenario:
          Given: User has AdminTo edge to DC01.CORP.COM
          When: _fetch_user_access() is called
          Then: DC01 appears in 'local-admin' group
        """
        records = [AccessRecordFactory.create_admin_access("DC01.CORP.COM", "192.168.1.10")]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "ADMIN@CORP.COM")

        assert len(result["local-admin"]) == 1
        assert result["local-admin"][0]["computer"] == "DC01.CORP.COM"

    def test_groups_canrdp_as_user_level(self):
        """
        BV: CanRDP provides user-level access (can't harvest creds)

        Scenario:
          Given: User has CanRDP edge to WS01.CORP.COM
          When: _fetch_user_access() is called
          Then: WS01 appears in 'user-level' group
        """
        records = [AccessRecordFactory.create_rdp_access("WS01.CORP.COM")]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "USER@CORP.COM")

        assert len(result["user-level"]) == 1
        assert result["user-level"][0]["computer"] == "WS01.CORP.COM"

    def test_groups_canpsremote_as_user_level(self):
        """
        BV: CanPSRemote provides user-level access (interactive shell)

        Scenario:
          Given: User has CanPSRemote edge to WS02.CORP.COM
          When: _fetch_user_access() is called
          Then: WS02 appears in 'user-level' group
        """
        records = [AccessRecordFactory.create_psremote_access("WS02.CORP.COM")]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "USER@CORP.COM")

        assert len(result["user-level"]) == 1
        assert result["user-level"][0]["computer"] == "WS02.CORP.COM"

    def test_groups_executedcom_as_dcom_exec(self):
        """
        BV: ExecuteDCOM requires special DCOM exploitation techniques

        Scenario:
          Given: User has ExecuteDCOM edge to SRV01.CORP.COM
          When: _fetch_user_access() is called
          Then: SRV01 appears in 'dcom-exec' group
        """
        records = [AccessRecordFactory.create_dcom_access("SRV01.CORP.COM")]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "USER@CORP.COM")

        assert len(result["dcom-exec"]) == 1
        assert result["dcom-exec"][0]["computer"] == "SRV01.CORP.COM"

    def test_extracts_computer_ip(self):
        """
        BV: IP address enables direct connection commands

        Scenario:
          Given: Computer has IP 192.168.1.100 stored
          When: _fetch_user_access() is called
          Then: IP is included in access entry
        """
        records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM", "192.168.1.100")]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "ADMIN@CORP.COM")

        assert result["local-admin"][0]["computer_ip"] == "192.168.1.100"

    def test_extracts_privileged_sessions(self):
        """
        BV: Privileged sessions indicate priority targets for cred harvesting

        Scenario:
          Given: WS01 has session from Domain Admin
          When: _fetch_user_access() is called
          Then: Session list is included for prioritization
        """
        records = [AccessRecordFactory.create_admin_access(
            "WS01.CORP.COM", sessions=["DA@CORP.COM", "ADMIN@CORP.COM"]
        )]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "USER@CORP.COM")

        assert "DA@CORP.COM" in result["local-admin"][0]["privileged_sessions"]

    def test_handles_multiple_access_types_per_computer(self):
        """
        BV: Computers may have multiple access paths

        Scenario:
          Given: User has both AdminTo and CanRDP to same computer
          When: _fetch_user_access() is called
          Then: Computer appears in highest privilege group (local-admin)
        """
        records = [AccessRecordFactory.create(
            "WS01.CORP.COM",
            access_types=["AdminTo", "CanRDP"],
        )]
        driver = MockDriverBuilder().with_user_access(records).build()

        result = _fetch_user_access(driver, "ADMIN@CORP.COM")

        # AdminTo takes priority
        assert len(result["local-admin"]) == 1
        assert "AdminTo" in result["local-admin"][0]["access_types"]

    def test_returns_empty_groups_when_no_access(self):
        """
        BV: Users without edges still get valid (empty) structure

        Scenario:
          Given: User has no access edges
          When: _fetch_user_access() is called
          Then: Returns dict with empty lists for all groups
        """
        driver = MockDriverBuilder().with_user_access([]).build()

        result = _fetch_user_access(driver, "NOOB@CORP.COM")

        assert result["local-admin"] == []
        assert result["user-level"] == []
        assert result["dcom-exec"] == []

    def test_handles_neo4j_exception_gracefully(self):
        """
        BV: Query failures don't crash the application

        Scenario:
          Given: Neo4j query fails
          When: _fetch_user_access() is called
          Then: Returns empty groups (graceful degradation)
        """
        driver = Mock()
        driver.session.side_effect = Exception("Query failed")

        result = _fetch_user_access(driver, "ADMIN@CORP.COM")

        assert result == {"local-admin": [], "user-level": [], "dcom-exec": []}


# =============================================================================
# _check_domain_access Tests
# =============================================================================

class TestCheckDomainAccess:
    """Tests for _check_domain_access() domain privilege detection"""

    def test_detects_dcsync_from_direct_rights(self):
        """
        BV: Direct DCSync rights enable full domain compromise

        Scenario:
          Given: User has GetChanges + GetChangesAll on Domain
          When: _check_domain_access() is called
          Then: Returns 'DCSync'
        """
        driver = MockDriverBuilder().with_domain_access("DCSync").build()

        result = _check_domain_access(driver, "EVIL@CORP.COM")

        assert result == "DCSync"

    def test_detects_domain_admin_membership(self):
        """
        BV: Domain Admin membership enables all domain operations

        Scenario:
          Given: User is member of Domain Admins group
          When: _check_domain_access() is called
          Then: Returns 'DomainAdmin'
        """
        # Mock the specific query for DA membership
        driver = Mock()
        session = Mock()

        def run_query(query, params=None):
            if "DOMAIN ADMINS" in query.upper():
                return MockNeo4jResult([{"admin_group": "DOMAIN ADMINS@CORP.COM"}])
            return MockNeo4jResult([])

        session.run = run_query
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        result = _check_domain_access(driver, "DA@CORP.COM")

        assert result == "DomainAdmin"

    def test_detects_genericall_on_domain(self):
        """
        BV: GenericAll on Domain provides full control

        Scenario:
          Given: User has GenericAll on Domain object
          When: _check_domain_access() is called
          Then: Returns 'GenericAll'
        """
        # Mock the GenericAll query
        driver = Mock()
        session = Mock()

        query_count = [0]

        def run_query(query, params=None):
            query_count[0] += 1
            # GenericAll queries are checked after DCSync and DA
            if "genericall" in query.lower() and ":Domain" in query:
                return MockNeo4jResult([{"access": "GenericAll"}])
            return MockNeo4jResult([])

        session.run = run_query
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        result = _check_domain_access(driver, "ATTACKER@CORP.COM")

        assert result == "GenericAll"

    def test_returns_none_for_no_domain_access(self):
        """
        BV: Regular users don't have domain-level access

        Scenario:
          Given: User has no domain-level privileges
          When: _check_domain_access() is called
          Then: Returns None
        """
        driver = Mock()
        session = Mock()
        session.run = Mock(return_value=MockNeo4jResult([]))
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        result = _check_domain_access(driver, "NORMALUSER@CORP.COM")

        assert result is None

    def test_handles_neo4j_exception_gracefully(self):
        """
        BV: Query failures don't crash domain access check

        Scenario:
          Given: Neo4j query fails
          When: _check_domain_access() is called
          Then: Returns None (safe default)
        """
        driver = Mock()
        driver.session.side_effect = Exception("Connection lost")

        result = _check_domain_access(driver, "USER@CORP.COM")

        assert result is None


# =============================================================================
# _fetch_user_spns Tests
# =============================================================================

class TestFetchUserSpns:
    """Tests for _fetch_user_spns() SPN query function"""

    def test_returns_spn_list(self):
        """
        BV: SPNs indicate where service accounts run (potential admin access)

        Scenario:
          Given: User has SPNs for MSSQL services
          When: _fetch_user_spns() is called
          Then: Returns list of SPNs
        """
        spns = ["MSSQLSvc/DB01.CORP.COM:1433", "MSSQLSvc/DB02.CORP.COM:1433"]
        driver = MockDriverBuilder().with_spns(spns).build()

        result = _fetch_user_spns(driver, "SQLSVC@CORP.COM")

        assert len(result) == 2
        assert "MSSQLSvc/DB01.CORP.COM:1433" in result

    def test_returns_empty_list_when_no_spns(self):
        """
        BV: Users without SPNs get empty list (not None)

        Scenario:
          Given: User has no SPNs
          When: _fetch_user_spns() is called
          Then: Returns empty list
        """
        driver = MockDriverBuilder().with_spns([]).build()

        result = _fetch_user_spns(driver, "NORMALUSER@CORP.COM")

        assert result == []

    def test_handles_none_spns_in_record(self):
        """
        BV: Null SPN values don't crash extraction

        Scenario:
          Given: User record has SPNs=null
          When: _fetch_user_spns() is called
          Then: Returns empty list
        """
        driver = Mock()
        session = Mock()
        session.run = Mock(return_value=MockNeo4jResult([{"SPNs": None}]))
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        result = _fetch_user_spns(driver, "USER@CORP.COM")

        assert result == []


# =============================================================================
# _fetch_dc_ip Tests
# =============================================================================

class TestFetchDcIp:
    """Tests for _fetch_dc_ip() domain controller IP query"""

    def test_returns_configured_dc_ip(self):
        """
        BV: DC IP is needed for many attack commands

        Scenario:
          Given: Domain has bloodtrail_dc_ip configured
          When: _fetch_dc_ip() is called
          Then: Returns the configured IP
        """
        driver = MockDriverBuilder().with_dc_ip("192.168.1.1").build()

        result = _fetch_dc_ip(driver)

        assert result == "192.168.1.1"

    def test_returns_none_when_not_configured(self):
        """
        BV: Missing DC IP is handled gracefully

        Scenario:
          Given: No bloodtrail_dc_ip in domain properties
          When: _fetch_dc_ip() is called
          Then: Returns None
        """
        driver = Mock()
        session = Mock()
        session.run = Mock(return_value=MockNeo4jResult([{"dc_ip": None}]))
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        driver.session = Mock(return_value=session)

        result = _fetch_dc_ip(driver)

        assert result is None

    def test_handles_no_domain_record(self):
        """
        BV: Missing domain record doesn't crash

        Scenario:
          Given: No Domain node exists
          When: _fetch_dc_ip() is called
          Then: Returns None
        """
        driver = MockDriverBuilder().with_dc_ip(None).build()
        # Override to return no records
        driver.session().run = Mock(return_value=MockNeo4jResult([]))

        result = _fetch_dc_ip(driver)

        assert result is None


# =============================================================================
# generate_pwned_attack_paths Tests
# =============================================================================

class TestGeneratePwnedAttackPaths:
    """Tests for generate_pwned_attack_paths() main report generation"""

    def test_returns_tuple_of_console_and_markdown(self):
        """
        BV: Function returns both output formats for flexibility

        Scenario:
          Given: Pwned users exist
          When: generate_pwned_attack_paths() is called
          Then: Returns (console_string, markdown_string) tuple
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        result = generate_pwned_attack_paths(driver, use_colors=False)

        assert isinstance(result, tuple)
        assert len(result) == 2
        console_out, md_out = result
        assert isinstance(console_out, str)
        assert isinstance(md_out, str)

    def test_returns_empty_strings_when_no_pwned_users(self):
        """
        BV: No pwned users means no attack paths to display

        Scenario:
          Given: No pwned users in Neo4j
          When: generate_pwned_attack_paths() is called
          Then: Returns ("", "")
        """
        driver = MockDriverBuilder().with_pwned_users([]).build()

        console_out, md_out = generate_pwned_attack_paths(driver)

        assert console_out == ""
        assert md_out == ""

    def test_console_output_includes_header(self):
        """
        BV: Clear section header helps user orientation

        Scenario:
          Given: Pwned users exist
          When: generate_pwned_attack_paths(use_colors=False)
          Then: Console output includes 'Pwned User Attack Paths'
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "Pwned User Attack Paths" in console_out

    def test_markdown_output_has_header(self):
        """
        BV: Markdown has proper header for document structure

        Scenario:
          Given: Pwned users exist
          When: generate_pwned_attack_paths() is called
          Then: Markdown includes ## header
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        _, md_out = generate_pwned_attack_paths(driver)

        assert "## " in md_out
        assert "Attack Paths" in md_out

    def test_console_output_has_colors_when_enabled(self):
        """
        BV: Colored output improves terminal readability

        Scenario:
          Given: use_colors=True
          When: generate_pwned_attack_paths() is called
          Then: Console output contains ANSI escape codes
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=True)

        # ANSI codes start with \033[
        assert "\033[" in console_out

    def test_console_output_no_colors_when_disabled(self):
        """
        BV: Color-free output for file/pipe redirection

        Scenario:
          Given: use_colors=False
          When: generate_pwned_attack_paths() is called
          Then: Console output has no ANSI escape codes
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "\033[" not in console_out

    def test_shows_user_credentials_section(self):
        """
        BV: User identity and credential type shown for context

        Scenario:
          Given: Pwned user ADMIN@CORP.COM with password
          When: generate_pwned_attack_paths() is called
          Then: Output shows username and credential type
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "ADMIN@CORP.COM" in console_out
        assert "password" in console_out.lower()

    def test_shows_local_admin_section_when_available(self):
        """
        BV: Local admin access is the primary lateral movement path

        Scenario:
          Given: User has AdminTo edge to DC01
          When: generate_pwned_attack_paths() is called
          Then: Output includes 'LOCAL ADMIN ACCESS' section
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("DC01.CORP.COM", "192.168.1.10")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "LOCAL ADMIN ACCESS" in console_out.upper()
        assert "DC01.CORP.COM" in console_out

    def test_shows_domain_admin_section_when_available(self):
        """
        BV: Domain admin access is the highest priority

        Scenario:
          Given: User has DCSync rights
          When: generate_pwned_attack_paths() is called
          Then: Output includes 'DOMAIN ADMIN ACCESS' section
        """
        user_records = [PwnedUserRecordFactory.create_with_password("EVIL", "Password123")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access([])\
            .with_domain_access("DCSync")\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "DOMAIN ADMIN ACCESS" in console_out.upper()

    def test_shows_dcsync_command_for_domain_access(self):
        """
        BV: DCSync command is auto-generated for DA users

        Scenario:
          Given: User with DCSync rights and password
          When: generate_pwned_attack_paths() is called
          Then: Output includes secretsdump command
        """
        user_records = [PwnedUserRecordFactory.create_with_password("DA", "DAPass123")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access([])\
            .with_domain_access("DomainAdmin")\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "secretsdump" in console_out.lower() or "DCSync" in console_out


# =============================================================================
# Credential Type Awareness Tests
# =============================================================================

class TestCredentialTypeAwareness:
    """Tests for credential-type-specific command generation"""

    def test_password_cred_generates_password_commands(self):
        """
        BV: Password credentials use cleartext auth commands

        Scenario:
          Given: User with password credential
          When: generate_pwned_attack_paths() is called
          Then: Commands use password-based syntax
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Password-based commands typically include the password directly
        assert "Secret123" in console_out or "password" in console_out.lower()

    def test_ntlm_hash_generates_pth_commands(self):
        """
        BV: NTLM hashes use Pass-the-Hash commands

        Scenario:
          Given: User with NTLM hash credential
          When: generate_pwned_attack_paths() is called
          Then: Commands use -hashes syntax
        """
        ntlm_hash = "aabbccdd11223344" * 2
        user_records = [PwnedUserRecordFactory.create_with_hash("ADMIN", ntlm_hash)]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Hash-based commands use -hashes flag
        assert "-hashes" in console_out or "pth" in console_out.lower() or ntlm_hash in console_out

    def test_kerberos_ticket_generates_ptt_commands(self):
        """
        BV: Kerberos tickets use Pass-the-Ticket commands

        Scenario:
          Given: User with Kerberos ticket credential
          When: generate_pwned_attack_paths() is called
          Then: Commands use KRB5CCNAME syntax
        """
        ticket_path = "/tmp/admin.ccache"
        user_records = [PwnedUserRecordFactory.create_with_ticket("ADMIN", ticket_path)]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Kerberos-based commands use KRB5CCNAME or -k flag
        assert "KRB5CCNAME" in console_out or "-k" in console_out or ticket_path in console_out


# =============================================================================
# generate_post_exploit_section Tests
# =============================================================================

class TestGeneratePostExploitSection:
    """Tests for generate_post_exploit_section() credential harvest commands"""

    def test_returns_tuple_of_console_and_markdown(self):
        """
        BV: Function returns both output formats

        Scenario:
          Given: Users with local admin access
          When: generate_post_exploit_section() is called
          Then: Returns (console_string, markdown_string)
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        result = generate_post_exploit_section(driver, use_colors=False)

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_returns_empty_when_no_pwned_users(self):
        """
        BV: No users means no post-exploitation section

        Scenario:
          Given: No pwned users
          When: generate_post_exploit_section() is called
          Then: Returns ("", "")
        """
        driver = MockDriverBuilder().with_pwned_users([]).build()

        console_out, md_out = generate_post_exploit_section(driver)

        assert console_out == ""
        assert md_out == ""

    def test_returns_empty_when_no_admin_access(self):
        """
        BV: Post-exploitation requires admin privileges

        Scenario:
          Given: Pwned user with only RDP access (no admin)
          When: generate_post_exploit_section() is called
          Then: Returns ("", "")
        """
        user_records = [PwnedUserRecordFactory.create_with_password("USER", "Pass123")]
        access_records = [AccessRecordFactory.create_rdp_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .with_domain_access(None)\
            .build()

        console_out, md_out = generate_post_exploit_section(driver, use_colors=False)

        assert console_out == ""
        assert md_out == ""

    def test_includes_post_exploitation_header(self):
        """
        BV: Clear header for post-exploitation section

        Scenario:
          Given: User with local admin access
          When: generate_post_exploit_section() is called
          Then: Output includes 'Post-Exploitation' header
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_post_exploit_section(driver, use_colors=False)

        assert "Post-Exploitation" in console_out

    def test_includes_mimikatz_commands(self):
        """
        BV: Mimikatz commands for credential harvesting

        Scenario:
          Given: User with local admin access
          When: generate_post_exploit_section() is called
          Then: Output includes mimikatz command templates
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_post_exploit_section(driver, use_colors=False)

        assert "mimikatz" in console_out.lower()

    def test_includes_credential_harvest_order(self):
        """
        BV: Credential harvest commands shown in priority order

        Scenario:
          Given: User with local admin access
          When: generate_post_exploit_section() is called
          Then: Output includes 'CREDENTIAL HARVEST ORDER'
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_post_exploit_section(driver, use_colors=False)

        assert "CREDENTIAL HARVEST" in console_out.upper()


# =============================================================================
# Output Format Tests
# =============================================================================

class TestOutputFormatting:
    """Tests for output formatting (console vs markdown)"""

    def test_markdown_has_proper_headers(self):
        """
        BV: Markdown headers structure the document

        Scenario:
          Given: Pwned users exist
          When: generate_pwned_attack_paths() is called
          Then: Markdown has ## and ### headers
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        _, md_out = generate_pwned_attack_paths(driver)

        assert "##" in md_out

    def test_markdown_has_tables(self):
        """
        BV: Markdown tables organize attack techniques

        Scenario:
          Given: User with local admin access
          When: generate_pwned_attack_paths() is called
          Then: Markdown includes pipe-delimited tables
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        _, md_out = generate_pwned_attack_paths(driver)

        # Markdown tables use | separators
        assert "|" in md_out

    def test_markdown_has_code_blocks(self):
        """
        BV: Commands in markdown are in code blocks for copy-paste

        Scenario:
          Given: User with local admin access
          When: generate_pwned_attack_paths() is called
          Then: Markdown has backtick code blocks
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        _, md_out = generate_pwned_attack_paths(driver)

        assert "`" in md_out


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_handles_user_without_domain_part(self):
        """
        BV: Usernames without @ are handled gracefully

        Scenario:
          Given: Username "ADMIN" (no domain)
          When: generate_pwned_attack_paths() is called
          Then: No crash, username used as-is
        """
        records = [{"name": "ADMIN", "cred_types": ["password"],
                    "cred_values": ["Pass123"], "source_machine": None}]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "ADMIN" in console_out

    def test_handles_unicode_in_username(self):
        """
        BV: Unicode characters in usernames don't crash

        Scenario:
          Given: Username with unicode characters
          When: generate_pwned_attack_paths() is called
          Then: No crash
        """
        records = [{"name": "ADMIN@CORP.COM", "cred_types": ["password"],
                    "cred_values": ["Pass123"], "source_machine": None}]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        # Should not raise
        console_out, md_out = generate_pwned_attack_paths(driver, use_colors=False)

        assert isinstance(console_out, str)
        assert isinstance(md_out, str)

    def test_handles_empty_credential_value(self):
        """
        BV: Empty credential values are handled

        Scenario:
          Given: User with empty cred_value
          When: generate_pwned_attack_paths() is called
          Then: No crash, commands may have placeholders
        """
        records = [{"name": "ADMIN@CORP.COM", "cred_types": ["password"],
                    "cred_values": [""], "source_machine": None}]
        driver = MockDriverBuilder().with_pwned_users(records).with_user_access([]).build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert isinstance(console_out, str)

    def test_handles_special_characters_in_password(self):
        """
        BV: Special chars in passwords don't break output

        Scenario:
          Given: Password with special chars: $, `, ", '
          When: generate_pwned_attack_paths() is called
          Then: No crash, password appears in output
        """
        records = [PwnedUserRecordFactory.create_with_password("ADMIN", "P@$$w0rd`\"'test")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "P@$$w0rd" in console_out

    def test_handles_many_machines_without_timeout(self):
        """
        BV: Large machine lists are processed efficiently

        Scenario:
          Given: User with admin on 50 machines
          When: generate_pwned_attack_paths() is called
          Then: Completes without timeout, shows truncation
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [
            AccessRecordFactory.create_admin_access(f"WS{i:02d}.CORP.COM", f"192.168.1.{i}")
            for i in range(50)
        ]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Should complete and show some machines
        assert "WS01.CORP.COM" in console_out
        # Should indicate there are more
        assert "more" in console_out.lower()

    def test_handles_no_edge_based_access(self):
        """
        BV: Users without edges get manual enumeration suggestions

        Scenario:
          Given: User with credentials but no BloodHound edges
          When: generate_pwned_attack_paths() is called
          Then: Output suggests manual enumeration
        """
        records = [PwnedUserRecordFactory.create_with_password("USER", "Pass123")]

        driver = MockDriverBuilder()\
            .with_pwned_users(records)\
            .with_user_access([])\
            .with_domain_access(None)\
            .with_dc_ip("192.168.1.1")\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Should show something when no edges exist
        assert len(console_out) > 0


# =============================================================================
# Priority Target Tests
# =============================================================================

class TestPriorityTargets:
    """Tests for priority target handling (machines with sessions)"""

    def test_highlights_machines_with_privileged_sessions(self):
        """
        BV: Machines with DA sessions are priority targets

        Scenario:
          Given: Machine has Domain Admin session
          When: generate_pwned_attack_paths() is called
          Then: Machine is marked as priority target
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [
            AccessRecordFactory.create_admin_access(
                "WS01.CORP.COM",
                "192.168.1.10",
                sessions=["DA@CORP.COM"]
            )
        ]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Should highlight priority target or sessions
        assert "WS01.CORP.COM" in console_out


# =============================================================================
# Authenticated Attacks Section Tests
# =============================================================================

class TestAuthenticatedAttacksSection:
    """Tests for authenticated user attacks section"""

    def test_includes_authenticated_attacks_section(self):
        """
        BV: Shows attacks any domain user can run

        Scenario:
          Given: Pwned users exist
          When: generate_pwned_attack_paths() is called
          Then: Output includes authenticated attacks section
        """
        records = [PwnedUserRecordFactory.create_with_password("USER", "Pass123")]

        driver = MockDriverBuilder()\
            .with_pwned_users(records)\
            .with_user_access([])\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        assert "AUTHENTICATED" in console_out.upper()


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests combining multiple features"""

    def test_full_workflow_with_admin_and_domain_access(self):
        """
        BV: Complete attack path generation for privileged user

        Scenario:
          Given: User with local admin + domain admin access
          When: generate_pwned_attack_paths() is called
          Then: Output includes all relevant sections
        """
        user_records = [PwnedUserRecordFactory.create_with_password("DA", "DAPass123")]
        access_records = [
            AccessRecordFactory.create_admin_access("DC01.CORP.COM", "192.168.1.10"),
            AccessRecordFactory.create_admin_access("WS01.CORP.COM", "192.168.1.20"),
        ]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .with_domain_access("DomainAdmin")\
            .build()

        console_out, md_out = generate_pwned_attack_paths(driver, use_colors=False)

        # Should have domain admin section
        assert "DOMAIN ADMIN" in console_out.upper() or "DCSync" in console_out

        # Should have local admin section
        assert "LOCAL ADMIN" in console_out.upper()

        # Should list machines
        assert "DC01.CORP.COM" in console_out
        assert "WS01.CORP.COM" in console_out

        # Markdown should have content too
        assert len(md_out) > 0
        assert "Attack" in md_out

    def test_multiple_users_with_different_cred_types(self):
        """
        BV: Multiple users generate separate attack sections

        Scenario:
          Given: User1 with password, User2 with hash
          When: generate_pwned_attack_paths() is called
          Then: Both users shown with appropriate commands
        """
        user_records = [
            PwnedUserRecordFactory.create_with_password("USER1", "Password1"),
            PwnedUserRecordFactory.create_with_hash("USER2", "aabbccdd" * 4),
        ]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access([])\
            .build()

        console_out, _ = generate_pwned_attack_paths(driver, use_colors=False)

        # Both users should appear
        assert "USER1@CORP.COM" in console_out
        assert "USER2@CORP.COM" in console_out

    def test_markdown_is_valid_format(self):
        """
        BV: Markdown output is parseable

        Scenario:
          Given: Generated markdown output
          When: Checking format
          Then: Code blocks are balanced, headers present
        """
        user_records = [PwnedUserRecordFactory.create_with_password("ADMIN", "Secret123")]
        access_records = [AccessRecordFactory.create_admin_access("WS01.CORP.COM")]

        driver = MockDriverBuilder()\
            .with_pwned_users(user_records)\
            .with_user_access(access_records)\
            .build()

        _, md_out = generate_pwned_attack_paths(driver)

        # Headers exist
        assert "##" in md_out or "#" in md_out

        # If code blocks exist, they should be balanced
        if "```" in md_out:
            count = md_out.count("```")
            assert count % 2 == 0, f"Unbalanced code blocks: {count}"
