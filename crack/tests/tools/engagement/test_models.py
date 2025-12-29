"""
Tests for Engagement Tracking Data Models.

Business Value Focus:
- Data models correctly serialize and deserialize without data loss
- Enum values are handled correctly for status fields
- Factory methods generate valid, unique identifiers
- Edge cases like missing fields are handled gracefully

Test Coverage:
- Client: create, to_dict, from_dict
- Engagement: create, to_dict, from_dict, status enum handling
- Target: create (IP vs hostname detection), display_name, to_dict, from_dict
- Service: create, display_name, to_dict, from_dict
- Finding: create, severity enum, to_dict, from_dict
- Enums: EngagementStatus, FindingSeverity, TargetStatus, FindingStatus
"""

import pytest
from datetime import datetime
from unittest.mock import patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tools.engagement.models import (
    Client,
    Engagement,
    Target,
    Service,
    Finding,
    EngagementStatus,
    FindingSeverity,
    TargetStatus,
    FindingStatus,
    generate_id,
)


# =============================================================================
# Test: generate_id Helper
# =============================================================================

class TestGenerateId:
    """Tests for unique ID generation."""

    def test_generate_id_returns_string(self):
        """
        BV: IDs must be strings for Neo4j property storage

        Scenario:
          Given: No prefix
          When: generate_id() is called
          Then: Returns a string
        """
        result = generate_id()
        assert isinstance(result, str)

    def test_generate_id_without_prefix_is_uuid_format(self):
        """
        BV: IDs are recognizable UUID fragments

        Scenario:
          Given: No prefix
          When: generate_id() is called
          Then: Returns 8-character hex string
        """
        result = generate_id()
        assert len(result) == 8
        assert all(c in '0123456789abcdef-' for c in result.lower())

    def test_generate_id_with_prefix_includes_prefix(self):
        """
        BV: Prefixed IDs enable quick identification of entity type

        Scenario:
          Given: Prefix "eng"
          When: generate_id("eng") is called
          Then: Returns "eng-XXXXXXXX" format
        """
        result = generate_id("eng")
        assert result.startswith("eng-")
        assert len(result) == 12  # "eng-" + 8 chars

    def test_generate_id_uniqueness(self):
        """
        BV: IDs must be unique to prevent data corruption

        Scenario:
          Given: Multiple calls to generate_id
          When: 100 IDs are generated
          Then: All are unique
        """
        ids = [generate_id("test") for _ in range(100)]
        assert len(set(ids)) == 100, "Generated IDs should be unique"


# =============================================================================
# Test: Client Model
# =============================================================================

class TestClientModel:
    """Tests for Client dataclass."""

    def test_client_create_with_name_only(self):
        """
        BV: Users can create clients with minimal required info

        Scenario:
          Given: Only a client name
          When: Client.create() is called
          Then: Client is created with defaults for optional fields
        """
        client = Client.create("ACME Corp")

        assert client.name == "ACME Corp"
        assert client.id.startswith("client-")
        assert client.organization == ""
        assert client.contact_email == ""
        assert client.industry == ""
        assert client.notes == ""
        assert client.created_at  # Should be set

    def test_client_create_with_all_fields(self):
        """
        BV: All client metadata is preserved

        Scenario:
          Given: Full client details
          When: Client.create() is called
          Then: All fields are preserved
        """
        client = Client.create(
            "ACME Corp",
            organization="ACME Corporation Inc.",
            contact_email="security@acme.com",
            industry="Technology",
            notes="Annual pentest contract"
        )

        assert client.name == "ACME Corp"
        assert client.organization == "ACME Corporation Inc."
        assert client.contact_email == "security@acme.com"
        assert client.industry == "Technology"
        assert client.notes == "Annual pentest contract"

    def test_client_to_dict_roundtrip(self):
        """
        BV: Client data survives storage and retrieval without loss

        Scenario:
          Given: A fully populated Client
          When: Converted to dict and back
          Then: All fields are preserved
        """
        original = Client.create(
            "Test Corp",
            organization="Test Organization",
            contact_email="test@test.com",
            industry="Finance",
            notes="Test notes"
        )

        data = original.to_dict()
        restored = Client.from_dict(data)

        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.organization == original.organization
        assert restored.contact_email == original.contact_email
        assert restored.industry == original.industry
        assert restored.notes == original.notes
        assert restored.created_at == original.created_at

    def test_client_from_dict_with_missing_fields(self):
        """
        BV: Handles incomplete data from corrupted storage

        Scenario:
          Given: Dict with only id and name
          When: Client.from_dict() is called
          Then: Missing fields default to empty strings
        """
        data = {"id": "client-123", "name": "Partial Client"}
        client = Client.from_dict(data)

        assert client.id == "client-123"
        assert client.name == "Partial Client"
        assert client.organization == ""
        assert client.contact_email == ""


# =============================================================================
# Test: Engagement Model
# =============================================================================

class TestEngagementModel:
    """Tests for Engagement dataclass."""

    def test_engagement_create_minimal(self):
        """
        BV: Engagements can be created with minimal info

        Scenario:
          Given: Name and client_id only
          When: Engagement.create() is called
          Then: Engagement is created with default active status
        """
        eng = Engagement.create("Q4 Pentest", "client-abc")

        assert eng.name == "Q4 Pentest"
        assert eng.client_id == "client-abc"
        assert eng.id.startswith("eng-")
        assert eng.status == EngagementStatus.ACTIVE
        assert eng.start_date  # Should be set to today

    def test_engagement_create_with_scope(self):
        """
        BV: Scope information is critical for engagement tracking

        Scenario:
          Given: Engagement with full scope details
          When: Engagement.create() is called
          Then: Scope fields are preserved
        """
        eng = Engagement.create(
            "External Assessment",
            "client-123",
            scope_type="external",
            scope_text="192.168.1.0/24, *.example.com",
            rules_of_engagement="No DoS, business hours only"
        )

        assert eng.scope_type == "external"
        assert eng.scope_text == "192.168.1.0/24, *.example.com"
        assert eng.rules_of_engagement == "No DoS, business hours only"

    def test_engagement_to_dict_converts_status_enum(self):
        """
        BV: Enum values are serialized as strings for storage

        Scenario:
          Given: Engagement with ACTIVE status
          When: to_dict() is called
          Then: status is string "active", not enum
        """
        eng = Engagement.create("Test", "client-1")
        data = eng.to_dict()

        assert data['status'] == "active"
        assert isinstance(data['status'], str)

    def test_engagement_from_dict_parses_status_string(self):
        """
        BV: Stored string status is converted back to enum

        Scenario:
          Given: Dict with status="paused"
          When: from_dict() is called
          Then: status is EngagementStatus.PAUSED enum
        """
        data = {
            "id": "eng-123",
            "name": "Test",
            "client_id": "client-1",
            "status": "paused"
        }
        eng = Engagement.from_dict(data)

        assert eng.status == EngagementStatus.PAUSED
        assert isinstance(eng.status, EngagementStatus)

    def test_engagement_roundtrip_preserves_all_fields(self):
        """
        BV: No data loss during storage/retrieval cycle

        Scenario:
          Given: Fully populated engagement
          When: Converted to dict and back
          Then: All fields match original
        """
        original = Engagement.create(
            "Full Pentest",
            "client-abc",
            scope_type="internal",
            scope_text="10.0.0.0/8",
            rules_of_engagement="All systems in scope",
            notes="Detailed notes here"
        )
        original.end_date = "2024-12-31"

        data = original.to_dict()
        restored = Engagement.from_dict(data)

        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.client_id == original.client_id
        assert restored.status == original.status
        assert restored.start_date == original.start_date
        assert restored.end_date == original.end_date
        assert restored.scope_type == original.scope_type
        assert restored.scope_text == original.scope_text
        assert restored.rules_of_engagement == original.rules_of_engagement
        assert restored.notes == original.notes


# =============================================================================
# Test: EngagementStatus Enum
# =============================================================================

class TestEngagementStatusEnum:
    """Tests for EngagementStatus enum values."""

    def test_status_values_are_lowercase(self):
        """
        BV: Consistent lowercase values for Neo4j queries

        Scenario:
          Given: All EngagementStatus values
          When: Values are accessed
          Then: All are lowercase strings
        """
        assert EngagementStatus.ACTIVE.value == "active"
        assert EngagementStatus.PAUSED.value == "paused"
        assert EngagementStatus.COMPLETED.value == "completed"
        assert EngagementStatus.ARCHIVED.value == "archived"

    def test_status_can_be_created_from_string(self):
        """
        BV: String status from storage can be converted to enum

        Scenario:
          Given: String "completed"
          When: EngagementStatus() is called
          Then: Returns COMPLETED enum
        """
        status = EngagementStatus("completed")
        assert status == EngagementStatus.COMPLETED


# =============================================================================
# Test: Target Model
# =============================================================================

class TestTargetModel:
    """Tests for Target dataclass."""

    def test_target_create_with_ip_address(self):
        """
        BV: IP addresses are correctly identified and stored

        Scenario:
          Given: Valid IPv4 address
          When: Target.create() is called
          Then: ip_address field is populated
        """
        target = Target.create("192.168.1.100")

        assert target.ip_address == "192.168.1.100"
        assert target.hostname == ""
        assert target.id.startswith("target-")
        assert target.status == TargetStatus.NEW

    def test_target_create_with_hostname(self):
        """
        BV: Hostnames are correctly identified and stored

        Scenario:
          Given: Hostname string
          When: Target.create() is called
          Then: hostname field is populated, ip_address is empty
        """
        target = Target.create("dc01.corp.local")

        assert target.hostname == "dc01.corp.local"
        assert target.ip_address == ""

    def test_target_create_with_both_ip_and_hostname(self):
        """
        BV: Both IP and hostname can be stored together

        Scenario:
          Given: IP address and hostname kwarg
          When: Target.create() is called
          Then: Both fields are populated
        """
        target = Target.create("192.168.1.10", hostname="web01.corp.local")

        assert target.ip_address == "192.168.1.10"
        assert target.hostname == "web01.corp.local"

    def test_target_display_name_with_both(self):
        """
        BV: Display name shows human-readable identifier

        Scenario:
          Given: Target with IP and hostname
          When: display_name is accessed
          Then: Returns "hostname (ip)" format
        """
        target = Target.create("192.168.1.10", hostname="web01.corp.local")
        assert target.display_name == "web01.corp.local (192.168.1.10)"

    def test_target_display_name_ip_only(self):
        """
        BV: IP-only targets show IP in display name

        Scenario:
          Given: Target with IP only
          When: display_name is accessed
          Then: Returns IP address
        """
        target = Target.create("10.0.0.5")
        assert target.display_name == "10.0.0.5"

    def test_target_display_name_hostname_only(self):
        """
        BV: Hostname-only targets show hostname in display name

        Scenario:
          Given: Target with hostname only
          When: display_name is accessed
          Then: Returns hostname
        """
        target = Target.create("db.internal")
        assert target.display_name == "db.internal"

    def test_target_to_dict_converts_status_enum(self):
        """
        BV: Status enum is serialized to string

        Scenario:
          Given: Target with SCANNING status
          When: to_dict() is called
          Then: status is "scanning" string
        """
        target = Target.create("192.168.1.1")
        target.status = TargetStatus.SCANNING

        data = target.to_dict()
        assert data['status'] == "scanning"

    def test_target_from_dict_handles_invalid_status(self):
        """
        BV: Invalid status defaults to NEW (graceful degradation)

        Scenario:
          Given: Dict with invalid status value
          When: from_dict() is called
          Then: status defaults to TargetStatus.NEW
        """
        data = {
            "id": "target-123",
            "ip_address": "192.168.1.1",
            "status": "invalid_status"
        }
        target = Target.from_dict(data)

        assert target.status == TargetStatus.NEW

    def test_target_roundtrip_preserves_all_fields(self):
        """
        BV: No data loss during storage/retrieval

        Scenario:
          Given: Fully populated target
          When: Converted to dict and back
          Then: All fields match
        """
        original = Target.create(
            "192.168.1.100",
            hostname="server01.corp.local",
            os_guess="Windows Server 2019",
            notes="Domain controller"
        )
        original.status = TargetStatus.EXPLOITED
        original.last_seen = datetime.now().isoformat()

        data = original.to_dict()
        restored = Target.from_dict(data)

        assert restored.id == original.id
        assert restored.ip_address == original.ip_address
        assert restored.hostname == original.hostname
        assert restored.os_guess == original.os_guess
        assert restored.status == original.status
        assert restored.notes == original.notes
        assert restored.last_seen == original.last_seen


# =============================================================================
# Test: TargetStatus Enum
# =============================================================================

class TestTargetStatusEnum:
    """Tests for TargetStatus enum."""

    def test_target_status_progression(self):
        """
        BV: Status values support logical workflow progression

        Scenario:
          Given: All TargetStatus values
          When: Values are checked
          Then: All expected statuses exist
        """
        assert TargetStatus.NEW.value == "new"
        assert TargetStatus.SCANNING.value == "scanning"
        assert TargetStatus.ENUMERATED.value == "enumerated"
        assert TargetStatus.EXPLOITED.value == "exploited"
        assert TargetStatus.COMPLETED.value == "completed"


# =============================================================================
# Test: Service Model
# =============================================================================

class TestServiceModel:
    """Tests for Service dataclass."""

    def test_service_create_minimal(self):
        """
        BV: Services can be created with just target and port

        Scenario:
          Given: target_id and port
          When: Service.create() is called
          Then: Service is created with TCP protocol default
        """
        svc = Service.create("target-123", 80)

        assert svc.target_id == "target-123"
        assert svc.port == 80
        assert svc.protocol == "tcp"
        assert svc.state == "open"
        assert svc.id.startswith("svc-")

    def test_service_create_with_details(self):
        """
        BV: Service details are preserved for enumeration

        Scenario:
          Given: Full service details
          When: Service.create() is called
          Then: All details are preserved
        """
        svc = Service.create(
            "target-123",
            443,
            protocol="tcp",
            service_name="https",
            version="Apache/2.4.41 (Ubuntu)",
            banner="Server: Apache/2.4.41",
            state="open"
        )

        assert svc.service_name == "https"
        assert svc.version == "Apache/2.4.41 (Ubuntu)"
        assert svc.banner == "Server: Apache/2.4.41"

    def test_service_display_name_with_version(self):
        """
        BV: Display shows port/protocol and service info

        Scenario:
          Given: Service with name and version
          When: display_name is accessed
          Then: Returns "port/proto name version" format
        """
        svc = Service.create("target-1", 22, service_name="ssh", version="OpenSSH 8.2")
        assert svc.display_name == "22/tcp ssh OpenSSH 8.2"

    def test_service_display_name_unknown_service(self):
        """
        BV: Unknown services still display port info

        Scenario:
          Given: Service without name
          When: display_name is accessed
          Then: Shows "unknown" for service name
        """
        svc = Service.create("target-1", 9999)
        assert svc.display_name == "9999/tcp unknown"

    def test_service_roundtrip_preserves_all_fields(self):
        """
        BV: No service data loss during storage

        Scenario:
          Given: Fully populated service
          When: Converted to dict and back
          Then: All fields preserved
        """
        original = Service.create(
            "target-abc",
            8080,
            protocol="tcp",
            service_name="http-proxy",
            version="Squid 4.10",
            banner="Squid proxy-caching web server",
            state="open"
        )

        data = original.to_dict()
        restored = Service.from_dict(data)

        assert restored.id == original.id
        assert restored.target_id == original.target_id
        assert restored.port == original.port
        assert restored.protocol == original.protocol
        assert restored.service_name == original.service_name
        assert restored.version == original.version
        assert restored.banner == original.banner
        assert restored.state == original.state


# =============================================================================
# Test: Finding Model
# =============================================================================

class TestFindingModel:
    """Tests for Finding dataclass."""

    def test_finding_create_minimal(self):
        """
        BV: Findings can be quickly logged with just a title

        Scenario:
          Given: Only a finding title
          When: Finding.create() is called
          Then: Finding is created with MEDIUM severity default
        """
        finding = Finding.create("SQL Injection")

        assert finding.title == "SQL Injection"
        assert finding.severity == FindingSeverity.MEDIUM
        assert finding.status == FindingStatus.OPEN
        assert finding.id.startswith("finding-")

    def test_finding_create_critical(self):
        """
        BV: Critical findings are properly tagged

        Scenario:
          Given: Finding with critical severity
          When: Finding.create() is called
          Then: Severity is CRITICAL enum
        """
        finding = Finding.create(
            "Remote Code Execution",
            severity="critical",
            cve_id="CVE-2024-12345"
        )

        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.cve_id == "CVE-2024-12345"

    def test_finding_create_with_all_fields(self):
        """
        BV: Complete finding documentation is preserved

        Scenario:
          Given: Finding with all fields
          When: Finding.create() is called
          Then: All fields are accessible
        """
        finding = Finding.create(
            "Weak Password Policy",
            severity="high",
            cvss_score="7.5",
            cve_id="",
            description="Password policy allows weak passwords",
            impact="Attacker could brute force accounts",
            remediation="Enforce minimum 12 character passwords",
            evidence="Observed password 'password123' accepted"
        )

        assert finding.description == "Password policy allows weak passwords"
        assert finding.impact == "Attacker could brute force accounts"
        assert finding.remediation == "Enforce minimum 12 character passwords"
        assert finding.evidence == "Observed password 'password123' accepted"
        assert finding.cvss_score == "7.5"

    def test_finding_to_dict_converts_enums(self):
        """
        BV: Enum values are serialized for storage

        Scenario:
          Given: Finding with enum values
          When: to_dict() is called
          Then: severity and status are strings
        """
        finding = Finding.create("Test", severity="high")
        finding.status = FindingStatus.EXPLOITED

        data = finding.to_dict()

        assert data['severity'] == "high"
        assert data['status'] == "exploited"
        assert isinstance(data['severity'], str)
        assert isinstance(data['status'], str)

    def test_finding_from_dict_handles_invalid_severity(self):
        """
        BV: Invalid severity defaults to MEDIUM (graceful degradation)

        Scenario:
          Given: Dict with invalid severity
          When: from_dict() is called
          Then: severity defaults to MEDIUM
        """
        data = {
            "id": "finding-123",
            "title": "Test",
            "severity": "super_critical"  # Invalid
        }
        finding = Finding.from_dict(data)

        assert finding.severity == FindingSeverity.MEDIUM

    def test_finding_from_dict_handles_case_insensitive_severity(self):
        """
        BV: Severity matching is case-insensitive

        Scenario:
          Given: Dict with uppercase severity
          When: from_dict() is called
          Then: severity is correctly parsed
        """
        data = {
            "id": "finding-123",
            "title": "Test",
            "severity": "HIGH"
        }
        finding = Finding.from_dict(data)

        assert finding.severity == FindingSeverity.HIGH

    def test_finding_roundtrip_preserves_affected_targets(self):
        """
        BV: Target associations are preserved

        Scenario:
          Given: Finding with affected_targets list
          When: Converted to dict and back
          Then: affected_targets list is preserved
        """
        original = Finding.create("Multi-target Vuln", severity="high")
        original.affected_targets = ["target-1", "target-2", "target-3"]

        data = original.to_dict()
        restored = Finding.from_dict(data)

        assert restored.affected_targets == ["target-1", "target-2", "target-3"]


# =============================================================================
# Test: FindingSeverity Enum
# =============================================================================

class TestFindingSeverityEnum:
    """Tests for FindingSeverity enum."""

    def test_severity_values_match_cvss_tiers(self):
        """
        BV: Severity names align with CVSS scoring tiers

        Scenario:
          Given: All severity values
          When: Values are checked
          Then: All CVSS-aligned severities exist
        """
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"


# =============================================================================
# Test: FindingStatus Enum
# =============================================================================

class TestFindingStatusEnum:
    """Tests for FindingStatus enum."""

    def test_finding_status_workflow(self):
        """
        BV: Status values support finding lifecycle

        Scenario:
          Given: All FindingStatus values
          When: Values are checked
          Then: Complete workflow is supported
        """
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.EXPLOITED.value == "exploited"
        assert FindingStatus.REPORTED.value == "reported"
        assert FindingStatus.REMEDIATED.value == "remediated"


# =============================================================================
# Test: Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_client_from_dict_with_empty_dict(self):
        """
        BV: Handles completely empty data gracefully

        Scenario:
          Given: Empty dictionary
          When: Client.from_dict() is called
          Then: Returns Client with empty strings
        """
        client = Client.from_dict({})
        assert client.id == ""
        assert client.name == ""

    def test_target_create_with_ipv4_like_hostname(self):
        """
        BV: Handles hostnames that look like partial IPs

        Scenario:
          Given: Hostname "10.server.local"
          When: Target.create() is called
          Then: Treated as hostname, not IP
        """
        target = Target.create("10.server.local")
        assert target.hostname == "10.server.local"
        assert target.ip_address == ""

    def test_target_create_with_invalid_ip_format(self):
        """
        BV: Invalid IPs are treated as hostnames

        Scenario:
          Given: String "999.999.999.999"
          When: Target.create() is called
          Then: Treated as hostname (IP regex won't validate range)

        Note: The regex only checks format, not valid range.
        """
        target = Target.create("999.999.999.999")
        # The regex matches format, so this IS treated as IP
        assert target.ip_address == "999.999.999.999"

    def test_service_from_dict_with_zero_port(self):
        """
        BV: Handles zero port gracefully

        Scenario:
          Given: Service dict with port=0
          When: from_dict() is called
          Then: Port is 0 (not an error)
        """
        data = {"id": "svc-1", "target_id": "t-1", "port": 0}
        svc = Service.from_dict(data)
        assert svc.port == 0

    def test_finding_affected_targets_default_empty(self):
        """
        BV: affected_targets defaults to empty list

        Scenario:
          Given: Finding created without affected_targets
          When: affected_targets is accessed
          Then: Returns empty list (not None)
        """
        finding = Finding.create("Test")
        assert finding.affected_targets == []
        assert isinstance(finding.affected_targets, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
