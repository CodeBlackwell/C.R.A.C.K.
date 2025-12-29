"""
Tests for PRISM Credential Deduplication

Business Value Focus:
- BV:HIGH - No data loss from aggressive deduplication
- BV:HIGH - True duplicates are correctly merged
- BV:MEDIUM - Occurrence counts are accurate

Test Categories:
1. Exact Duplicate Removal - Identical credentials merged
2. Non-Duplicate Preservation - Different cred types preserved
3. Case Insensitivity - Username/domain case handled
4. Occurrence Counting - Duplicate counts tracked
"""

import pytest
from tools.post.prism.models.credential import Credential, CredentialType
from tools.post.prism.models.summary import ParsedSummary


class TestExactDuplicateRemoval:
    """Tests for merging identical credentials."""

    def test_removes_exact_duplicates(self, credential_factory, parsed_summary_factory):
        """
        BV: Prevents cluttered output from repeated credential captures.

        Scenario:
          Given: Summary with two identical credentials
          When: deduplicate() is called
          Then: Only one copy remains
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_removes_multiple_duplicates(self, credential_factory, parsed_summary_factory):
        """
        BV: Many duplicates of same credential collapse to one.

        Scenario:
          Given: Summary with 5 identical credentials
          When: deduplicate() is called
          Then: Only one remains
        """
        creds = [
            credential_factory.create(
                username="admin", domain="CORP",
                value="aabbccdd11223344aabbccdd11223344"
            )
            for _ in range(5)
        ]

        summary = parsed_summary_factory(credentials=creds)

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_preserves_first_occurrence(self, credential_factory, parsed_summary_factory):
        """
        BV: Original credential data is preserved (first seen).

        Scenario:
          Given: Duplicates with different first_seen_line
          When: deduplicate() is called
          Then: First occurrence's line preserved
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344",
            first_seen_line=10
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344",
            first_seen_line=50
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1
        assert deduped.credentials[0].first_seen_line == 10


class TestNonDuplicatePreservation:
    """Tests ensuring distinct credentials are not merged."""

    def test_different_usernames_not_merged(self, credential_factory, parsed_summary_factory):
        """
        BV: Different users' credentials are not lost.

        Scenario:
          Given: Two credentials with different usernames
          When: deduplicate() is called
          Then: Both credentials preserved
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="user1", domain="CORP",
            value="11223344aabbccdd11223344aabbccdd"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 2

    def test_different_domains_not_merged(self, credential_factory, parsed_summary_factory):
        """
        BV: Same username in different domains not merged.

        Scenario:
          Given: Same username in CORP and DEV domains
          When: deduplicate() is called
          Then: Both credentials preserved
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="DEV",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 2

    def test_different_cred_types_not_merged(self, credential_factory, parsed_summary_factory):
        """
        BV: NTLM and cleartext for same user are both valuable.

        Scenario:
          Given: Same user with NTLM and cleartext
          When: deduplicate() is called
          Then: Both credentials preserved

        Edge Case: User might have same hash appear in NTLM and password form.
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            cred_type=CredentialType.NTLM,
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            value="Password123!"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 2

        cred_types = {c.cred_type for c in deduped.credentials}
        assert CredentialType.NTLM in cred_types
        assert CredentialType.CLEARTEXT in cred_types

    def test_different_values_not_merged(self, credential_factory, parsed_summary_factory):
        """
        BV: Different hashes for same user are both kept.

        Scenario:
          Given: Same user with two different NTLM hashes
          When: deduplicate() is called
          Then: Both credentials preserved

        Edge Case: Password changed, both hashes captured.
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            value="11223344aabbccdd11223344aabbccdd"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 2


class TestCaseInsensitivity:
    """Tests for case-insensitive deduplication."""

    def test_username_case_insensitive_dedup(self, credential_factory, parsed_summary_factory):
        """
        BV: ADMIN and admin are the same user.

        Scenario:
          Given: Credentials with username case variation
          When: deduplicate() is called
          Then: Treated as duplicates
        """
        cred1 = credential_factory.create(
            username="ADMIN", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_domain_case_insensitive_dedup(self, credential_factory, parsed_summary_factory):
        """
        BV: CORP and corp are the same domain.

        Scenario:
          Given: Credentials with domain case variation
          When: deduplicate() is called
          Then: Treated as duplicates
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="corp",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_value_case_insensitive_dedup(self, credential_factory, parsed_summary_factory):
        """
        BV: Hex hashes with case variation are same hash.

        Scenario:
          Given: Same hash in uppercase and lowercase
          When: deduplicate() is called
          Then: Treated as duplicates
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="AABBCCDD11223344AABBCCDD11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1


class TestOccurrenceCounting:
    """Tests for occurrence count tracking."""

    def test_duplicate_increments_occurrence(self, credential_factory, parsed_summary_factory):
        """
        BV: Occurrence count shows how many times credential appeared.

        Scenario:
          Given: 3 identical credentials
          When: deduplicate() is called
          Then: Remaining credential has occurrences=3
        """
        creds = [
            credential_factory.create(
                username="admin", domain="CORP",
                value="aabbccdd11223344aabbccdd11223344"
            )
            for _ in range(3)
        ]

        summary = parsed_summary_factory(credentials=creds)

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1
        assert deduped.credentials[0].occurrences == 3

    def test_unique_credentials_have_occurrence_one(
        self, credential_factory, parsed_summary_factory
    ):
        """
        BV: Unique credentials retain occurrence count of 1.

        Scenario:
          Given: Two different credentials
          When: deduplicate() is called
          Then: Each has occurrences=1
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="user1", domain="CORP",
            value="11223344aabbccdd11223344aabbccdd"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        for cred in deduped.credentials:
            assert cred.occurrences == 1


class TestMixedScenarios:
    """Tests for realistic mixed credential scenarios."""

    def test_mixed_duplicates_and_unique(self, credential_factory, parsed_summary_factory):
        """
        BV: Real output has mix of duplicates and unique credentials.

        Scenario:
          Given: Mix of duplicates and unique credentials
          When: deduplicate() is called
          Then: Correct number preserved with correct counts
        """
        # 3 duplicates of admin
        admin_creds = [
            credential_factory.create(
                username="admin", domain="CORP",
                value="aabbccdd11223344aabbccdd11223344"
            )
            for _ in range(3)
        ]

        # 2 duplicates of user1
        user1_creds = [
            credential_factory.create(
                username="user1", domain="CORP",
                value="11223344aabbccdd11223344aabbccdd"
            )
            for _ in range(2)
        ]

        # 1 unique user2
        user2_cred = credential_factory.create(
            username="user2", domain="CORP",
            value="55667788aabbccdd55667788aabbccdd"
        )

        all_creds = admin_creds + user1_creds + [user2_cred]
        summary = parsed_summary_factory(credentials=all_creds)

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 3

        creds_by_user = {c.username: c for c in deduped.credentials}
        assert creds_by_user["admin"].occurrences == 3
        assert creds_by_user["user1"].occurrences == 2
        assert creds_by_user["user2"].occurrences == 1

    def test_same_user_multiple_cred_types(self, credential_factory, parsed_summary_factory):
        """
        BV: User with NTLM, SHA1, and cleartext keeps all types.

        Scenario:
          Given: Same user with 3 different credential types
          When: deduplicate() is called
          Then: All 3 types preserved
        """
        creds = [
            credential_factory.create(
                username="admin", domain="CORP",
                cred_type=CredentialType.NTLM,
                value="aabbccdd11223344aabbccdd11223344"
            ),
            credential_factory.create(
                username="admin", domain="CORP",
                cred_type=CredentialType.SHA1,
                value="a" * 40
            ),
            credential_factory.create(
                username="admin", domain="CORP",
                cred_type=CredentialType.CLEARTEXT,
                value="Password123!"
            ),
        ]

        summary = parsed_summary_factory(credentials=creds)

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 3


class TestEdgeCases:
    """Tests for edge cases in deduplication."""

    def test_empty_credentials_list(self, parsed_summary_factory):
        """
        BV: Empty input doesn't crash.

        Scenario:
          Given: Summary with no credentials
          When: deduplicate() is called
          Then: Returns empty list (no crash)
        """
        summary = parsed_summary_factory(credentials=[])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 0

    def test_single_credential(self, credential_factory, parsed_summary_factory):
        """
        BV: Single credential passes through unchanged.

        Scenario:
          Given: Summary with one credential
          When: deduplicate() is called
          Then: Same credential returned
        """
        cred = credential_factory.create()
        summary = parsed_summary_factory(credentials=[cred])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_empty_username_credentials(self, parsed_summary_factory):
        """
        BV: Empty usernames don't cause errors.

        Scenario:
          Given: Credentials with empty usernames
          When: deduplicate() is called
          Then: Handles gracefully
        """
        cred1 = Credential(
            username="",
            domain="CORP",
            cred_type=CredentialType.NTLM,
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = Credential(
            username="",
            domain="CORP",
            cred_type=CredentialType.NTLM,
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_empty_domain_credentials(self, credential_factory, parsed_summary_factory):
        """
        BV: Empty domains are valid (local accounts).

        Scenario:
          Given: Credentials with empty domains
          When: deduplicate() is called
          Then: Handles correctly
        """
        cred1 = credential_factory.create(
            username="admin", domain="",
            value="aabbccdd11223344aabbccdd11223344"
        )
        cred2 = credential_factory.create(
            username="admin", domain="",
            value="aabbccdd11223344aabbccdd11223344"
        )

        summary = parsed_summary_factory(credentials=[cred1, cred2])

        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1

    def test_none_value_handling(self, parsed_summary_factory):
        """
        BV: None values don't crash deduplication.

        Scenario:
          Given: Credential with None value
          When: deduplicate() is called
          Then: Handles gracefully
        """
        cred = Credential(
            username="test",
            domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            value=None
        )

        summary = parsed_summary_factory(credentials=[cred])

        # Should not raise
        deduped = summary.deduplicate()

        assert len(deduped.credentials) == 1


class TestReturnValueImmutability:
    """Tests ensuring deduplicate doesn't modify original."""

    def test_original_not_modified(self, credential_factory, parsed_summary_factory):
        """
        BV: Original summary remains unchanged after dedup.

        Scenario:
          Given: Summary with duplicates
          When: deduplicate() is called
          Then: Original summary unchanged
        """
        creds = [
            credential_factory.create(
                username="admin", domain="CORP",
                value="aabbccdd11223344aabbccdd11223344"
            )
            for _ in range(3)
        ]

        summary = parsed_summary_factory(credentials=creds)
        original_count = len(summary.credentials)

        deduped = summary.deduplicate()

        # Original unchanged
        assert len(summary.credentials) == original_count
        assert len(summary.credentials) == 3

        # Deduped is different
        assert len(deduped.credentials) == 1

    def test_returns_new_summary(self, credential_factory, parsed_summary_factory):
        """
        BV: Deduplicate returns new object, not modified original.

        Scenario:
          Given: Summary
          When: deduplicate() is called
          Then: New summary object returned
        """
        summary = parsed_summary_factory(credentials=[
            credential_factory.create()
        ])

        deduped = summary.deduplicate()

        assert deduped is not summary


class TestSummaryMetadataPreservation:
    """Tests that dedup preserves summary metadata."""

    def test_preserves_source_info(self, credential_factory, parsed_summary_factory):
        """
        BV: Source file info preserved after dedup.

        Scenario:
          Given: Summary with source metadata
          When: deduplicate() is called
          Then: Metadata preserved in result
        """
        summary = parsed_summary_factory(
            source_file="/path/to/output.txt",
            source_tool="mimikatz",
            credentials=[credential_factory.create()]
        )

        deduped = summary.deduplicate()

        assert deduped.source_file == "/path/to/output.txt"
        assert deduped.source_tool == "mimikatz"

    def test_preserves_sessions(self, credential_factory, parsed_summary_factory, logon_session_factory):
        """
        BV: Session list preserved after dedup.

        Scenario:
          Given: Summary with sessions
          When: deduplicate() is called
          Then: Sessions unchanged
        """
        session = logon_session_factory()
        summary = parsed_summary_factory(
            sessions=[session],
            credentials=[credential_factory.create()]
        )

        deduped = summary.deduplicate()

        assert len(deduped.sessions) == 1


class TestTicketDeduplication:
    """Tests for ticket deduplication (if implemented)."""

    def test_ticket_dedup_by_service_and_client(self, parsed_summary_factory):
        """
        BV: Duplicate tickets are merged like credentials.

        Scenario:
          Given: Summary with duplicate tickets
          When: deduplicate() is called
          Then: Ticket duplicates merged

        Note: Depends on ticket model implementation.
        """
        # Ticket dedup tests would go here if KerberosTicket model
        # has similar dedup logic
        pass
