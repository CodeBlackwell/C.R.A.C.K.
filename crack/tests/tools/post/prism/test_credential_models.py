"""
Tests for PRISM Credential Models

Business Value Focus:
- BV:MEDIUM - Credential property accuracy
- BV:HIGH - Dedup key generation correctness
- BV:MEDIUM - Serialization completeness

Test Categories:
1. Property Computation - is_machine_account, high_value, is_null_password
2. Dedup Key Generation - Key format, case insensitivity
3. Serialization - to_dict, to_neo4j_dict roundtrip
4. Display Formatting - account_key, display_type
"""

import pytest


class TestIsMachineAccount:
    """Tests for is_machine_account property."""

    def test_account_ending_with_dollar_is_machine(self, credential_factory):
        """
        BV: Machine accounts (DC01$, WORKSTATION$) are correctly identified.

        Scenario:
          Given: Credential with username ending in $
          When: is_machine_account property checked
          Then: Returns True
        """
        cred = credential_factory.create(username="DC01$")

        assert cred.is_machine_account is True

    def test_regular_user_not_machine(self, credential_factory):
        """
        BV: Regular users are not incorrectly flagged as machines.

        Scenario:
          Given: Credential with normal username
          When: is_machine_account property checked
          Then: Returns False
        """
        cred = credential_factory.create(username="administrator")

        assert cred.is_machine_account is False

    def test_dollar_in_middle_not_machine(self, credential_factory):
        """
        BV: Usernames with $ not at end are not machine accounts.

        Scenario:
          Given: Credential with $ in middle of username
          When: is_machine_account property checked
          Then: Returns False
        """
        cred = credential_factory.create(username="user$admin")

        assert cred.is_machine_account is False

    def test_empty_username_not_machine(self, credential_factory):
        """
        BV: Empty usernames don't crash the check.

        Scenario:
          Given: Credential with empty username
          When: is_machine_account property checked
          Then: Returns False (no crash)
        """
        cred = credential_factory.create(username="")

        assert cred.is_machine_account is False


class TestIsServiceAccount:
    """Tests for is_service_account property."""

    def test_local_service_is_service_account(self, credential_factory):
        """
        BV: Well-known service accounts are identified.

        Scenario:
          Given: Credential with "LOCAL SERVICE" username
          When: is_service_account property checked
          Then: Returns True
        """
        cred = credential_factory.create(username="LOCAL SERVICE", domain="NT AUTHORITY")

        assert cred.is_service_account is True

    def test_nt_authority_domain_is_service(self, credential_factory):
        """
        BV: NT AUTHORITY domain indicates service account.

        Scenario:
          Given: Credential with NT AUTHORITY domain
          When: is_service_account property checked
          Then: Returns True
        """
        cred = credential_factory.create(username="SYSTEM", domain="NT AUTHORITY")

        assert cred.is_service_account is True

    def test_dwm_is_service_account(self, credential_factory):
        """
        BV: Desktop Window Manager accounts are service accounts.

        Scenario:
          Given: Credential with DWM-1 username
          When: is_service_account property checked
          Then: Returns True
        """
        cred = credential_factory.create(username="DWM-1")

        assert cred.is_service_account is True

    def test_regular_user_not_service(self, credential_factory):
        """
        BV: Regular domain users are not service accounts.

        Scenario:
          Given: Credential with regular username
          When: is_service_account property checked
          Then: Returns False
        """
        cred = credential_factory.create(username="jsmith", domain="CORP")

        assert cred.is_service_account is False


class TestIsNullPassword:
    """Tests for is_null_password property."""

    def test_null_literal_is_null(self, credential_factory):
        """
        BV: "(null)" value is correctly identified.

        Scenario:
          Given: Credential with "(null)" password
          When: is_null_password property checked
          Then: Returns True
        """
        cred = credential_factory.create_null_password()

        assert cred.is_null_password is True

    def test_empty_string_is_null(self, credential_factory):
        """
        BV: Empty password is considered null.

        Scenario:
          Given: Credential with empty string value
          When: is_null_password property checked
          Then: Returns True
        """
        from tools.post.prism.models.credential import Credential, CredentialType

        cred = Credential(
            username="test",
            domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            value=""
        )

        assert cred.is_null_password is True

    def test_real_password_not_null(self, credential_factory):
        """
        BV: Actual passwords are not flagged as null.

        Scenario:
          Given: Credential with real password
          When: is_null_password property checked
          Then: Returns False
        """
        cred = credential_factory.create_cleartext(password="RealPassword123!")

        assert cred.is_null_password is False


class TestHighValue:
    """Tests for high_value property."""

    def test_cleartext_admin_is_high_value(self, credential_factory):
        """
        BV: Cleartext passwords for regular users are high value.

        Scenario:
          Given: Cleartext credential for regular user
          When: high_value property checked
          Then: Returns True
        """
        cred = credential_factory.create_high_value()

        assert cred.high_value is True

    def test_null_password_not_high_value(self, credential_factory):
        """
        BV: Null passwords are not high value.

        Scenario:
          Given: Credential with null password
          When: high_value property checked
          Then: Returns False
        """
        cred = credential_factory.create_null_password()

        assert cred.high_value is False

    def test_machine_account_not_high_value(self, credential_factory):
        """
        BV: Machine account NTLM is not flagged as high value.

        Scenario:
          Given: Machine account with NTLM hash
          When: high_value property checked
          Then: Returns False
        """
        cred = credential_factory.create_machine_account()

        assert cred.high_value is False

    def test_service_account_not_high_value(self, credential_factory):
        """
        BV: Service account credentials are not high value.

        Scenario:
          Given: Service account credential
          When: high_value property checked
          Then: Returns False
        """
        cred = credential_factory.create_service_account()

        assert cred.high_value is False

    def test_regular_user_ntlm_is_high_value(self, credential_factory):
        """
        BV: Regular user NTLM hashes are high value.

        Scenario:
          Given: Regular user with NTLM hash
          When: high_value property checked
          Then: Returns True
        """
        cred = credential_factory.create_ntlm(username="jsmith", domain="CORP")

        assert cred.high_value is True


class TestDedupKey:
    """Tests for dedup_key property."""

    def test_dedup_key_is_tuple(self, credential_factory):
        """
        BV: Dedup key is hashable for use in sets/dicts.

        Scenario:
          Given: Any credential
          When: dedup_key property accessed
          Then: Returns tuple
        """
        cred = credential_factory.create()

        assert isinstance(cred.dedup_key, tuple)

    def test_dedup_key_includes_all_identifying_fields(self, credential_factory):
        """
        BV: Dedup key considers username, domain, type, and value.

        Scenario:
          Given: Credential with all fields
          When: dedup_key checked
          Then: All fields contribute to key
        """
        cred = credential_factory.create(
            username="admin",
            domain="CORP",
            value="aabbccdd11223344aabbccdd11223344"
        )

        key = cred.dedup_key
        assert len(key) == 4
        assert "admin" in key  # Username (lowercase)
        assert "corp" in key   # Domain (lowercase)

    def test_dedup_key_case_insensitive(self, credential_factory):
        """
        BV: Dedup key matches regardless of case.

        Scenario:
          Given: Two credentials differing only in case
          When: dedup_keys compared
          Then: Keys are equal
        """
        cred1 = credential_factory.create(
            username="ADMIN",
            domain="CORP",
            value="AABBCCDD11223344AABBCCDD11223344"
        )
        cred2 = credential_factory.create(
            username="admin",
            domain="corp",
            value="aabbccdd11223344aabbccdd11223344"
        )

        assert cred1.dedup_key == cred2.dedup_key

    def test_different_cred_types_different_keys(self, credential_factory):
        """
        BV: Same user with different cred types are not duplicates.

        Scenario:
          Given: Same user with NTLM and cleartext
          When: dedup_keys compared
          Then: Keys are different
        """
        from tools.post.prism.models.credential import CredentialType

        ntlm_cred = credential_factory.create(
            username="admin",
            domain="CORP",
            cred_type=CredentialType.NTLM,
            value="aabbccdd11223344aabbccdd11223344"
        )
        cleartext_cred = credential_factory.create(
            username="admin",
            domain="CORP",
            cred_type=CredentialType.CLEARTEXT,
            value="Password123!"
        )

        assert ntlm_cred.dedup_key != cleartext_cred.dedup_key


class TestAccountKey:
    """Tests for account_key property."""

    def test_account_key_with_domain(self, credential_factory):
        """
        BV: Account key shows DOMAIN\\user format.

        Scenario:
          Given: Credential with domain
          When: account_key property accessed
          Then: Returns "DOMAIN\\username"
        """
        cred = credential_factory.create(username="admin", domain="CORP")

        assert cred.account_key == "CORP\\admin"

    def test_account_key_without_domain(self, credential_factory):
        """
        BV: Account key works without domain.

        Scenario:
          Given: Credential without domain
          When: account_key property accessed
          Then: Returns just username
        """
        cred = credential_factory.create(username="localuser", domain="")

        assert cred.account_key == "localuser"


class TestDisplayType:
    """Tests for display_type property."""

    def test_display_type_cleartext(self, credential_factory):
        """
        BV: Cleartext type displays as "Cleartext".

        Scenario:
          Given: Cleartext credential
          When: display_type property accessed
          Then: Returns "Cleartext"
        """
        cred = credential_factory.create_cleartext()

        assert cred.display_type == "Cleartext"

    def test_display_type_ntlm(self, credential_factory):
        """
        BV: NTLM type displays as "NTLM".

        Scenario:
          Given: NTLM credential
          When: display_type property accessed
          Then: Returns "NTLM"
        """
        cred = credential_factory.create_ntlm()

        assert cred.display_type == "NTLM"

    def test_display_type_sha1(self, credential_factory):
        """
        BV: SHA1 type displays as "SHA1".

        Scenario:
          Given: SHA1 credential
          When: display_type property accessed
          Then: Returns "SHA1"
        """
        from tools.post.prism.models.credential import CredentialType

        cred = credential_factory.create(cred_type=CredentialType.SHA1)

        assert cred.display_type == "SHA1"


class TestToDict:
    """Tests for to_dict serialization."""

    def test_to_dict_includes_all_fields(self, credential_factory):
        """
        BV: Serialized dict includes all important fields.

        Scenario:
          Given: Complete credential
          When: to_dict() called
          Then: All fields present in result
        """
        cred = credential_factory.create(
            username="admin",
            domain="CORP",
            value="aabbccdd11223344aabbccdd11223344",
            sid="S-1-5-21-12345-500"
        )

        data = cred.to_dict()

        assert data["username"] == "admin"
        assert data["domain"] == "CORP"
        assert data["value"] == "aabbccdd11223344aabbccdd11223344"
        assert data["sid"] == "S-1-5-21-12345-500"
        assert "cred_type" in data
        assert "is_machine_account" in data
        assert "is_service_account" in data
        assert "high_value" in data

    def test_to_dict_cred_type_is_string(self, credential_factory):
        """
        BV: Enum serializes to string for JSON compatibility.

        Scenario:
          Given: Credential with enum type
          When: to_dict() called
          Then: cred_type is string value
        """
        cred = credential_factory.create_ntlm()

        data = cred.to_dict()

        assert isinstance(data["cred_type"], str)
        assert data["cred_type"] == "ntlm"


class TestToNeo4jDict:
    """Tests for to_neo4j_dict serialization."""

    def test_to_neo4j_dict_includes_id(self, credential_factory):
        """
        BV: Neo4j dict includes unique ID for node creation.

        Scenario:
          Given: Credential
          When: to_neo4j_dict() called
          Then: ID field is present and unique
        """
        cred = credential_factory.create(
            username="admin",
            domain="CORP"
        )

        data = cred.to_neo4j_dict()

        assert "id" in data
        assert "admin" in data["id"]
        assert "CORP" in data["id"]

    def test_to_neo4j_dict_uses_is_machine_shorthand(self, credential_factory):
        """
        BV: Neo4j dict uses shortened property names.

        Scenario:
          Given: Machine account credential
          When: to_neo4j_dict() called
          Then: Uses "is_machine" not "is_machine_account"
        """
        cred = credential_factory.create_machine_account()

        data = cred.to_neo4j_dict()

        assert "is_machine" in data
        assert data["is_machine"] is True

    def test_to_neo4j_dict_all_fields_serializable(self, credential_factory):
        """
        BV: All fields can be sent to Neo4j (no complex types).

        Scenario:
          Given: Credential with all fields
          When: to_neo4j_dict() called
          Then: All values are primitive types
        """
        cred = credential_factory.create(
            username="admin",
            domain="CORP",
            sid="S-1-5-21-12345-500"
        )

        data = cred.to_neo4j_dict()

        # All values should be primitive (str, int, bool, None)
        for key, value in data.items():
            assert isinstance(value, (str, int, bool, type(None))), \
                f"Field '{key}' has non-primitive type: {type(value)}"


class TestCredentialTypeEnum:
    """Tests for CredentialType enum values."""

    def test_all_credential_types_exist(self):
        """
        BV: All expected credential types are defined.

        Scenario:
          Given: CredentialType enum
          When: Check for expected types
          Then: All types exist
        """
        from tools.post.prism.models.credential import CredentialType

        expected_types = [
            "CLEARTEXT", "NTLM", "SHA1", "LM",
            "AES128", "AES256", "DES_CBC_MD5", "RC4_HMAC",
            "GPP_PASSWORD", "GPP_CPASSWORD",
            "KRB5TGS", "KRB5ASREP",
            "SAM_HASH", "NTDS_HASH", "DCC2",
            "NET_NTLMV1", "NET_NTLMV2",
            "SSH_KEY", "MACHINE_HEX"
        ]

        for type_name in expected_types:
            assert hasattr(CredentialType, type_name), f"Missing type: {type_name}"

    def test_credential_type_value_lowercase(self):
        """
        BV: Enum values are lowercase for consistency.

        Scenario:
          Given: CredentialType enum
          When: Check value property
          Then: Value is lowercase string
        """
        from tools.post.prism.models.credential import CredentialType

        assert CredentialType.NTLM.value == "ntlm"
        assert CredentialType.CLEARTEXT.value == "cleartext"
        assert CredentialType.SHA1.value == "sha1"


class TestCredentialRepr:
    """Tests for __repr__ string representation."""

    def test_repr_includes_account_and_type(self, credential_factory):
        """
        BV: Repr is informative for debugging.

        Scenario:
          Given: Credential
          When: repr() called
          Then: Shows account_key and type
        """
        cred = credential_factory.create(username="admin", domain="CORP")

        repr_str = repr(cred)

        assert "Credential" in repr_str
        assert "CORP\\admin" in repr_str or "admin" in repr_str
        assert "ntlm" in repr_str.lower()


class TestCredentialEquality:
    """Tests for credential comparison."""

    def test_same_dedup_key_credentials_equal_key(self, credential_factory):
        """
        BV: Credentials with same dedup_key have equal keys.

        Scenario:
          Given: Two credentials with same identifying fields
          When: dedup_keys compared
          Then: Keys match
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP", value="hash123"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP", value="hash123"
        )

        assert cred1.dedup_key == cred2.dedup_key

    def test_different_values_different_keys(self, credential_factory):
        """
        BV: Different hash values create different dedup keys.

        Scenario:
          Given: Same user with different hash values
          When: dedup_keys compared
          Then: Keys differ
        """
        cred1 = credential_factory.create(
            username="admin", domain="CORP", value="hash111"
        )
        cred2 = credential_factory.create(
            username="admin", domain="CORP", value="hash222"
        )

        assert cred1.dedup_key != cred2.dedup_key


class TestOccurrenceTracking:
    """Tests for occurrence count tracking."""

    def test_default_occurrences_is_one(self, credential_factory):
        """
        BV: New credentials start with occurrence count of 1.

        Scenario:
          Given: Newly created credential
          When: occurrences property checked
          Then: Returns 1
        """
        cred = credential_factory.create()

        assert cred.occurrences == 1

    def test_occurrences_can_be_incremented(self, credential_factory):
        """
        BV: Occurrence count can be updated during dedup.

        Scenario:
          Given: Credential with occurrences=1
          When: occurrences incremented
          Then: New value is stored
        """
        cred = credential_factory.create()
        cred.occurrences += 1

        assert cred.occurrences == 2


class TestFirstSeenLine:
    """Tests for first_seen_line tracking."""

    def test_default_first_seen_is_zero(self, credential_factory):
        """
        BV: Default first seen line is 0.

        Scenario:
          Given: Newly created credential
          When: first_seen_line property checked
          Then: Returns 0
        """
        cred = credential_factory.create()

        assert cred.first_seen_line == 0

    def test_first_seen_can_be_set(self, credential_factory):
        """
        BV: First seen line can be set during parsing.

        Scenario:
          Given: Credential created with specific line
          When: first_seen_line property checked
          Then: Returns correct line number
        """
        cred = credential_factory.create(first_seen_line=42)

        assert cred.first_seen_line == 42
