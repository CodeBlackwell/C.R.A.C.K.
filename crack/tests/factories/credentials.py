"""
Credential Factory for PRISM Test Data

Creates Credential objects with sensible defaults for testing.
Override only the fields that matter for your specific test case.

Business Value Focus:
- Reduces boilerplate in credential-related tests
- Ensures consistent test data across modules
- Provides type-specific factories for common scenarios

Usage Examples:
    # Basic credential with defaults
    cred = CredentialFactory.create()

    # Cleartext password
    cred = CredentialFactory.create_cleartext(password="SuperSecret!")

    # Machine account
    cred = CredentialFactory.create_machine_account(name="DC01$")

    # Batch creation
    creds = CredentialFactory.create_batch(5)

    # High-value credential
    cred = CredentialFactory.create_high_value()
"""

import sys
from pathlib import Path
from typing import Optional, List
from threading import Lock

# Ensure crack package is importable
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.post.prism.models.credential import Credential, CredentialType


class CredentialFactory:
    """
    Factory for creating test Credential objects.

    Thread-safe counter ensures unique usernames across parallel tests.
    Reset counter before test runs for deterministic output.
    """

    _counter: int = 0
    _lock: Lock = Lock()

    # Default values for minimal valid credential
    DEFAULT_DOMAIN = "TESTDOMAIN"
    DEFAULT_CRED_TYPE = CredentialType.NTLM
    DEFAULT_NTLM_VALUE = "a" * 32  # 32-char hex string
    DEFAULT_CLEARTEXT_PASSWORD = "Password123!"

    @classmethod
    def reset(cls) -> None:
        """
        Reset counter for deterministic test output.

        Call at start of test module or in fixture setup.
        """
        with cls._lock:
            cls._counter = 0

    @classmethod
    def _next_id(cls) -> int:
        """Get next unique ID (thread-safe)."""
        with cls._lock:
            cls._counter += 1
            return cls._counter

    @classmethod
    def create(
        cls,
        username: Optional[str] = None,
        domain: str = None,
        cred_type: CredentialType = None,
        value: str = None,
        sid: Optional[str] = None,
        logon_server: Optional[str] = None,
        session_type: Optional[str] = None,
        source_session_id: Optional[str] = None,
        first_seen_line: int = 0,
        occurrences: int = 1,
    ) -> Credential:
        """
        Create Credential with sensible defaults.

        Args:
            username: Account name. Defaults to "testuser{n}" where n is unique.
            domain: Domain name. Defaults to "TESTDOMAIN".
            cred_type: Credential type. Defaults to NTLM.
            value: Secret value. Defaults to 32-char hex for NTLM.
            sid: Security Identifier (optional).
            logon_server: Logon server name (optional).
            session_type: Session type (optional).
            source_session_id: Source session ID (optional).
            first_seen_line: Line number where first seen. Defaults to 0.
            occurrences: Occurrence count. Defaults to 1.

        Returns:
            Credential object with specified/default values.

        BV: Override only what matters - sensible defaults reduce test noise.
        """
        unique_id = cls._next_id()

        # Apply defaults
        if username is None:
            username = f"testuser{unique_id}"
        if domain is None:
            domain = cls.DEFAULT_DOMAIN
        if cred_type is None:
            cred_type = cls.DEFAULT_CRED_TYPE
        if value is None:
            # Choose appropriate default based on type
            if cred_type == CredentialType.CLEARTEXT:
                value = cls.DEFAULT_CLEARTEXT_PASSWORD
            elif cred_type in (CredentialType.NTLM, CredentialType.LM):
                value = cls.DEFAULT_NTLM_VALUE
            elif cred_type == CredentialType.SHA1:
                value = "b" * 40  # 40-char hex for SHA1
            elif cred_type == CredentialType.AES256:
                value = "c" * 64  # 64-char hex for AES256
            elif cred_type == CredentialType.AES128:
                value = "d" * 32  # 32-char hex for AES128
            else:
                value = cls.DEFAULT_NTLM_VALUE

        return Credential(
            username=username,
            domain=domain,
            cred_type=cred_type,
            value=value,
            sid=sid,
            logon_server=logon_server,
            session_type=session_type,
            source_session_id=source_session_id,
            first_seen_line=first_seen_line,
            occurrences=occurrences,
        )

    @classmethod
    def create_batch(
        cls,
        count: int,
        domain: str = None,
        cred_type: CredentialType = None,
        **kwargs
    ) -> List[Credential]:
        """
        Create multiple credentials with unique usernames.

        Args:
            count: Number of credentials to create.
            domain: Shared domain for all credentials.
            cred_type: Shared credential type for all.
            **kwargs: Additional arguments passed to create().

        Returns:
            List of Credential objects.

        BV: Bulk creation for testing deduplication, filtering, etc.
        """
        return [
            cls.create(domain=domain, cred_type=cred_type, **kwargs)
            for _ in range(count)
        ]

    @classmethod
    def create_cleartext(
        cls,
        password: str = None,
        username: Optional[str] = None,
        domain: str = None,
        **kwargs
    ) -> Credential:
        """
        Create cleartext password credential.

        Args:
            password: The cleartext password. Defaults to "Password123!".
            username: Account name (optional).
            domain: Domain name (optional).
            **kwargs: Additional Credential fields.

        Returns:
            Credential with cred_type=CLEARTEXT.

        BV: Cleartext passwords are highest-value credentials.
        """
        return cls.create(
            username=username,
            domain=domain,
            cred_type=CredentialType.CLEARTEXT,
            value=password or cls.DEFAULT_CLEARTEXT_PASSWORD,
            **kwargs
        )

    @classmethod
    def create_ntlm(
        cls,
        ntlm_hash: str = None,
        username: Optional[str] = None,
        domain: str = None,
        **kwargs
    ) -> Credential:
        """
        Create NTLM hash credential.

        Args:
            ntlm_hash: 32-char NTLM hash. Defaults to 32 'a' chars.
            username: Account name (optional).
            domain: Domain name (optional).
            **kwargs: Additional Credential fields.

        Returns:
            Credential with cred_type=NTLM.

        BV: NTLM hashes enable pass-the-hash attacks.
        """
        return cls.create(
            username=username,
            domain=domain,
            cred_type=CredentialType.NTLM,
            value=ntlm_hash or cls.DEFAULT_NTLM_VALUE,
            **kwargs
        )

    @classmethod
    def create_machine_account(
        cls,
        name: str = None,
        domain: str = None,
        **kwargs
    ) -> Credential:
        """
        Create machine account credential (username ends with $).

        Args:
            name: Machine name with $ suffix. Defaults to "DC01$".
            domain: Domain name (optional).
            **kwargs: Additional Credential fields.

        Returns:
            Credential where is_machine_account=True.

        BV: Machine accounts have different value than user accounts.
        """
        return cls.create(
            username=name or "DC01$",
            domain=domain,
            **kwargs
        )

    @classmethod
    def create_service_account(
        cls,
        username: str = None,
        domain: str = None,
        **kwargs
    ) -> Credential:
        """
        Create well-known service account credential.

        Args:
            username: Service account name. Defaults to "LOCAL SERVICE".
            domain: Domain name. Defaults to "NT AUTHORITY".
            **kwargs: Additional Credential fields.

        Returns:
            Credential where is_service_account=True.

        BV: Service accounts are typically low-value for lateral movement.
        """
        return cls.create(
            username=username or "LOCAL SERVICE",
            domain=domain or "NT AUTHORITY",
            **kwargs
        )

    @classmethod
    def create_high_value(
        cls,
        username: str = None,
        domain: str = None,
        password: str = None,
        **kwargs
    ) -> Credential:
        """
        Create high-value credential (cleartext, non-service, non-machine).

        Args:
            username: Account name. Defaults to "administrator".
            domain: Domain name. Defaults to "CORP".
            password: Cleartext password. Defaults to "SuperSecretP@ss!".
            **kwargs: Additional Credential fields.

        Returns:
            Credential where high_value=True.

        BV: High-value credentials should be prominently displayed.
        """
        return cls.create(
            username=username or "administrator",
            domain=domain or "CORP",
            cred_type=CredentialType.CLEARTEXT,
            value=password or "SuperSecretP@ss!",
            **kwargs
        )

    @classmethod
    def create_null_password(
        cls,
        username: str = None,
        domain: str = None,
        **kwargs
    ) -> Credential:
        """
        Create credential with null/empty password.

        Args:
            username: Account name (optional).
            domain: Domain name (optional).
            **kwargs: Additional Credential fields.

        Returns:
            Credential where is_null_password=True, high_value=False.

        BV: Null passwords should not be flagged as high-value.
        """
        return cls.create(
            username=username,
            domain=domain,
            cred_type=CredentialType.CLEARTEXT,
            value="(null)",
            **kwargs
        )

    @classmethod
    def create_kerberos_hash(
        cls,
        username: str = None,
        domain: str = None,
        hash_type: CredentialType = None,
        **kwargs
    ) -> Credential:
        """
        Create Kerberos-related hash credential.

        Args:
            username: Account name (optional).
            domain: Domain name (optional).
            hash_type: AES256, AES128, RC4_HMAC, or DES_CBC_MD5.
                       Defaults to AES256.
            **kwargs: Additional Credential fields.

        Returns:
            Credential with Kerberos key type.

        BV: Kerberos keys enable sophisticated attacks.
        """
        if hash_type is None:
            hash_type = CredentialType.AES256

        return cls.create(
            username=username,
            domain=domain,
            cred_type=hash_type,
            **kwargs
        )

    @classmethod
    def create_duplicate_of(
        cls,
        original: Credential,
        change_field: str = None,
        new_value: str = None
    ) -> Credential:
        """
        Create credential that duplicates another (for dedup testing).

        Args:
            original: Credential to duplicate.
            change_field: Optional field to modify (breaks dedup match).
            new_value: New value for changed field.

        Returns:
            Credential with same dedup_key as original (unless field changed).

        BV: Testing deduplication requires controlled duplicates.
        """
        cred = cls.create(
            username=original.username,
            domain=original.domain,
            cred_type=original.cred_type,
            value=original.value,
            sid=original.sid,
            logon_server=original.logon_server,
            session_type=original.session_type,
            source_session_id=original.source_session_id,
        )

        if change_field and new_value:
            if hasattr(cred, change_field):
                # For dataclass, we need to create new instance
                # since fields are not mutable by default in frozen dataclasses
                # But Credential is not frozen, so direct assignment works
                setattr(cred, change_field, new_value)

        return cred
