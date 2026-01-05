"""
Convert enumeration results to Findings for the recommendation engine.

Bridges between the raw enumeration output and the typed Finding objects
that the recommendation engine expects.
"""

from typing import List, Dict, Any, Optional

from .models import Finding, FindingType


def findings_from_enumeration(
    aggregated,
    source: str = "enumeration",
) -> List[Finding]:
    """
    Convert aggregated enumeration results to Finding objects.

    Extracts findings for:
    - Users with dangerous flags (ASREP, PWNOTREQ, etc.)
    - Users with SPNs (kerberoastable)
    - Users with password-in-description
    - Custom LDAP attributes
    - Group memberships

    Args:
        aggregated: AggregatedResult from enumerators/aggregator
        source: Source identifier for the findings

    Returns:
        List of Finding objects
    """
    findings = []

    # Process users
    for username, user_data in aggregated.users.items():
        findings.extend(_findings_from_user(user_data, source))

    # Process custom attributes (if present)
    if hasattr(aggregated, 'custom_attributes'):
        for attr_data in aggregated.custom_attributes:
            finding = _finding_from_custom_attribute(attr_data, source)
            if finding:
                findings.append(finding)

    return findings


def _findings_from_user(
    user_data: Dict[str, Any],
    source: str,
) -> List[Finding]:
    """Extract findings from a user record."""
    findings = []
    username = user_data.get('name', 'unknown')

    # AS-REP Roastable
    if user_data.get('asrep'):
        finding = Finding(
            id=f"asrep_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value="DONT_REQ_PREAUTH",
            tags=["DONT_REQ_PREAUTH"],
            metadata={
                "username": username,
                "flag": "DONT_REQ_PREAUTH",
                "asrep_hash": user_data.get('asrep_hash'),
            },
        )
        findings.append(finding)

    # Password not required
    if user_data.get('pwnotreq'):
        finding = Finding(
            id=f"pwnotreq_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value="PASSWD_NOTREQD",
            tags=["PASSWD_NOTREQD"],
            metadata={
                "username": username,
                "flag": "PASSWD_NOTREQD",
            },
        )
        findings.append(finding)

    # Kerberoastable (has SPN)
    if user_data.get('spn') or user_data.get('spns'):
        spns = user_data.get('spns', [])
        finding = Finding(
            id=f"spn_{username}",
            finding_type=FindingType.USER_FLAG,
            source=source,
            target=username,
            raw_value=spns[0] if spns else "HAS_SPN",
            tags=["HAS_SPN"],
            metadata={
                "username": username,
                "spn_user": username,
                "spns": spns,
            },
        )
        findings.append(finding)

    # Password in description
    desc = user_data.get('description', '').lower()
    if desc and any(hint in desc for hint in ['pass', 'pwd', 'cred', 'secret', 'key']):
        finding = Finding(
            id=f"pwd_in_desc_{username}",
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source=source,
            target="description",
            raw_value=user_data.get('description', ''),
            tags=["suspicious_description", "possible_password"],
            metadata={
                "username": username,
                "attribute_name": "description",
            },
        )
        findings.append(finding)

    # Custom attributes (like cascadeLegacyPwd)
    custom_attrs = user_data.get('custom_attributes', {})
    for attr_name, attr_value in custom_attrs.items():
        finding = Finding(
            id=f"custom_attr_{username}_{attr_name}",
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source=source,
            target=attr_name,
            raw_value=attr_value,
            tags=["custom_attribute"],
            metadata={
                "username": username,
                "attribute_name": attr_name,
            },
        )
        findings.append(finding)

    return findings


def _finding_from_custom_attribute(
    attr_data: Dict[str, Any],
    source: str,
) -> Optional[Finding]:
    """Create finding from a custom attribute record."""
    username = attr_data.get('username', 'unknown')
    attr_name = attr_data.get('attribute_name', 'unknown')
    attr_value = attr_data.get('value', '')

    if not attr_value:
        return None

    return Finding(
        id=f"custom_attr_{username}_{attr_name}",
        finding_type=FindingType.LDAP_ATTRIBUTE,
        source=source,
        target=attr_name,
        raw_value=attr_value,
        tags=["custom_attribute"],
        metadata={
            "username": username,
            "attribute_name": attr_name,
        },
    )


def findings_from_smb_crawl(
    crawl_result,
    source: str = "smb_crawl",
) -> List[Finding]:
    """
    Convert SMB crawl results to Finding objects.

    Args:
        crawl_result: CrawlResult from SMBCrawler
        source: Source identifier

    Returns:
        List of Finding objects for interesting files
    """
    findings = []

    if not crawl_result or not hasattr(crawl_result, 'files'):
        return findings

    for file_info in crawl_result.files:
        file_path = file_info.get('path', '')
        file_name = file_info.get('name', '')

        # Check for interesting file types
        tags = []

        lower_name = file_name.lower()
        lower_path = file_path.lower()

        # VNC registry files
        if 'vnc' in lower_name and lower_name.endswith('.reg'):
            tags.append('vnc')
            tags.append('registry')

        # Database files
        if any(lower_name.endswith(ext) for ext in ['.db', '.sqlite', '.sqlite3']):
            tags.append('database')

        # Config files
        if any(lower_name.endswith(ext) for ext in ['.ini', '.conf', '.config', '.cfg', '.xml']):
            tags.append('config')

        # Executable/DLL
        if any(lower_name.endswith(ext) for ext in ['.exe', '.dll']):
            tags.append('executable')

        # Skip uninteresting files
        if not tags:
            continue

        finding = Finding(
            id=f"file_{file_path.replace('/', '_').replace('\\', '_')}",
            finding_type=FindingType.FILE,
            source=source,
            target=file_path,
            raw_value=file_info.get('content'),
            tags=tags,
            metadata={
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_info.get('size'),
                "share": file_info.get('share'),
            },
        )
        findings.append(finding)

    return findings


def findings_from_group_memberships(
    user_groups: Dict[str, List[str]],
    source: str = "ldap_enum",
) -> List[Finding]:
    """
    Convert group membership data to Finding objects.

    Args:
        user_groups: Dict mapping username to list of group names
        source: Source identifier

    Returns:
        List of Finding objects for interesting group memberships
    """
    findings = []

    # Groups that grant special privileges
    interesting_groups = [
        "domain admins",
        "enterprise admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
        "dnsadmins",
        "recycle bin",  # AD Recycle Bin
        "gpo creator",
        "schema admins",
        "key admins",
        "enterprise key admins",
    ]

    for username, groups in user_groups.items():
        for group_name in groups:
            group_lower = group_name.lower()

            # Check if this is an interesting group
            is_interesting = any(ig in group_lower for ig in interesting_groups)
            if not is_interesting:
                continue

            tags = ["group_membership"]
            if "recycle" in group_lower and "bin" in group_lower:
                tags.append("ad_recycle_bin")
            if "admin" in group_lower:
                tags.append("privileged_group")
            if "backup" in group_lower or "server op" in group_lower:
                tags.append("privileged_group")

            finding = Finding(
                id=f"group_{username}_{group_name.replace(' ', '_')}",
                finding_type=FindingType.GROUP_MEMBERSHIP,
                source=source,
                target=group_name,
                raw_value=group_name,
                tags=tags,
                metadata={
                    "username": username,
                    "group_name": group_name,
                },
            )
            findings.append(finding)

    return findings
