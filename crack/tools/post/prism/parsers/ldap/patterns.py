"""
LDAP Parser Patterns

Regex patterns for detecting and parsing ldapsearch LDIF output.
"""

import re

# Detection patterns for ldapsearch output
LDIF_HEADER = re.compile(
    r'^#\s*extended LDIF',
    re.MULTILINE | re.IGNORECASE
)

LDIF_VERSION = re.compile(
    r'^#\s*LDAPv\d',
    re.MULTILINE | re.IGNORECASE
)

LDIF_BASE = re.compile(
    r'^#\s*base\s+<([^>]+)>',
    re.MULTILINE | re.IGNORECASE
)

LDIF_FILTER = re.compile(
    r'^#\s*filter:\s*\(([^)]+)\)',
    re.MULTILINE | re.IGNORECASE
)

# Entry parsing patterns
DN_LINE = re.compile(
    r'^dn:\s*(.+)$',
    re.MULTILINE
)

# Base64 encoded DN (dn:: indicates base64)
DN_BASE64_LINE = re.compile(
    r'^dn::\s*(.+)$',
    re.MULTILINE
)

# Attribute line: name: value
ATTRIBUTE_LINE = re.compile(
    r'^([a-zA-Z][a-zA-Z0-9-]*):(?!:)\s*(.*)$',
    re.MULTILINE
)

# Base64 attribute line: name:: base64value
ATTRIBUTE_BASE64_LINE = re.compile(
    r'^([a-zA-Z][a-zA-Z0-9-]*)::?\s*(.*)$',
    re.MULTILINE
)

# Continuation line (starts with single space)
CONTINUATION_LINE = re.compile(
    r'^ (.*)$',
    re.MULTILINE
)

# Comment line
COMMENT_LINE = re.compile(
    r'^#.*$',
    re.MULTILINE
)

# Search reference
SEARCH_REF = re.compile(
    r'^ref:\s*(.+)$',
    re.MULTILINE
)

# Search result summary
SEARCH_RESULT = re.compile(
    r'^result:\s*(\d+)\s+(.*)$',
    re.MULTILINE
)

NUM_RESPONSES = re.compile(
    r'^#\s*numResponses:\s*(\d+)',
    re.MULTILINE
)

NUM_ENTRIES = re.compile(
    r'^#\s*numEntries:\s*(\d+)',
    re.MULTILINE
)

# Domain component extraction from DN
DC_PATTERN = re.compile(
    r'DC=([^,]+)',
    re.IGNORECASE
)

# Object class patterns
OBJECT_CLASS_USER = frozenset([
    'user', 'person', 'organizationalperson', 'inetorgperson'
])

OBJECT_CLASS_COMPUTER = frozenset([
    'computer'
])

OBJECT_CLASS_GROUP = frozenset([
    'group', 'groupofnames', 'groupofuniquenames'
])

OBJECT_CLASS_DOMAIN = frozenset([
    'domain', 'domaindns'
])

# High-value attributes to extract
USER_ATTRIBUTES = frozenset([
    'samaccountname', 'userprincipalname', 'displayname', 'name',
    'description', 'memberof', 'serviceprincipalname', 'useraccountcontrol',
    'admincount', 'whencreated', 'lastlogon', 'pwdlastset', 'objectsid',
    'primarygroupid', 'distinguishedname', 'mail', 'title', 'department',
])

COMPUTER_ATTRIBUTES = frozenset([
    'samaccountname', 'dnshostname', 'operatingsystem', 'operatingsystemversion',
    'operatingsystemservicepack', 'serviceprincipalname', 'useraccountcontrol',
    'whencreated', 'lastlogon', 'distinguishedname', 'objectsid',
])

GROUP_ATTRIBUTES = frozenset([
    'samaccountname', 'description', 'member', 'memberof', 'admincount',
    'distinguishedname', 'objectsid', 'grouptype',
])

DOMAIN_ATTRIBUTES = frozenset([
    'distinguishedname', 'name', 'dc', 'lockoutthreshold', 'lockoutduration',
    'lockoutobservationwindow', 'minpwdlength', 'maxpwdage', 'minpwdage',
    'pwdhistorylength', 'pwdproperties', 'msds-behavior-version',
    'ms-ds-machineaccountquota', 'fsmoreowner', 'whencreated', 'whenchanged',
])
