# Verification Commands Mapping

**Phase 2B.3: State Condition Preservation**

This document maps the 248 removed state conditions to their new verification command IDs, preserving the information that was removed during Phase 1.4 schema enforcement.

## Summary

- **Total Verification Commands Created**: 26
- **State Conditions Preserved**: 25+ unique categories
- **File Location**: `/home/kali/Desktop/OSCP/crack/reference/data/commands/utilities/verification-utilities.json`
- **Schema Compliance**: 100% (all commands use valid IDs in prerequisites/alternatives)

---

## State Condition → Verification Command Mapping

### High-Priority Conversions (Most Referenced)

| Old State Condition Text | New Command ID | References | Category |
|--------------------------|----------------|------------|----------|
| `NTLM hash obtained` | `verify-ntlm-hash` | 5 | Credential verification |
| `CrackMapExec installed` | `verify-crackmapexec-installed` | 4 | Tool availability |
| `Neo4j running` | `verify-neo4j-running` | 2 | Service status |
| `PowerView imported` | `verify-powerview-imported` | 2 | Module loaded |
| `Verify web server is up: curl -I...` | `verify-web-server-up` | 2 | Service connectivity |

### Tool Installation Verifications

| Old State Condition Text | New Command ID | Tool Type |
|--------------------------|----------------|-----------|
| `Impacket installed on Kali` | `verify-impacket-installed` | Python toolkit |
| `nmap installed (default on Kali)` | `verify-nmap-installed` | Network scanner |
| `Evil-WinRM installed on Kali` | `verify-evil-winrm-installed` | Remote access |
| `Mimikatz available` | `verify-mimikatz-available` | Credential extraction |
| `Rubeus.exe available` | `verify-rubeus-available` | Kerberos toolkit |
| `getcap utility installed (part of libcap package)` | `verify-getcap-installed` | Linux capabilities |
| `Socat installed on pivot host` | `verify-socat-installed` | Port forwarding |

### File/Resource Availability

| Old State Condition Text | New Command ID | Resource Type |
|--------------------------|----------------|---------------|
| `docker pull alpine (if no images available)` | `verify-docker-images-available` | Container image |
| `wget if curl unavailable` | `verify-curl-available` | HTTP client |
| `Use wget/curl if available` | `verify-curl-available` | HTTP client |
| `Python available on pivot host` | `verify-python-available` | Interpreter |
| Generic file check | `verify-file-exists` | File system |

### Service/Network Verifications

| Old State Condition Text | New Command ID | Service Type |
|--------------------------|----------------|--------------|
| `RDP service running on target` | `verify-rdp-service-running` | Remote Desktop |
| `SOCKS proxy running: ssh -D...` | `verify-socks-proxy-running` | Pivoting proxy |
| Generic port check | `verify-port-open` | Network port |
| Generic connectivity | `verify-network-connectivity` | Network reachability |

### Authentication/Access Verifications

| Old State Condition Text | New Command ID | Access Type |
|--------------------------|----------------|-------------|
| `Valid credentials` | `verify-credentials` | SMB authentication |
| `PowerShell access` | `verify-powershell-access` | Windows shell |
| `Root access` | `verify-root-access` | Elevated privileges |
| SMB null session allowed | `verify-smb-null-session` | Anonymous SMB |
| LDAP anonymous bind allowed | `verify-ldap-anonymous-bind` | Anonymous LDAP |

### Vulnerability/Exploitation Verifications

| Old State Condition Text | New Command ID | Vulnerability Type |
|--------------------------|----------------|--------------------|
| `sqli-union-mysql-info (if SQL injection available)` | `verify-sql-injection-vulnerable` | SQL injection |
| `sqli-union-postgresql-info (if SQL injection available)` | `verify-sql-injection-vulnerable` | SQL injection |

---

## Usage Examples

### Before (Invalid - State Condition as Text)
```json
{
  "id": "impacket-psexec",
  "prerequisites": [
    "Valid credentials",
    "NTLM hash obtained",
    "Impacket installed on Kali"
  ]
}
```

### After (Valid - Verification Command IDs)
```json
{
  "id": "impacket-psexec",
  "prerequisites": [
    "verify-credentials",
    "verify-ntlm-hash",
    "verify-impacket-installed"
  ]
}
```

---

## Command Categories

### 1. Tool Installation Checks (8 commands)
- `verify-crackmapexec-installed`
- `verify-impacket-installed`
- `verify-evil-winrm-installed`
- `verify-nmap-installed`
- `verify-getcap-installed`
- `verify-socat-installed`
- `verify-curl-available`
- `verify-python-available`

### 2. Tool/Module Availability (3 commands)
- `verify-mimikatz-available`
- `verify-rubeus-available`
- `verify-powerview-imported`

### 3. Service Status (4 commands)
- `verify-neo4j-running`
- `verify-web-server-up`
- `verify-rdp-service-running`
- `verify-socks-proxy-running`

### 4. Authentication/Privileges (5 commands)
- `verify-credentials`
- `verify-ntlm-hash`
- `verify-powershell-access`
- `verify-root-access`
- `verify-smb-null-session`
- `verify-ldap-anonymous-bind`

### 5. Network/Connectivity (3 commands)
- `verify-network-connectivity`
- `verify-port-open`
- `verify-web-server-up`

### 6. Resource Availability (3 commands)
- `verify-docker-images-available`
- `verify-file-exists`
- `verify-curl-available`

### 7. Vulnerability Detection (1 command)
- `verify-sql-injection-vulnerable`

---

## Schema Compliance

All verification commands follow the schema requirements:

1. **Unique IDs**: All 26 commands have unique kebab-case identifiers
2. **Category**: `utilities` (valid enum value)
3. **Command**: Shell commands returning exit code 0 (success) or 1 (failure)
4. **Placeholders**: All variables defined in `variables` array
5. **Relationships**: Use command IDs only (no text)
6. **Tags**: Include `VERIFICATION` and `PREREQUISITE_CHECK`
7. **Metadata**: Include `success_indicators`, `failure_indicators`, `troubleshooting`

---

## Data Preservation Strategy

### Phase 1.4: Removed State Conditions
- 248 state condition text strings removed from `prerequisites` and `alternatives` arrays
- Reason: Schema violation (relationships must be command IDs, not text)

### Phase 2B.3: Preserved as Verification Commands
- 26 verification commands created to preserve information
- Each command provides executable validation logic
- State conditions converted to testable prerequisites

### Impact
- **Before**: `"prerequisites": ["Valid credentials"]` → INVALID (removed)
- **After**: `"prerequisites": ["verify-credentials"]` → VALID (preserved as executable command)

---

## Next Steps

### Phase 2B.4: Update Command References
1. Find all commands that referenced removed state conditions
2. Replace with new verification command IDs
3. Run validation: `python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose`

### Phase 2B.5: Relationship Mapping
1. Create graph relationships: `(:Command)-[:REQUIRES]->(:VerificationCommand)`
2. Update Neo4j migration scripts to handle verification commands
3. Ensure proper traversal: exploit → verify → prerequisites

---

## Mapping Report Correlation

These verification commands address items from:
- **Preservation Plan**: `detailed_plan.verification_commands` array
- **Mapping Report**: State conditions marked with `action: CREATE_VERIFY_CMD`

Cross-reference count:
- Preservation plan items: 25
- Created commands: 26 (includes generic utilities)
- Coverage: 100%

---

## Quality Assurance

Validated against schema:
- [x] All IDs unique
- [x] All commands executable
- [x] All placeholders parameterized
- [x] All relationships use IDs
- [x] All categories valid enum
- [x] Zero text in prerequisites/alternatives
- [x] JSON syntax valid
- [x] Graph-compatible structure

---

## File Locations

- **Verification Commands**: `/home/kali/Desktop/OSCP/crack/reference/data/commands/utilities/verification-utilities.json`
- **Preservation Plan**: `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/preservation_plan.json`
- **Mapping Report**: `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/mapping_report.json`
- **This Mapping**: `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/verification_commands_mapping.md`

---

Generated: 2025-11-09
Phase: 2B.3 - Verification Command Creation
Author: Neo4j Migration Agent
