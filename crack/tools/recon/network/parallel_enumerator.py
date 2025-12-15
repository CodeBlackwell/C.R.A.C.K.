#!/usr/bin/env python3
"""
Parallel enumeration - run multiple scans simultaneously for time efficiency
Starts multiple background processes and waits for completion
"""

import subprocess
import os
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from crack.core.themes import Colors
except ImportError:
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'


class ParallelEnumerator:
    """Run multiple enumeration tools in parallel"""

    def __init__(self, target, ports, output_dir, run_udp=False):
        self.target = target
        self.ports = ports
        self.output_dir = Path(output_dir)
        self.run_udp = run_udp
        self.has_web = any(p in [80, 443, 8000, 8080, 8443] for p in ports)
        self.has_smb = any(p in [139, 445] for p in ports)
        self.results = {}

    def _run_command(self, name, cmd, timeout=600):
        """Run a command and capture output"""
        print(f"{Colors.CYAN}[Starting]{Colors.END} {name}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                print(f"{Colors.GREEN}[Complete]{Colors.END} {name}")
                return True, result.stdout
            else:
                print(f"{Colors.YELLOW}[Warning]{Colors.END} {name} exited with code {result.returncode}")
                return False, result.stderr

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[Timeout]{Colors.END} {name}")
            return False, "Timeout"
        except FileNotFoundError:
            print(f"{Colors.RED}[Missing]{Colors.END} {name} - tool not installed")
            return False, "Tool not found"
        except Exception as e:
            print(f"{Colors.RED}[Error]{Colors.END} {name}: {str(e)}")
            return False, str(e)

    def scan_udp(self):
        """
        UDP service scan
        - Commonly overlooked but important (SNMP, DNS, TFTP, NTP)
        - Requires sudo privileges
        - Scans top 20 most common UDP services
        """
        if not self.run_udp:
            return False, "Skipped (use --full to enable)"

        output_file = self.output_dir / "udp_scan.txt"
        cmd = [
            'sudo', 'nmap',
            '-sU',                      # UDP scan
            '--top-ports', '20',        # 20 most common UDP ports
            '-oN', str(output_file),
            self.target
        ]

        print(f"\n{Colors.YELLOW}UDP SCAN:{Colors.END}")
        print(f"  {Colors.BOLD}-sU{Colors.END}: UDP scan (requires sudo, finds SNMP/DNS/TFTP)")
        print(f"  {Colors.BOLD}--top-ports 20{Colors.END}: Most common UDP services only")
        print(f"  {Colors.YELLOW}TIME:{Colors.END} 2-5 minutes")

        return self._run_command("UDP Scan", cmd, timeout=400)

    def scan_web(self):
        """
        Web server enumeration
        - Nikto for vulnerabilities and misconfigurations
        - Only runs if web ports are open
        """
        if not self.has_web:
            return False, "No web ports detected"

        # Determine web URL
        if 443 in self.ports or 8443 in self.ports:
            url = f"https://{self.target}"
        else:
            url = f"http://{self.target}"

        output_file = self.output_dir / "nikto.txt"
        cmd = [
            'nikto',
            '-h', url,                  # Target URL
            '-output', str(output_file)
        ]

        print(f"\n{Colors.YELLOW}NIKTO WEB SCAN:{Colors.END}")
        print(f"  {Colors.BOLD}-h{Colors.END}: Target URL ({url})")
        print(f"  {Colors.BOLD}-output{Colors.END}: Save results for documentation")
        print(f"  {Colors.YELLOW}PURPOSE:{Colors.END} Find outdated software, misconfigs, known vulns")
        print(f"  {Colors.YELLOW}TIME:{Colors.END} 2-5 minutes")

        return self._run_command("Nikto Web Scan", cmd, timeout=400)

    def scan_smb(self):
        """
        SMB enumeration
        - enum4linux for null session enumeration
        - Finds shares, users, groups, password policy
        - Only runs if SMB ports are open
        """
        if not self.has_smb:
            return False, "No SMB ports detected"

        output_file = self.output_dir / "enum4linux.txt"
        cmd = [
            'enum4linux',
            '-a',                       # All enumeration
            self.target
        ]

        print(f"\n{Colors.YELLOW}SMB ENUMERATION:{Colors.END}")
        print(f"  {Colors.BOLD}-a{Colors.END}: All enumeration (users, shares, groups, password policy)")
        print(f"  {Colors.YELLOW}PURPOSE:{Colors.END}: Null session enumeration (no auth required)")
        print(f"  {Colors.YELLOW}TIME:{Colors.END} 1-3 minutes")

        success, output = self._run_command("enum4linux", cmd, timeout=300)

        # Save output to file manually since enum4linux outputs to stdout
        if success:
            output_file.write_text(output)

        return success, output

    def scan_whatweb(self):
        """
        Web technology fingerprinting
        - Identifies CMS, frameworks, server software
        - Fast and lightweight
        """
        if not self.has_web:
            return False, "No web ports detected"

        # Determine web URL
        if 443 in self.ports or 8443 in self.ports:
            url = f"https://{self.target}"
        else:
            url = f"http://{self.target}"

        output_file = self.output_dir / "whatweb.txt"
        cmd = [
            'whatweb',
            '-v',                       # Verbose output
            url
        ]

        print(f"\n{Colors.YELLOW}WHATWEB FINGERPRINT:{Colors.END}")
        print(f"  {Colors.BOLD}-v{Colors.END}: Verbose (show all detected technologies)")
        print(f"  {Colors.YELLOW}PURPOSE:{Colors.END} Identify CMS, frameworks, libraries")
        print(f"  {Colors.YELLOW}TIME:{Colors.END} < 30 seconds")

        success, output = self._run_command("WhatWeb", cmd, timeout=60)

        if success:
            output_file.write_text(output)

        return success, output

    def run_all(self):
        """
        Run all applicable scans in parallel
        Returns when all scans complete
        """
        print(f"\n{Colors.BOLD}[PARALLEL ENUMERATION]{Colors.END}")
        print(f"{Colors.CYAN}=" * 60 + Colors.END)
        print(f"\n{Colors.YELLOW}Running multiple scans simultaneously...{Colors.END}\n")

        # Define all scans to run
        scans = []

        if self.run_udp:
            scans.append(('UDP', self.scan_udp))

        if self.has_web:
            scans.append(('WhatWeb', self.scan_whatweb))
            scans.append(('Nikto', self.scan_web))

        if self.has_smb:
            scans.append(('SMB', self.scan_smb))

        if not scans:
            print(f"{Colors.YELLOW}No additional scans to run{Colors.END}")
            return {}

        # Run scans in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_scan = {executor.submit(scan_func): name for name, scan_func in scans}

            for future in as_completed(future_to_scan):
                scan_name = future_to_scan[future]
                try:
                    success, output = future.result()
                    self.results[scan_name] = {
                        'success': success,
                        'output': output[:500] if isinstance(output, str) else output
                    }
                except Exception as e:
                    print(f"{Colors.RED}[Error]{Colors.END} {scan_name}: {e}")
                    self.results[scan_name] = {'success': False, 'output': str(e)}

        print(f"\n{Colors.GREEN}✓ Parallel enumeration complete{Colors.END}")
        return self.results

    def get_summary(self):
        """Get summary of all scans"""
        summary = []
        summary.append(f"\n{Colors.BOLD}[PARALLEL SCAN SUMMARY]{Colors.END}")
        summary.append(f"{Colors.CYAN}-" * 40 + Colors.END)

        for scan_name, result in self.results.items():
            status = f"{Colors.GREEN}✓{Colors.END}" if result['success'] else f"{Colors.RED}✗{Colors.END}"
            summary.append(f"  {status} {scan_name}")

        return '\n'.join(summary)
