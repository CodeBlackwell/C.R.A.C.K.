#!/usr/bin/env python3
"""
Two-stage port scanning for time-efficient enumeration
STAGE 1: Fast port discovery (30 seconds)
STAGE 2: Targeted service detection (1-2 minutes)
"""

import subprocess
import re
import os
from pathlib import Path

try:
    from crack.utils.colors import Colors
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


class PortScanner:
    """Two-stage port scanning for maximum efficiency"""

    def __init__(self, target, output_dir=None, min_rate=5000):
        self.target = target
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.min_rate = min_rate
        self.open_ports = []

    def stage1_fast_discovery(self):
        """
        STAGE 1: Fast port discovery
        - Scans all 65535 ports quickly
        - No service detection (saves time)
        - Typical runtime: 10-30 seconds
        """
        print(f"\n{Colors.BOLD}[STAGE 1] Fast Port Discovery{Colors.END}")
        print(f"{Colors.CYAN}=" * 60 + Colors.END)

        ports_file = self.output_dir / "ports_discovery.gnmap"

        cmd = [
            'nmap',
            '-p-',                      # All ports
            f'--min-rate={self.min_rate}',  # Aggressive speed
            '-oG', str(ports_file),     # Greppable output
            self.target
        ]

        print(f"\n{Colors.YELLOW}COMMAND:{Colors.END} {' '.join(cmd)}")
        print(f"\n{Colors.CYAN}FLAG EXPLANATIONS:{Colors.END}")
        print(f"  {Colors.BOLD}-p-{Colors.END}: Scan all 65535 ports (don't miss hidden services)")
        print(f"  {Colors.BOLD}--min-rate={self.min_rate}{Colors.END}: Minimum {self.min_rate} packets/sec (very fast)")
        print(f"  {Colors.BOLD}-oG{Colors.END}: Greppable output format (easy to parse open ports)")
        print(f"\n{Colors.YELLOW}PURPOSE:{Colors.END} Quickly find open ports WITHOUT service detection")
        print(f"{Colors.YELLOW}TIME ESTIMATE:{Colors.END} 10-30 seconds\n")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Parse open ports from greppable output
            if ports_file.exists():
                with open(ports_file, 'r') as f:
                    content = f.read()
                    # Extract ports in format: 80/open/tcp
                    port_matches = re.findall(r'(\d+)/open', content)
                    self.open_ports = sorted([int(p) for p in port_matches])

            if self.open_ports:
                print(f"{Colors.GREEN}✓ FOUND {len(self.open_ports)} open ports:{Colors.END} {','.join(map(str, self.open_ports))}")
            else:
                print(f"{Colors.RED}✗ No open ports found{Colors.END}")

            return self.open_ports

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}✗ Stage 1 timeout (increase timeout or reduce min-rate){Colors.END}")
            return []
        except Exception as e:
            print(f"{Colors.RED}✗ Error: {e}{Colors.END}")
            return []

    def stage2_service_detection(self):
        """
        STAGE 2: Targeted service detection
        - Only scans confirmed open ports
        - Runs version detection + NSE scripts
        - Typical runtime: 1-2 minutes
        """
        if not self.open_ports:
            print(f"\n{Colors.YELLOW}⚠ No ports to scan in Stage 2{Colors.END}")
            return None

        print(f"\n{Colors.BOLD}[STAGE 2] Targeted Service Detection{Colors.END}")
        print(f"{Colors.CYAN}=" * 60 + Colors.END)

        ports_str = ','.join(map(str, self.open_ports))
        scan_file = self.output_dir / "service_scan"

        cmd = [
            'nmap',
            f'-p{ports_str}',           # Only discovered ports
            '-sV',                       # Service version detection
            '-sC',                       # Default NSE scripts
            '-oA', str(scan_file),       # All output formats
            self.target
        ]

        print(f"\n{Colors.YELLOW}COMMAND:{Colors.END} {' '.join(cmd)}")
        print(f"\n{Colors.CYAN}FLAG EXPLANATIONS:{Colors.END}")
        print(f"  {Colors.BOLD}-p{ports_str[:50]}...{Colors.END}: Scan ONLY open ports (saves massive time)")
        print(f"  {Colors.BOLD}-sV{Colors.END}: Service version detection (critical for CVE matching)")
        print(f"  {Colors.BOLD}-sC{Colors.END}: Default NSE scripts (safe enumeration scripts)")
        print(f"  {Colors.BOLD}-oA{Colors.END}: Output all formats (nmap, xml, gnmap for documentation)")
        print(f"\n{Colors.YELLOW}PURPOSE:{Colors.END} Deep scan on confirmed ports for versions/vulnerabilities")
        print(f"{Colors.YELLOW}TIME ESTIMATE:{Colors.END} 1-2 minutes")
        print(f"\n{Colors.GREEN}TIME SAVED:{Colors.END} ~3-5 minutes vs full -sV -sC on all ports\n")

        try:
            # Run scan (this will take 1-2 minutes)
            subprocess.run(cmd, timeout=300)

            nmap_file = self.output_dir / "service_scan.nmap"
            if nmap_file.exists():
                print(f"\n{Colors.GREEN}✓ Service scan complete{Colors.END}")
                print(f"{Colors.CYAN}Results saved to:{Colors.END} {nmap_file}")
                return str(nmap_file)
            else:
                print(f"{Colors.RED}✗ Service scan failed{Colors.END}")
                return None

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}✗ Stage 2 timeout{Colors.END}")
            return None
        except Exception as e:
            print(f"{Colors.RED}✗ Error: {e}{Colors.END}")
            return None

    def run(self):
        """Execute both stages and return results"""
        # Stage 1: Fast discovery
        ports = self.stage1_fast_discovery()

        if not ports:
            return None

        # Stage 2: Service detection
        scan_file = self.stage2_service_detection()

        return {
            'ports': self.open_ports,
            'scan_file': scan_file,
            'output_dir': str(self.output_dir)
        }
