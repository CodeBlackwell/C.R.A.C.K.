#!/usr/bin/env python3
"""
Enumeration Scanner - Fast initial target discovery
Two-stage port scanning + parallel service enumeration + CVE lookup

USAGE:
    crack enum-scan <target> [options]

EXAMPLES:
    crack enum-scan 192.168.45.100                # Quick scan
    crack enum-scan 192.168.45.100 --full         # Include UDP
    crack enum-scan 192.168.45.100 -o capstones/target/
"""

import argparse
import sys
import time
from pathlib import Path
from datetime import datetime

try:
    from .port_scanner import PortScanner
    from .parallel_enumerator import ParallelEnumerator
    from crack.core.themes import Colors
    CVELookup = None  # Optional module
except ImportError:
    # Fallback for direct execution
    from port_scanner import PortScanner
    from parallel_enumerator import ParallelEnumerator
    CVELookup = None

    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'


def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}┌─────────────────────────────────────────────────────────┐
│         ENUMERATION SCANNER - Professional Edition              │
│  Two-Stage Port Scan → Parallel Enumeration → CVE      │
└─────────────────────────────────────────────────────────┘{Colors.END}
    """
    print(banner)


def save_markdown_report(target, output_dir, scan_results, parallel_results, cve_results):
    """Generate markdown report for documentation"""
    report_file = Path(output_dir) / "enumeration.md"

    with open(report_file, 'w') as f:
        # Header
        f.write(f"# Enumeration Report\n\n")
        f.write(f"**Target**: {target}\n\n")
        f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Scan Type**: Two-Stage Port Discovery + Parallel Enumeration\n\n")

        # Methodology
        f.write(f"## Methodology\n\n")
        f.write(f"### Two-Stage Port Scanning (Time-Optimized)\n\n")
        f.write(f"**Stage 1: Fast Port Discovery**\n")
        f.write(f"```bash\n")
        f.write(f"nmap -p- --min-rate=5000 -oG ports.gnmap {target}\n")
        f.write(f"```\n")
        f.write(f"- Scans all 65535 ports in 10-30 seconds\n")
        f.write(f"- No service detection (saves time)\n")
        f.write(f"- Finds: {len(scan_results['ports'])} open ports\n\n")

        f.write(f"**Stage 2: Targeted Service Detection**\n")
        f.write(f"```bash\n")
        ports_str = ','.join(map(str, scan_results['ports']))
        f.write(f"nmap -p{ports_str} -sV -sC -oA service_scan {target}\n")
        f.write(f"```\n")
        f.write(f"- Scans ONLY confirmed open ports (saves 3-5 minutes)\n")
        f.write(f"- Service version detection for CVE matching\n")
        f.write(f"- Default NSE scripts for safe enumeration\n\n")

        # Open Ports
        f.write(f"## Open Ports\n\n")
        f.write(f"```\n")
        for port in scan_results['ports']:
            f.write(f"{port}/tcp\n")
        f.write(f"```\n\n")

        # Parallel Scans
        f.write(f"## Parallel Enumeration\n\n")
        f.write(f"Run simultaneously while targeted nmap executes:\n\n")

        if parallel_results:
            for scan_name, result in parallel_results.items():
                status = "✓ Complete" if result['success'] else "✗ Failed"
                f.write(f"- **{scan_name}**: {status}\n")
            f.write(f"\n")

        # CVE Findings
        if cve_results:
            f.write(f"## CVE & Exploit Findings\n\n")
            for port, data in cve_results.items():
                f.write(f"### Port {port}: {data['service']}\n\n")
                f.write(f"**Version**: {data['version']}\n\n")
                f.write(f"**Exploits Found**:\n\n")
                for exploit in data['exploits']:
                    f.write(f"- {exploit['title']}\n")
                    f.write(f"  - Path: `{exploit['path']}`\n")
                f.write(f"\n")

        # Next Steps
        f.write(f"## Next Steps\n\n")
        f.write(f"1. **Review service scans**: `cat {output_dir}/service_scan.nmap`\n")
        f.write(f"2. **Analyze CVE findings**: Research exploits found above\n")

        if 'WhatWeb' in parallel_results:
            f.write(f"3. **Check web technologies**: `cat {output_dir}/whatweb.txt`\n")

        if 'Nikto' in parallel_results:
            f.write(f"4. **Review nikto findings**: `cat {output_dir}/nikto.txt`\n")

        if 'SMB' in parallel_results:
            f.write(f"5. **Check SMB enumeration**: `cat {output_dir}/enum4linux.txt`\n")

        f.write(f"\n## Manual Verification\n\n")
        f.write(f"Always manually verify findings:\n\n")
        f.write(f"```bash\n")
        f.write(f"# Quick service check\n")
        for port in scan_results['ports'][:5]:  # Show first 5
            f.write(f"nc -nv {target} {port}\n")
        f.write(f"```\n")

    return str(report_file)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Enumeration Scanner - Fast initial target discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack enum-scan 192.168.45.100
  crack enum-scan 192.168.45.100 --full
  crack enum-scan 192.168.45.100 -o capstones/target/
  crack enum-scan 192.168.45.100 --min-rate 3000

Time Estimates:
  Quick scan: 3-5 minutes
  Full scan (with --full): 8-12 minutes

Methodology:
  1. Stage 1: Fast port discovery (30 sec)
  2. Stage 2: Targeted service scan (1-2 min)
  3. Parallel: UDP/Web/SMB scans (2-5 min)
  4. CVE lookup via searchsploit (30 sec)
        """
    )

    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-o', '--output', default='.',
                       help='Output directory (default: current directory)')
    parser.add_argument('--full', action='store_true',
                       help='Include UDP scan (requires sudo, adds 3-5 min)')
    parser.add_argument('--min-rate', type=int, default=5000,
                       help='Nmap min-rate for stage 1 (default: 5000)')
    parser.add_argument('--no-cve', action='store_true',
                       help='Skip CVE/exploit lookup')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress banner')

    args = parser.parse_args()

    # Show banner
    if not args.no_banner:
        print_banner()

    # Setup output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{Colors.BOLD}Target:{Colors.END} {args.target}")
    print(f"{Colors.BOLD}Output:{Colors.END} {output_dir}")
    print(f"{Colors.BOLD}Mode:{Colors.END} {'Full (with UDP)' if args.full else 'Quick'}")

    start_time = time.time()

    # STAGE 1 & 2: Port scanning
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}STARTING TWO-STAGE PORT SCAN{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")

    scanner = PortScanner(args.target, output_dir, min_rate=args.min_rate)
    scan_results = scanner.run()

    if not scan_results or not scan_results['ports']:
        print(f"\n{Colors.RED}✗ No open ports found. Exiting.{Colors.END}")
        sys.exit(1)

    # PARALLEL ENUMERATION
    enumerator = ParallelEnumerator(
        args.target,
        scan_results['ports'],
        output_dir,
        run_udp=args.full
    )
    parallel_results = enumerator.run()

    print(enumerator.get_summary())

    # CVE LOOKUP
    cve_results = {}
    if not args.no_cve and scan_results['scan_file']:
        lookup = CVELookup(scan_results['scan_file'])
        cve_results = lookup.lookup_all()
        print(lookup.get_summary())
        print(lookup.generate_commands())

    # FINAL REPORT
    elapsed = time.time() - start_time
    print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}ENUMERATION COMPLETE{Colors.END}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"\n{Colors.GREEN}✓ Total time:{Colors.END} {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"{Colors.GREEN}✓ Open ports:{Colors.END} {len(scan_results['ports'])}")
    print(f"{Colors.GREEN}✓ Scans completed:{Colors.END} {len([r for r in parallel_results.values() if r['success']])}/{len(parallel_results)}")

    # Generate markdown report
    report_file = save_markdown_report(
        args.target,
        output_dir,
        scan_results,
        parallel_results,
        cve_results
    )

    print(f"\n{Colors.CYAN}📄 Report saved:{Colors.END} {report_file}")
    print(f"{Colors.CYAN}📁 All output in:{Colors.END} {output_dir}/")

    print(f"\n{Colors.YELLOW}NEXT STEPS:{Colors.END}")
    print(f"  1. Review: cat {report_file}")
    print(f"  2. Analyze service versions for vulnerabilities")
    print(f"  3. Research exploits found by searchsploit")
    print(f"  4. Manual verification of interesting services")


if __name__ == '__main__':
    main()
