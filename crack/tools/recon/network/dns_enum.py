#!/usr/bin/env python3
"""
DNS Recursive Enumeration - OSCP Edition
========================================

Multi-level DNS discovery that recursively follows:
- Discovered subdomains
- Nameserver IPs
- All discovered IP addresses
- CNAME chains

Performs comprehensive DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
and reverse DNS lookups on all discovered IPs until no new discoveries are found.

Usage:
    crack dns-enum example.com
    crack dns-enum example.com --max-depth 3
    crack dns-enum example.com -o /path/to/output
"""

import subprocess
import argparse
import json
import re
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
import time

# Try to import CRACK themes, fallback to ANSI codes
try:
    from crack.core.themes import Colors
except ImportError:
    class Colors:
        CYAN = '\033[96m'
        BOLD = '\033[1m'
        YELLOW = '\033[93m'
        GREEN = '\033[92m'
        RED = '\033[91m'
        END = '\033[0m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'


@dataclass
class DNSRecord:
    """Represents a single DNS record"""
    domain: str
    record_type: str
    value: str
    discovered_via: str
    depth: int
    parent: Optional[str] = None


@dataclass
class DNSDiscovery:
    """Holds all DNS discovery data"""
    root_domain: str
    start_time: datetime = field(default_factory=datetime.now)

    # Tracking sets to prevent loops
    domains_visited: Set[str] = field(default_factory=set)
    ips_visited: Set[str] = field(default_factory=set)

    # Discovery queue: (entity, entity_type, depth, parent, discovered_via)
    discovery_queue: deque = field(default_factory=deque)

    # Results storage
    dns_records: List[DNSRecord] = field(default_factory=list)
    ip_to_domains: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    domain_to_ips: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    cname_chains: List[Tuple[str, str]] = field(default_factory=list)
    discovery_tree: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))

    # Statistics
    max_depth_reached: int = 0
    total_queries: int = 0
    failed_queries: int = 0

    def add_record(self, record: DNSRecord):
        """Add a DNS record and update mappings"""
        self.dns_records.append(record)

        # Update depth tracking
        if record.depth > self.max_depth_reached:
            self.max_depth_reached = record.depth

        # Update mappings based on record type
        if record.record_type in ['A', 'AAAA']:
            self.domain_to_ips[record.domain].add(record.value)
            self.ip_to_domains[record.value].add(record.domain)
        elif record.record_type == 'CNAME':
            self.cname_chains.append((record.domain, record.value))

        # Update discovery tree
        if record.parent:
            self.discovery_tree[record.parent].append(f"{record.domain} ({record.record_type})")


class RecursiveDNSEnumerator:
    """Recursive DNS enumeration engine"""

    def __init__(self, root_domain: str, output_dir: Optional[Path] = None,
                 max_depth: int = 10, rate_limit: float = 0.1, timeout: int = 10):
        self.discovery = DNSDiscovery(root_domain=root_domain)
        self.max_depth = max_depth
        self.rate_limit = rate_limit  # Seconds between queries
        self.timeout = timeout  # Timeout per DNS query

        # Setup output directory (None = console output only)
        self.output_dir = Path(output_dir) if output_dir else None

        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{Colors.BOLD}{Colors.CYAN}=== Recursive DNS Enumeration ==={Colors.END}")
        print(f"{Colors.YELLOW}Target:{Colors.END} {root_domain}")
        if self.output_dir:
            print(f"{Colors.YELLOW}Output Mode:{Colors.END} Save to {self.output_dir}")
        else:
            print(f"{Colors.YELLOW}Output Mode:{Colors.END} Console only (use -o to save files)")
        print(f"{Colors.YELLOW}Max Depth:{Colors.END} {max_depth}")
        print(f"{Colors.YELLOW}Rate Limit:{Colors.END} {rate_limit}s between queries\n")

    def run_command(self, cmd: List[str], description: str) -> Tuple[bool, str]:
        """Execute a command with error handling and educational output"""
        self.discovery.total_queries += 1

        # Echo command to console (educational)
        cmd_str = ' '.join(cmd)
        print(f"{Colors.BLUE}  $ {cmd_str}{Colors.END}")

        # Rate limiting
        time.sleep(self.rate_limit)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode == 0 and result.stdout.strip():
                return True, result.stdout
            else:
                self.discovery.failed_queries += 1
                return False, result.stderr

        except subprocess.TimeoutExpired:
            self.discovery.failed_queries += 1
            return False, "Query timeout"
        except FileNotFoundError:
            self.discovery.failed_queries += 1
            return False, f"Tool not installed: {cmd[0]}"
        except Exception as e:
            self.discovery.failed_queries += 1
            return False, str(e)

    def query_dns_record(self, domain: str, record_type: str, depth: int,
                        parent: Optional[str] = None) -> List[str]:
        """Query a specific DNS record type using dig"""
        cmd = ['dig', '+short', record_type, domain]
        success, output = self.run_command(cmd, f"Query {record_type} for {domain}")

        if not success:
            return []

        # Parse dig output
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Clean up the value (remove trailing dots from domains)
            value = line.rstrip('.')

            # Skip invalid results
            if not value or value.startswith(';'):
                continue

            results.append(value)

            # Add to discovery records
            record = DNSRecord(
                domain=domain,
                record_type=record_type,
                value=value,
                discovered_via=f"dig +short {record_type}",
                depth=depth,
                parent=parent
            )
            self.discovery.add_record(record)

        return results

    def query_all_records(self, domain: str, depth: int, parent: Optional[str] = None) -> Dict[str, List[str]]:
        """Query all relevant DNS record types for a domain"""
        print(f"{Colors.CYAN}[Depth {depth}]{Colors.END} Enumerating: {Colors.BOLD}{domain}{Colors.END}")

        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        for rtype in record_types:
            values = self.query_dns_record(domain, rtype, depth, parent)
            if values:
                results[rtype] = values
                print(f"  {Colors.GREEN}✓{Colors.END} {rtype}: {len(values)} record(s)")

        return results

    def reverse_dns_lookup(self, ip: str, depth: int, parent: Optional[str] = None) -> List[str]:
        """Perform reverse DNS lookup using host command"""
        cmd = ['host', ip]
        success, output = self.run_command(cmd, f"Reverse DNS for {ip}")

        if not success:
            return []

        # Parse host output
        # Format: "159.67.213.44.in-addr.arpa domain name pointer ec2-44-213-67-159.compute-1.amazonaws.com."
        domains = []
        for line in output.strip().split('\n'):
            match = re.search(r'domain name pointer (.+)\.?$', line)
            if match:
                domain = match.group(1).rstrip('.')
                domains.append(domain)

                # Add to discovery records
                record = DNSRecord(
                    domain=ip,
                    record_type='PTR',
                    value=domain,
                    discovered_via='host (reverse DNS)',
                    depth=depth,
                    parent=parent
                )
                self.discovery.add_record(record)

                print(f"  {Colors.GREEN}✓{Colors.END} PTR: {ip} → {domain}")

        return domains

    def is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain name"""
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(domain))

    def is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        # IPv4 pattern
        ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(
            r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$'
        )
        return bool(ipv4_pattern.match(ip)) or bool(ipv6_pattern.match(ip))

    def recursive_discover(self):
        """Main recursive discovery algorithm using BFS"""
        # Initialize with root domain
        self.discovery.discovery_queue.append((
            self.discovery.root_domain,
            'domain',
            0,
            None,
            'initial target'
        ))

        print(f"\n{Colors.BOLD}{Colors.YELLOW}Starting recursive discovery...{Colors.END}\n")

        iteration = 0
        while self.discovery.discovery_queue:
            iteration += 1
            entity, entity_type, depth, parent, discovered_via = self.discovery.discovery_queue.popleft()

            # Check depth limit
            if depth > self.max_depth:
                print(f"{Colors.YELLOW}⚠{Colors.END} Max depth reached for {entity}")
                continue

            # Process based on entity type
            if entity_type == 'domain':
                # Skip if already visited
                if entity in self.discovery.domains_visited:
                    continue

                self.discovery.domains_visited.add(entity)

                # Validate domain
                if not self.is_valid_domain(entity):
                    continue

                # Query all DNS records
                records = self.query_all_records(entity, depth, parent)

                # Queue discovered entities
                # A/AAAA records → IPs
                for ip in records.get('A', []) + records.get('AAAA', []):
                    if self.is_valid_ip(ip):
                        self.discovery.discovery_queue.append((
                            ip,
                            'ip',
                            depth + 1,
                            entity,
                            f'{entity} A/AAAA record'
                        ))

                # NS records → nameserver domains
                for ns in records.get('NS', []):
                    if self.is_valid_domain(ns):
                        self.discovery.discovery_queue.append((
                            ns,
                            'domain',
                            depth + 1,
                            entity,
                            f'{entity} NS record'
                        ))

                # CNAME records → target domains
                for cname_target in records.get('CNAME', []):
                    if self.is_valid_domain(cname_target):
                        self.discovery.discovery_queue.append((
                            cname_target,
                            'domain',
                            depth + 1,
                            entity,
                            f'{entity} CNAME target'
                        ))

                # MX records → mail server domains (extract domain from "priority domain" format)
                for mx in records.get('MX', []):
                    # MX format is often "10 mail.example.com"
                    mx_domain = mx.split()[-1].rstrip('.')
                    if self.is_valid_domain(mx_domain):
                        self.discovery.discovery_queue.append((
                            mx_domain,
                            'domain',
                            depth + 1,
                            entity,
                            f'{entity} MX record'
                        ))

            elif entity_type == 'ip':
                # Skip if already visited
                if entity in self.discovery.ips_visited:
                    continue

                self.discovery.ips_visited.add(entity)

                # Validate IP
                if not self.is_valid_ip(entity):
                    continue

                print(f"{Colors.CYAN}[Depth {depth}]{Colors.END} Reverse DNS: {Colors.BOLD}{entity}{Colors.END}")

                # Reverse DNS lookup
                ptr_domains = self.reverse_dns_lookup(entity, depth, parent)

                # Queue discovered domains
                for domain in ptr_domains:
                    if self.is_valid_domain(domain):
                        self.discovery.discovery_queue.append((
                            domain,
                            'domain',
                            depth + 1,
                            entity,
                            f'PTR record for {entity}'
                        ))

        print(f"\n{Colors.BOLD}{Colors.GREEN}✓ Discovery Complete!{Colors.END}")
        print(f"{Colors.YELLOW}Iterations:{Colors.END} {iteration}")
        print(f"{Colors.YELLOW}Domains Discovered:{Colors.END} {len(self.discovery.domains_visited)}")
        print(f"{Colors.YELLOW}IPs Discovered:{Colors.END} {len(self.discovery.ips_visited)}")
        print(f"{Colors.YELLOW}DNS Records:{Colors.END} {len(self.discovery.dns_records)}")
        print(f"{Colors.YELLOW}Max Depth Reached:{Colors.END} {self.discovery.max_depth_reached}")
        print(f"{Colors.YELLOW}Total Queries:{Colors.END} {self.discovery.total_queries}")
        print(f"{Colors.YELLOW}Failed Queries:{Colors.END} {self.discovery.failed_queries}\n")


def generate_discovery_tree_ascii(discovery: DNSDiscovery) -> str:
    """Generate ASCII art discovery tree"""
    lines = []
    lines.append(f"{discovery.root_domain} (Level 0)")

    def add_children(entity: str, indent: int = 0, is_last: bool = True):
        """Recursively add children to tree"""
        children = discovery.discovery_tree.get(entity, [])

        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)

            # Draw tree connectors
            if indent > 0:
                prefix = "    " * (indent - 1)
                if is_last:
                    prefix += "└── " if is_last_child else "├── "
                else:
                    prefix += "│   " if not is_last_child else "├── "
            else:
                prefix = "├── " if not is_last_child else "└── "

            lines.append(f"{prefix}{child}")

            # Recurse for children (extract entity name from "name (type)" format)
            child_entity = child.split(' (')[0] if ' (' in child else child
            add_children(child_entity, indent + 1, is_last_child)

    add_children(discovery.root_domain)
    return '\n'.join(lines)


def print_console_report(enumerator: RecursiveDNSEnumerator):
    """Print comprehensive report to console"""
    discovery = enumerator.discovery
    end_time = datetime.now()
    duration = (end_time - discovery.start_time).total_seconds()

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}DNS ENUMERATION REPORT{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    # Header
    print(f"{Colors.BOLD}Target Domain:{Colors.END} {discovery.root_domain}")
    print(f"{Colors.BOLD}Scan Date:{Colors.END} {discovery.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.BOLD}Duration:{Colors.END} {duration:.1f} seconds")
    print(f"{Colors.BOLD}Max Recursion Depth:{Colors.END} {enumerator.max_depth}")
    print(f"{Colors.BOLD}Depth Reached:{Colors.END} {discovery.max_depth_reached}\n")

    # Executive Summary
    print(f"{Colors.BOLD}{Colors.YELLOW}EXECUTIVE SUMMARY{Colors.END}")
    print(f"  Domains Discovered:     {Colors.GREEN}{len(discovery.domains_visited)}{Colors.END}")
    print(f"  Unique IP Addresses:    {Colors.GREEN}{len(discovery.ips_visited)}{Colors.END}")
    print(f"  Total DNS Records:      {Colors.GREEN}{len(discovery.dns_records)}{Colors.END}")
    print(f"  CNAME Chains:           {Colors.GREEN}{len(discovery.cname_chains)}{Colors.END}")
    print(f"  Total DNS Queries:      {discovery.total_queries}")
    print(f"  Failed Queries:         {discovery.failed_queries}\n")

    # Discovery Tree
    print(f"{Colors.BOLD}{Colors.YELLOW}DISCOVERY TREE{Colors.END}")
    print(generate_discovery_tree_ascii(discovery))
    print()

    # DNS Records by Type
    print(f"{Colors.BOLD}{Colors.YELLOW}DNS RECORDS{Colors.END}\n")
    records_by_type = defaultdict(list)
    for record in discovery.dns_records:
        records_by_type[record.record_type].append(record)

    for record_type in sorted(records_by_type.keys()):
        records = records_by_type[record_type]
        print(f"{Colors.BOLD}{record_type} Records ({len(records)}){Colors.END}")

        for record in sorted(records, key=lambda r: r.depth):
            print(f"  {Colors.CYAN}{record.domain}{Colors.END} → {record.value}")
            print(f"    Depth: {record.depth} | Via: {record.discovered_via}")

        print()

    # IP Address Inventory
    print(f"{Colors.BOLD}{Colors.YELLOW}IP ADDRESS INVENTORY{Colors.END}")
    print(f"Total unique IPs: {Colors.GREEN}{len(discovery.ips_visited)}{Colors.END}\n")

    for ip in sorted(discovery.ips_visited):
        domains = list(discovery.ip_to_domains.get(ip, set()))
        ptr_records = [r.value for r in discovery.dns_records if r.domain == ip and r.record_type == 'PTR']

        print(f"{Colors.BOLD}{ip}{Colors.END}")
        if domains:
            print(f"  Associated: {', '.join(domains)}")
        if ptr_records:
            print(f"  PTR: {', '.join(ptr_records)}")
        print()

    # CNAME Chains
    if discovery.cname_chains:
        print(f"{Colors.BOLD}{Colors.YELLOW}CNAME CHAINS{Colors.END}")
        for source, target in discovery.cname_chains:
            print(f"  {Colors.CYAN}{source}{Colors.END} → {target}")
        print()

    # Discovered Domains
    print(f"{Colors.BOLD}{Colors.YELLOW}DISCOVERED DOMAINS ({len(discovery.domains_visited)}){Colors.END}")
    for domain in sorted(discovery.domains_visited):
        print(f"  {domain}")
    print()

    # Next Steps
    print(f"{Colors.BOLD}{Colors.YELLOW}NEXT STEPS{Colors.END}\n")

    if discovery.ips_visited:
        print(f"{Colors.BOLD}1. Port Scanning{Colors.END}")
        ips_list = ' '.join(list(discovery.ips_visited))
        print(f"   nmap -T4 -p- {ips_list}")
        print()

    ns_servers = [r.value for r in discovery.dns_records if r.record_type == 'NS']
    if ns_servers:
        print(f"{Colors.BOLD}2. Zone Transfer Attempts{Colors.END}")
        for ns in ns_servers:
            print(f"   dig axfr @{ns} {discovery.root_domain}")
        print()

    if discovery.cname_chains:
        print(f"{Colors.BOLD}3. Subdomain Takeover Check{Colors.END}")
        print(f"   subjack -w discovered_domains.txt -t 100")
        print()

    # OSCP Tips
    print(f"{Colors.BOLD}{Colors.YELLOW}OSCP EXAM TIPS{Colors.END}")
    print(f"  • Time Management: Limit depth to 2-3 during exam")
    print(f"  • Manual Verification: Always verify with 'dig' and 'host'")
    print(f"  • Documentation: Document methodology and failures")
    print(f"  • Focus: Prioritize actionable findings (ports, web apps)")
    print()

    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")


def generate_markdown_report(enumerator: RecursiveDNSEnumerator, output_file: Path):
    """Generate comprehensive OSCP-style markdown report"""
    discovery = enumerator.discovery
    end_time = datetime.now()
    duration = (end_time - discovery.start_time).total_seconds()

    report = []

    # Header
    report.append("# Recursive DNS Enumeration Report")
    report.append("")
    report.append(f"**Target Domain**: {discovery.root_domain}")
    report.append(f"**Scan Date**: {discovery.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Duration**: {duration:.1f} seconds")
    report.append(f"**Max Recursion Depth**: {enumerator.max_depth}")
    report.append(f"**Depth Reached**: {discovery.max_depth_reached}")
    report.append("")

    # Executive Summary
    report.append("## Executive Summary")
    report.append("")
    report.append(f"- **Domains Discovered**: {len(discovery.domains_visited)}")
    report.append(f"- **Unique IP Addresses**: {len(discovery.ips_visited)}")
    report.append(f"- **Total DNS Records**: {len(discovery.dns_records)}")
    report.append(f"- **CNAME Chains**: {len(discovery.cname_chains)}")
    report.append(f"- **Total DNS Queries**: {discovery.total_queries}")
    report.append(f"- **Failed Queries**: {discovery.failed_queries}")
    report.append("")

    # Methodology
    report.append("## Methodology")
    report.append("")
    report.append("### Recursive DNS Enumeration Process")
    report.append("")
    report.append("This enumeration follows a **breadth-first search (BFS)** approach to comprehensively map DNS infrastructure:")
    report.append("")
    report.append("1. **Initial Query**: Start with root domain")
    report.append("2. **Record Enumeration**: Query all DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME)")
    report.append("3. **Discovery Queue**: For each discovered entity:")
    report.append("   - **Subdomains** (NS, MX, CNAME targets) → Full enumeration")
    report.append("   - **IP Addresses** (A/AAAA records) → Reverse DNS lookup")
    report.append("   - **PTR Records** → Enqueue discovered domains")
    report.append("4. **Recursion**: Repeat until no new discoveries")
    report.append("5. **Loop Prevention**: Track visited domains/IPs to avoid infinite loops")
    report.append("")
    report.append("### Commands Used")
    report.append("")
    report.append("```bash")
    report.append("# DNS record enumeration")
    report.append("dig +short A example.com")
    report.append("# Purpose: Query A records (IPv4 addresses)")
    report.append("# +short: Display only the answer section (clean output)")
    report.append("")
    report.append("# Reverse DNS lookup")
    report.append("host 1.2.3.4")
    report.append("# Purpose: Resolve IP to domain name (PTR record)")
    report.append("# Manual Alternative: dig -x 1.2.3.4 +short")
    report.append("```")
    report.append("")
    report.append("### OSCP Exam Relevance")
    report.append("")
    report.append("- **Time Estimate**: 5-10 minutes for basic enumeration, 15-30 minutes for full recursive discovery")
    report.append("- **Use Case**: Discover hidden subdomains, identify infrastructure relationships, map attack surface")
    report.append("- **Manual Verification**: Always verify automated findings with manual `dig` queries")
    report.append("- **Next Steps**: Port scan all discovered IPs, enumerate web applications, check for subdomain takeover")
    report.append("")

    # Discovery Tree
    report.append("## Discovery Tree")
    report.append("")
    report.append("Visual representation of the recursive discovery path:")
    report.append("")
    report.append("```")
    report.append(generate_discovery_tree_ascii(discovery))
    report.append("```")
    report.append("")

    # DNS Records Table
    report.append("## DNS Records")
    report.append("")
    report.append("All discovered DNS records grouped by type:")
    report.append("")

    # Group records by type
    records_by_type = defaultdict(list)
    for record in discovery.dns_records:
        records_by_type[record.record_type].append(record)

    for record_type in sorted(records_by_type.keys()):
        records = records_by_type[record_type]
        report.append(f"### {record_type} Records ({len(records)})")
        report.append("")
        report.append("| Domain | Value | Depth | Discovered Via |")
        report.append("|--------|-------|-------|----------------|")

        for record in sorted(records, key=lambda r: r.depth):
            domain = record.domain[:50] + "..." if len(record.domain) > 50 else record.domain
            value = record.value[:50] + "..." if len(record.value) > 50 else record.value
            discovered_via = record.discovered_via[:40] + "..." if len(record.discovered_via) > 40 else record.discovered_via
            report.append(f"| {domain} | {value} | {record.depth} | {discovered_via} |")

        report.append("")

    # IP Address Inventory
    report.append("## IP Address Inventory")
    report.append("")
    report.append(f"Total unique IP addresses discovered: **{len(discovery.ips_visited)}**")
    report.append("")
    report.append("| IP Address | Associated Domains | Reverse DNS |")
    report.append("|------------|-------------------|-------------|")

    for ip in sorted(discovery.ips_visited):
        domains = ', '.join(sorted(discovery.ip_to_domains.get(ip, set())))[:60]
        if len(domains) > 60:
            domains += "..."

        # Find PTR records for this IP
        ptr_records = [r.value for r in discovery.dns_records if r.domain == ip and r.record_type == 'PTR']
        ptr = ', '.join(ptr_records[:2])[:40] if ptr_records else "N/A"
        if len(ptr_records) > 2:
            ptr += "..."

        report.append(f"| {ip} | {domains or 'N/A'} | {ptr} |")

    report.append("")

    # CNAME Chains
    if discovery.cname_chains:
        report.append("## CNAME Chains")
        report.append("")
        report.append("Redirect paths discovered:")
        report.append("")
        report.append("| Source | Target |")
        report.append("|--------|--------|")

        for source, target in discovery.cname_chains:
            report.append(f"| {source} | {target} |")

        report.append("")

    # Domain List
    report.append("## Discovered Domains")
    report.append("")
    report.append(f"Complete list of {len(discovery.domains_visited)} discovered domains:")
    report.append("")
    report.append("```")
    for domain in sorted(discovery.domains_visited):
        report.append(domain)
    report.append("```")
    report.append("")

    # Attack Surface & Next Steps
    report.append("## Attack Surface Analysis")
    report.append("")
    report.append("### Immediate Next Steps")
    report.append("")

    # Generate specific commands based on discoveries
    if discovery.ips_visited:
        report.append("#### 1. Port Scanning")
        report.append("")
        report.append("Scan all discovered IP addresses:")
        report.append("")
        report.append("```bash")
        report.append("# Quick scan (top 1000 ports)")
        ips_list = ' '.join(list(discovery.ips_visited)[:5])
        if len(discovery.ips_visited) > 5:
            ips_list += " ..."
        report.append(f"nmap -T4 -p- {ips_list}")
        report.append("")
        report.append("# Service detection on discovered ports")
        report.append(f"nmap -sV -sC -p <ports> {list(discovery.ips_visited)[0]}")
        report.append("```")
        report.append("")

    # Web enumeration if http/https domains found
    web_domains = [d for d in discovery.domains_visited if 'www' in d or 'web' in d]
    if web_domains:
        report.append("#### 2. Web Application Enumeration")
        report.append("")
        report.append("```bash")
        for domain in web_domains[:3]:
            report.append(f"# {domain}")
            report.append(f"nikto -h https://{domain}")
            report.append(f"dirb https://{domain} /usr/share/wordlists/dirb/common.txt")
        if len(web_domains) > 3:
            report.append("# ... more web targets")
        report.append("```")
        report.append("")

    # Subdomain takeover check
    if discovery.cname_chains:
        report.append("#### 3. Subdomain Takeover Check")
        report.append("")
        report.append("Check CNAME chains for potential takeover vulnerabilities:")
        report.append("")
        report.append("```bash")
        report.append("subjack -w discovered_domains.txt -t 100 -timeout 30 -o takeover_results.txt")
        report.append("```")
        report.append("")

    # Zone transfer attempts
    ns_servers = [r.value for r in discovery.dns_records if r.record_type == 'NS']
    if ns_servers:
        report.append("#### 4. Zone Transfer Attempts")
        report.append("")
        report.append("Attempt AXFR on discovered nameservers:")
        report.append("")
        report.append("```bash")
        for ns in ns_servers[:3]:
            report.append(f"dig axfr @{ns} {discovery.root_domain}")
        if len(ns_servers) > 3:
            report.append("# ... more nameservers")
        report.append("```")
        report.append("")

    # Manual Verification Section
    report.append("## Manual Verification")
    report.append("")
    report.append("Always verify automated findings manually:")
    report.append("")
    report.append("```bash")
    report.append(f"# Verify A records")
    report.append(f"dig A {discovery.root_domain}")
    report.append("")
    report.append(f"# Verify nameservers")
    report.append(f"dig NS {discovery.root_domain}")
    report.append("")
    if discovery.ips_visited:
        sample_ip = list(discovery.ips_visited)[0]
        report.append(f"# Verify reverse DNS")
        report.append(f"host {sample_ip}")
        report.append("")
    report.append(f"# Check for zone transfer")
    if ns_servers:
        report.append(f"dig axfr @{ns_servers[0]} {discovery.root_domain}")
    report.append("```")
    report.append("")

    # Lessons Learned
    report.append("## Lessons Learned")
    report.append("")
    report.append("### Key Takeaways")
    report.append("")
    report.append(f"1. **Recursion Depth**: Reached level {discovery.max_depth_reached} - demonstrates infrastructure complexity")
    report.append(f"2. **Discovery Efficiency**: {len(discovery.dns_records)} records from {discovery.total_queries} queries ({(len(discovery.dns_records)/max(discovery.total_queries, 1)*100):.1f}% success rate)")

    if discovery.cname_chains:
        report.append(f"3. **CNAME Usage**: {len(discovery.cname_chains)} CNAME records found - check for subdomain takeover vulnerabilities")

    if len(discovery.ips_visited) > 0:
        avg_domains_per_ip = len(discovery.domains_visited) / len(discovery.ips_visited)
        report.append(f"4. **Infrastructure Sharing**: Average {avg_domains_per_ip:.1f} domains per IP - indicates shared hosting or CDN usage")

    report.append("")
    report.append("### OSCP Exam Tips")
    report.append("")
    report.append("- **Time Management**: Limit recursive depth to 2-3 levels during exam to avoid time waste")
    report.append("- **Tool Independence**: Know how to reproduce findings with `dig` and `host` commands")
    report.append("- **Documentation**: Always document discovery methodology and failed attempts")
    report.append("- **Focus**: Prioritize actionable findings (open ports, web apps) over complete DNS mapping")
    report.append("")

    # Footer
    report.append("---")
    report.append("")
    report.append(f"*Report generated by CRACK DNS Enumeration Tool at {end_time.strftime('%Y-%m-%d %H:%M:%S')}*")
    report.append("")

    # Write report
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))

    print(f"{Colors.GREEN}✓{Colors.END} Markdown report saved: {output_file}")


def save_json_output(discovery: DNSDiscovery, output_file: Path):
    """Save discovery data as JSON for automation"""
    data = {
        'root_domain': discovery.root_domain,
        'scan_time': discovery.start_time.isoformat(),
        'statistics': {
            'domains_discovered': len(discovery.domains_visited),
            'ips_discovered': len(discovery.ips_visited),
            'total_records': len(discovery.dns_records),
            'max_depth': discovery.max_depth_reached,
            'total_queries': discovery.total_queries,
            'failed_queries': discovery.failed_queries
        },
        'domains': sorted(list(discovery.domains_visited)),
        'ips': sorted(list(discovery.ips_visited)),
        'dns_records': [
            {
                'domain': r.domain,
                'type': r.record_type,
                'value': r.value,
                'depth': r.depth,
                'discovered_via': r.discovered_via,
                'parent': r.parent
            }
            for r in discovery.dns_records
        ],
        'cname_chains': [{'source': s, 'target': t} for s, t in discovery.cname_chains],
        'ip_mappings': {
            ip: sorted(list(domains))
            for ip, domains in discovery.ip_to_domains.items()
        }
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"{Colors.GREEN}✓{Colors.END} JSON output saved: {output_file}")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Recursive DNS Enumeration - OSCP Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Console output (default)
  crack dns-enum offseclab.io
  crack dns-enum example.com --max-depth 3

  # Save to files
  crack dns-enum example.com -o /tmp/dns_output
  crack dns-enum example.com -o ./reports --json --max-depth 2

Time Estimates (OSCP Exam Planning):
  Quick scan (depth 2):     5-10 minutes
  Medium scan (depth 5):    10-20 minutes
  Full scan (unlimited):    20-60 minutes

Methodology:
  1. Query all DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME)
  2. Perform reverse DNS on all discovered IPs
  3. Recursively enumerate discovered subdomains and nameservers
  4. Follow CNAME chains to external domains
  5. Display results on console or save as markdown/JSON reports

OSCP Tips:
  - Use --max-depth 2 during exam to balance coverage and time
  - Always verify findings manually with 'dig' and 'host' commands
  - Focus on actionable discoveries (web apps, open services)
  - Document methodology and failed attempts
        """
    )

    parser.add_argument(
        'domain',
        help='Target domain to enumerate (e.g., example.com)'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output directory for saving markdown/JSON reports (default: console output only)',
        type=str
    )

    parser.add_argument(
        '--max-depth',
        help='Maximum recursion depth (default: 10, use 2-3 for OSCP exam)',
        type=int,
        default=10
    )

    parser.add_argument(
        '--rate-limit',
        help='Seconds between DNS queries (default: 0.1)',
        type=float,
        default=0.1
    )

    parser.add_argument(
        '--timeout',
        help='Timeout per DNS query in seconds (default: 10)',
        type=int,
        default=10
    )

    parser.add_argument(
        '--json',
        help='Also save JSON output for automation',
        action='store_true'
    )

    args = parser.parse_args()

    # Create enumerator
    output_dir = Path(args.output) if args.output else None
    enumerator = RecursiveDNSEnumerator(
        root_domain=args.domain,
        output_dir=output_dir,
        max_depth=args.max_depth,
        rate_limit=args.rate_limit,
        timeout=args.timeout
    )

    # Run discovery
    try:
        enumerator.recursive_discover()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠ Interrupted by user{Colors.END}")
        print(f"Generating report with {len(enumerator.discovery.dns_records)} records collected so far...\n")
    except Exception as e:
        print(f"\n{Colors.RED}✗ Error during enumeration: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        return 1

    # Generate reports
    try:
        if enumerator.output_dir:
            # Save to files
            markdown_file = enumerator.output_dir / 'dns_enumeration.md'
            generate_markdown_report(enumerator, markdown_file)

            if args.json:
                json_file = enumerator.output_dir / 'dns_enumeration.json'
                save_json_output(enumerator.discovery, json_file)

            print(f"\n{Colors.BOLD}{Colors.GREEN}=== Enumeration Complete ==={Colors.END}")
            print(f"{Colors.YELLOW}Reports saved to:{Colors.END} {enumerator.output_dir}\n")
        else:
            # Print to console
            print_console_report(enumerator)

    except Exception as e:
        print(f"\n{Colors.RED}✗ Error generating report: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
