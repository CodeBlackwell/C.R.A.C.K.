"""
BloodTrail CLI Analyze Commands

Commands for analyzing enumeration data:
- --detect: Run attack vector detection (Azure AD Connect, GPP, LAPS)
- --analyze-svc: Analyze service accounts for attack prioritization
- --analyze-reuse: Track password reuse patterns
- --crawl-smb: Crawl SMB shares for sensitive files
"""

from argparse import Namespace
from typing import Optional

from ..base import BaseCommandGroup
from ...core.formatters import Colors
from ...core.detection import (
    get_default_registry as get_detector_registry,
    DetectionResult,
)
from ...core.service_accounts import ServiceAccountAnalyzer
from ...core.password_reuse import PasswordReuseTracker
from ...core.models import DiscoveredCredential, SourceType, Confidence


class AnalyzeCommands(BaseCommandGroup):
    """
    Attack vector detection and analysis commands.

    These commands help identify attack opportunities and prioritize targets.
    """

    @classmethod
    def add_arguments(cls, parser) -> None:
        group = parser.add_argument_group("Analysis Commands")

        group.add_argument(
            "--detect",
            action="store_true",
            help="Detect attack vectors (Azure AD Connect, GPP, LAPS)",
        )

        group.add_argument(
            "--analyze-svc",
            action="store_true",
            help="Analyze service accounts for attack prioritization",
        )

        group.add_argument(
            "--analyze-reuse",
            metavar="CREDS_FILE",
            help="Analyze password reuse from credentials file",
        )

        group.add_argument(
            "--crawl-smb",
            metavar="HOST",
            help="Crawl SMB shares for sensitive files (requires -u/-p)",
        )

        group.add_argument(
            "--share",
            metavar="NAME",
            help="Specific share to crawl (with --crawl-smb)",
        )

    @classmethod
    def handle(cls, args: Namespace) -> int:
        if args.detect:
            return cls._handle_detect(args)
        elif args.analyze_svc:
            return cls._handle_analyze_svc(args)
        elif args.analyze_reuse:
            return cls._handle_analyze_reuse(args)
        elif args.crawl_smb:
            return cls._handle_crawl_smb(args)
        return -1  # Not handled

    @classmethod
    def _handle_detect(cls, args: Namespace) -> int:
        """Run attack vector detection against BloodHound data."""
        conn = cls.require_neo4j(args)
        if not conn:
            return 1

        cls.print_header("ATTACK VECTOR DETECTION")

        registry = get_detector_registry()
        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        # Get users and groups from BloodHound
        users = []
        groups = []

        try:
            # Query users
            result = conn.session.run("MATCH (u:User) RETURN u.name AS name, u.description AS description LIMIT 500")
            users = [dict(r) for r in result]

            # Query groups
            result = conn.session.run("""
                MATCH (g:Group)
                OPTIONAL MATCH (u:User)-[:MemberOf*1..]->(g)
                RETURN g.name AS name, collect(DISTINCT u.name)[..10] AS members
                LIMIT 200
            """)
            groups = [dict(r) for r in result]

        except Exception as e:
            cls.print_error(f"Failed to query BloodHound: {e}")
            conn.close()
            return 1

        # Run detectors
        results = registry.detect_all_ldap(users, groups, [], context)

        if not results:
            cls.print_warning("No attack vectors detected")
            print("\nNote: Detection works best with LDAP enumeration data imported to BloodHound.")
            conn.close()
            return 0

        # Display results
        for detection in results:
            cls._display_detection(detection)

        conn.close()
        return 0

    @classmethod
    def _display_detection(cls, detection: DetectionResult) -> None:
        """Display a single detection result with attack commands."""
        confidence_colors = {
            "confirmed": Colors.GREEN,
            "likely": Colors.YELLOW,
            "possible": Colors.CYAN,
        }
        color = confidence_colors.get(detection.confidence.value, Colors.WHITE)

        print(f"\n{Colors.BOLD}{color}[{detection.confidence.value.upper()}] {detection.name}{Colors.RESET}")
        print(f"  Indicator: {detection.indicator}")

        print(f"\n  {Colors.BOLD}Evidence:{Colors.RESET}")
        for evidence in detection.evidence:
            print(f"    - {evidence}")

        if detection.attack_commands:
            print(f"\n  {Colors.BOLD}Attack Commands:{Colors.RESET}")
            for i, cmd in enumerate(detection.attack_commands[:5], 1):
                print(f"\n    [{i}] {cmd.description}")
                print(f"        {Colors.CYAN}$ {cmd.command}{Colors.RESET}")
                if cmd.explanation:
                    print(f"        {Colors.DIM}Why: {cmd.explanation[:100]}...{Colors.RESET}")

        if detection.next_steps:
            print(f"\n  {Colors.BOLD}Next Steps:{Colors.RESET}")
            for step in detection.next_steps:
                print(f"    - {step}")

        if detection.references:
            print(f"\n  {Colors.BOLD}References:{Colors.RESET}")
            for ref in detection.references[:3]:
                print(f"    - {ref}")

    @classmethod
    def _handle_analyze_svc(cls, args: Namespace) -> int:
        """Analyze service accounts from BloodHound data."""
        conn = cls.require_neo4j(args)
        if not conn:
            return 1

        cls.print_header("SERVICE ACCOUNT ANALYSIS")

        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        analyzer = ServiceAccountAnalyzer()

        try:
            result = analyzer.analyze_from_bloodhound(conn.session, context)
        except Exception as e:
            cls.print_error(f"Analysis failed: {e}")
            conn.close()
            return 1

        if not result.all_accounts:
            cls.print_warning("No service accounts identified")
            conn.close()
            return 0

        # Display report
        print(analyzer.get_report(result))

        # Display spray wordlist
        domain = context.get('domain', '')
        wordlist = analyzer.get_spray_wordlist(domain)
        print(f"\n{Colors.BOLD}Suggested Spray Wordlist:{Colors.RESET}")
        for pwd in wordlist[:10]:
            print(f"  {pwd}")
        print(f"  ... ({len(wordlist)} total)")

        conn.close()
        return 0

    @classmethod
    def _handle_analyze_reuse(cls, args: Namespace) -> int:
        """Analyze password reuse from credentials file."""
        creds_file = args.analyze_reuse

        cls.print_header("PASSWORD REUSE ANALYSIS")

        # Read credentials file
        try:
            with open(creds_file, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            cls.print_error(f"Failed to read {creds_file}: {e}")
            return 1

        tracker = PasswordReuseTracker()

        # Parse credentials (format: user:password or domain/user:password)
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            user_part, password = parts

            # Parse domain if present
            domain = None
            if '/' in user_part:
                domain, username = user_part.split('/', 1)
            elif '\\' in user_part:
                domain, username = user_part.split('\\', 1)
            else:
                username = user_part

            cred = DiscoveredCredential(
                username=username,
                secret=password,
                domain=domain,
                source=creds_file,
                source_type=SourceType.MANUAL,
                confidence=Confidence.CONFIRMED,
            )
            tracker.add_credential(cred)

        # Display report
        print(tracker.get_reuse_report())

        # Spray suggestions
        context = {
            "target_ip": getattr(args, 'dc_ip', '<DC_IP>'),
            "domain": getattr(args, 'domain', '<DOMAIN>'),
        }

        suggestions = tracker.get_spray_suggestions([], context)
        if suggestions:
            print(f"\n{Colors.BOLD}Spray Suggestions:{Colors.RESET}")
            for s in suggestions[:5]:
                print(f"\n  [{s.priority}] {s.action}")
                print(f"      {Colors.CYAN}$ {s.command}{Colors.RESET}")
                print(f"      {Colors.DIM}Why: {s.explanation}{Colors.RESET}")

        return 0

    @classmethod
    def _handle_crawl_smb(cls, args: Namespace) -> int:
        """Crawl SMB shares for sensitive files."""
        try:
            from ...enumerators.smb_crawler import SMBCrawler, create_smb_crawler
        except ImportError as e:
            cls.print_error(f"SMB crawler requires impacket: {e}")
            print("Install with: pip install impacket")
            return 1

        host = args.crawl_smb
        username = getattr(args, 'username', None) or getattr(args, 'u', None)
        password = getattr(args, 'password', None) or getattr(args, 'p', None)
        domain = getattr(args, 'domain', '')

        if not username or not password:
            cls.print_error("SMB crawling requires credentials (-u/-p)")
            return 1

        cls.print_header(f"SMB SHARE CRAWL: {host}")

        try:
            crawler = SMBCrawler(
                host=host,
                username=username,
                password=password,
                domain=domain,
            )

            with crawler:
                # List shares
                shares = crawler.list_shares_detailed()
                print(f"\n{Colors.BOLD}Accessible Shares:{Colors.RESET}")
                for share in shares:
                    status = f"{Colors.GREEN}readable{Colors.RESET}" if share.readable else f"{Colors.RED}denied{Colors.RESET}"
                    print(f"  {share.name}: {status}")
                    if share.remark:
                        print(f"    Remark: {share.remark}")

                # Filter to specific share if requested
                target_shares = [args.share] if args.share else None

                # Crawl and extract
                print(f"\n{Colors.BOLD}Crawling for sensitive files...{Colors.RESET}")
                result = crawler.crawl_and_extract(shares=target_shares)

                # Display results
                print(f"\n{Colors.BOLD}Discovery Summary:{Colors.RESET}")
                print(f"  Shares accessed: {', '.join(result.shares_accessed)}")
                print(f"  Files found: {len(result.files)}")
                print(f"  Credentials extracted: {len(result.credentials)}")

                if result.files:
                    print(f"\n{Colors.BOLD}Top Interesting Files:{Colors.RESET}")
                    for f in sorted(result.files, key=lambda x: -x.interesting_score)[:10]:
                        print(f"  [{f.interesting_score:3d}] {f.path}")
                        print(f"        Reasons: {', '.join(f.score_reasons)}")

                if result.credentials:
                    print(f"\n{Colors.BOLD}Extracted Credentials:{Colors.RESET}")
                    for cred in result.credentials:
                        print(f"  {Colors.GREEN}{cred.upn}{Colors.RESET}")
                        print(f"    Source: {cred.source}")
                        print(f"    Confidence: {cred.confidence.value}")

                if result.next_steps:
                    print(f"\n{Colors.BOLD}Next Steps:{Colors.RESET}")
                    for step in result.next_steps[:5]:
                        print(f"  [{step.priority}] {step.action}")
                        print(f"      {Colors.CYAN}$ {step.command}{Colors.RESET}")

                if result.errors:
                    print(f"\n{Colors.YELLOW}Errors:{Colors.RESET}")
                    for err in result.errors[:5]:
                        print(f"  - {err}")

        except Exception as e:
            cls.print_error(f"SMB crawl failed: {e}")
            return 1

        return 0
