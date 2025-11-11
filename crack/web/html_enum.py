#!/usr/bin/env python3
"""
HTML Enumeration Tool for OSCP
Minimalist but effective HTML parser for finding vulnerabilities
"""

import sys
import re
import argparse
import time
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup, Comment
from collections import defaultdict
from queue import Queue

try:
    from crack.themes import Colors
except ImportError:
    # Fallback for standalone execution
    class Colors:
        """Terminal colors for output"""
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'

class HTMLEnumerator:
    def __init__(self, content, base_url=None, full_output=False):
        self.soup = BeautifulSoup(content, 'html.parser')
        self.base_url = base_url
        self.full_output = full_output
        self.forms = []
        self.comments = []
        self.endpoints = set()
        self.interesting = defaultdict(list)
        self.internal_links = set()  # For recursive crawling

    def extract_forms(self):
        """Extract all forms with inputs"""
        forms = self.soup.find_all('form')

        for idx, form in enumerate(forms, 1):
            form_data = {
                'index': idx,
                'action': form.get('action', '/'),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            # Get all inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_data = {
                    'name': inp.get('name', 'unnamed'),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                    'tag': inp.name
                }
                form_data['inputs'].append(input_data)

                # Flag interesting inputs
                if input_data['type'] == 'password':
                    self.interesting['passwords'].append(f"Password field: {input_data['name']}")
                elif input_data['type'] == 'file':
                    self.interesting['file_uploads'].append(f"File upload: {input_data['name']} in {form_data['action']}")
                elif input_data['type'] == 'hidden' and input_data['value']:
                    self.interesting['hidden_fields'].append(f"{input_data['name']}={input_data['value']}")

            self.forms.append(form_data)

            # Add form action to endpoints
            if form_data['action']:
                self.endpoints.add(form_data['action'])

    def extract_comments(self):
        """Extract HTML and JavaScript comments"""
        # HTML comments
        for comment in self.soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment).strip()
            if comment_text:
                self.comments.append(comment_text)

                # Check for interesting patterns in comments
                if re.search(r'(todo|fixme|hack|bug|xxx)', comment_text, re.I):
                    self.interesting['todos'].append(comment_text[:100])
                if re.search(r'(admin|secret|backup|test)', comment_text, re.I):
                    self.interesting['sensitive_comments'].append(comment_text[:100])

        # JavaScript comments (basic)
        scripts = self.soup.find_all('script')
        for script in scripts:
            if script.string:
                # Single line comments
                js_comments = re.findall(r'//.*$', script.string, re.MULTILINE)
                # Multi-line comments
                js_comments.extend(re.findall(r'/\*.*?\*/', script.string, re.DOTALL))
                self.comments.extend(js_comments)

    def extract_links(self):
        """Extract and categorize links from HTML"""
        for link in self.soup.find_all('a', href=True):
            href = link['href']
            if href and not href.startswith('#'):
                # Add to endpoints
                self.endpoints.add(href)

                # Categorize internal vs external if base_url exists
                if self.base_url:
                    full_url = urljoin(self.base_url, href)
                    # Check if same domain (internal)
                    if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                        # Skip non-HTML resources
                        if not any(full_url.lower().endswith(ext) for ext in
                                 ['.jpg', '.png', '.gif', '.pdf', '.zip', '.exe', '.css', '.js']):
                            # Store the original href (not full URL) for internal links
                            self.internal_links.add(href)

                # Check for interesting paths
                if re.search(r'(admin|upload|api|login|config|backup|test)', href, re.I):
                    self.interesting['paths'].append(href)

    def extract_endpoints(self):
        """Extract all URLs and endpoints"""
        # Extract links first
        self.extract_links()

        # Form actions (already added in extract_forms)

        # JavaScript URLs
        scripts = self.soup.find_all('script')
        for script in scripts:
            if script.string:
                # Find AJAX endpoints
                ajax_patterns = [
                    r'["\']/((?:api|ajax|json|rest)/[^"\']*)["\']',  # Capture full path after quote
                    r'\.ajax\s*\(\s*[{]?\s*url:\s*["\']([^"\']+)["\']',  # jQuery .ajax({url: '...'})
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',  # fetch('...')
                    r'url:\s*["\']([^"\']+)["\']'  # Generic url: '...'
                ]

                for pattern in ajax_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        # Ensure we have the full path for api/ajax patterns
                        if not match.startswith('/'):
                            match = '/' + match
                        self.endpoints.add(match)
                        if '/api/' in match or '/ajax/' in match:
                            self.interesting['api_endpoints'].append(match)

        # Image and resource URLs
        for tag in self.soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src and not src.startswith('data:'):
                self.endpoints.add(src)

    def find_interesting(self):
        """Find emails, IPs, and other interesting data"""
        page_text = self.soup.get_text()

        # Email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', page_text)
        self.interesting['emails'].extend(set(emails))

        # IP addresses
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', page_text)
        # Filter out common false positives
        ips = [ip for ip in ips if not ip.startswith('0.0.0')]
        self.interesting['ips'].extend(set(ips))

        # Version numbers
        versions = re.findall(r'(?:version|v)\s*[:\s]?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', page_text, re.I)
        self.interesting['versions'].extend(set(versions))

        # Error messages
        errors = re.findall(r'(?:error|exception|warning|fatal|fail)[:\s]+([^<\n]{10,100})', page_text, re.I)
        self.interesting['errors'].extend(errors[:5])  # Limit to first 5

    def generate_report(self):
        """Generate the enumeration report"""
        print(f"\n{Colors.BOLD}HTML ENUMERATION REPORT{Colors.END}")
        print("=" * 50)

        if self.base_url:
            print(f"Target: {self.base_url}\n")

        # Forms section
        if self.forms:
            print(f"{Colors.HEADER}[FORMS] {len(self.forms)} found{Colors.END}")
            print("-" * 30)
            for form in self.forms:
                print(f"\n{Colors.BOLD}Form #{form['index']}:{Colors.END} {form['method']} {form['action']}")
                for inp in form['inputs']:
                    value_display = f" = '{inp['value']}'" if inp['value'] and inp['type'] == 'hidden' else ""
                    type_display = f"({inp['type']})" if inp['type'] != 'text' else ""
                    print(f"  • {inp['name']} {type_display}{value_display}")

        # Comments section
        if self.comments:
            print(f"\n{Colors.HEADER}[COMMENTS] {len(self.comments)} found{Colors.END}")
            print("-" * 30)
            # Show comments (all if full_output, sample otherwise)
            comments_to_show = self.comments if self.full_output else self.comments[:5]
            for comment in comments_to_show:
                # Truncate long comments unless full output
                if self.full_output:
                    display = comment
                else:
                    display = comment[:100] + "..." if len(comment) > 100 else comment
                display = display.replace('\n', ' ')
                print(f"  • {display}")
            if not self.full_output and len(self.comments) > 5:
                print(f"  ... and {len(self.comments) - 5} more (use --full to see all)")

        # Endpoints section
        if self.endpoints:
            print(f"\n{Colors.HEADER}[ENDPOINTS] {len(self.endpoints)} unique{Colors.END}")
            print("-" * 30)
            # Group endpoints by type
            api_endpoints = [e for e in self.endpoints if '/api/' in e or '/ajax/' in e]
            admin_endpoints = [e for e in self.endpoints if re.search(r'(admin|manage|control)', e, re.I)]
            upload_endpoints = [e for e in self.endpoints if 'upload' in e.lower()]

            if api_endpoints:
                print(f"\n  {Colors.YELLOW}API Endpoints:{Colors.END}")
                endpoints_to_show = api_endpoints if self.full_output else api_endpoints[:10]
                for endpoint in endpoints_to_show:
                    print(f"  • {endpoint}")
                if not self.full_output and len(api_endpoints) > 10:
                    print(f"  ... and {len(api_endpoints) - 10} more (use --full to see all)")

            if admin_endpoints:
                print(f"\n  {Colors.RED}Admin/Management:{Colors.END}")
                endpoints_to_show = admin_endpoints if self.full_output else admin_endpoints[:10]
                for endpoint in endpoints_to_show:
                    print(f"  • {endpoint}")
                if not self.full_output and len(admin_endpoints) > 10:
                    print(f"  ... and {len(admin_endpoints) - 10} more (use --full to see all)")

            if upload_endpoints:
                print(f"\n  {Colors.RED}Upload Endpoints:{Colors.END}")
                endpoints_to_show = upload_endpoints if self.full_output else upload_endpoints[:10]
                for endpoint in endpoints_to_show:
                    print(f"  • {endpoint}")
                if not self.full_output and len(upload_endpoints) > 10:
                    print(f"  ... and {len(upload_endpoints) - 10} more (use --full to see all)")

            # Show sample of other endpoints
            other_endpoints = [e for e in self.endpoints if e not in api_endpoints + admin_endpoints + upload_endpoints]
            if other_endpoints:
                print(f"\n  Other endpoints:")
                endpoints_to_show = other_endpoints if self.full_output else other_endpoints[:10]
                for endpoint in endpoints_to_show:
                    print(f"  • {endpoint}")
                if not self.full_output and len(other_endpoints) > 10:
                    print(f"  ... and {len(other_endpoints) - 10} more (use --full to see all)")

        # Interesting findings section
        if any(self.interesting.values()):
            print(f"\n{Colors.HEADER}[INTERESTING FINDINGS]{Colors.END}")
            print("-" * 30)

            if self.interesting['emails']:
                print(f"\n  {Colors.GREEN}Emails:{Colors.END}")
                for email in set(self.interesting['emails']):
                    print(f"  • {email}")

            if self.interesting['file_uploads']:
                print(f"\n  {Colors.RED}File Uploads:{Colors.END}")
                for upload in self.interesting['file_uploads']:
                    print(f"  • {upload}")

            if self.interesting['hidden_fields']:
                print(f"\n  {Colors.YELLOW}Hidden Fields:{Colors.END}")
                for field in self.interesting['hidden_fields'][:10]:
                    print(f"  • {field}")

            if self.interesting['sensitive_comments']:
                print(f"\n  {Colors.RED}Sensitive Comments:{Colors.END}")
                for comment in self.interesting['sensitive_comments'][:5]:
                    print(f"  • {comment}")

            if self.interesting['ips']:
                print(f"\n  {Colors.BLUE}IP Addresses:{Colors.END}")
                for ip in set(self.interesting['ips']):
                    print(f"  • {ip}")

            if self.interesting['versions']:
                print(f"\n  {Colors.BLUE}Version Numbers:{Colors.END}")
                for version in set(self.interesting['versions']):
                    print(f"  • {version}")

        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.END}")
        print("-" * 30)
        print(f"  Forms: {len(self.forms)}")
        print(f"  Comments: {len(self.comments)}")
        print(f"  Unique endpoints: {len(self.endpoints)}")
        print(f"  Interesting findings: {sum(len(v) for v in self.interesting.values())}")

    def enumerate(self):
        """Run all enumeration functions"""
        self.extract_forms()
        self.extract_comments()
        self.extract_endpoints()
        self.find_interesting()

class RecursiveCrawler:
    """Handles recursive crawling and result aggregation"""
    def __init__(self, start_url, headers=None, max_depth=3, delay=0.5, full_output=False):
        self.start_url = start_url
        self.headers = headers or {}
        self.max_depth = max_depth
        self.delay = delay
        self.full_output = full_output
        self.visited = set()
        self.queue = Queue()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False

        # Aggregated results with source tracking
        self.all_forms = []
        self.all_comments = defaultdict(list)  # Track by source page
        self.all_endpoints = defaultdict(set)  # Track by source page
        self.all_interesting = defaultdict(lambda: defaultdict(set))  # Category -> Source -> Items
        self.pages_analyzed = 0
        self.page_titles = {}  # Store page titles

    def crawl(self):
        """Start recursive crawling"""
        print(f"{Colors.BOLD}Starting recursive crawl (max depth: {self.max_depth}){Colors.END}")
        print("-" * 50)

        # Add start URL to queue with depth 0
        self.queue.put((self.start_url, 0))

        while not self.queue.empty():
            url, depth = self.queue.get()

            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)

            # Status update
            print(f"{Colors.GREEN}[{len(self.visited)}]{Colors.END} Crawling: {url[:80]}... (depth: {depth})")

            try:
                # Fetch page
                response = self.session.get(url, timeout=10)
                response.raise_for_status()

                # Skip non-HTML content
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue

                # Enumerate page
                enumerator = HTMLEnumerator(response.text, url)
                enumerator.enumerate()

                # Aggregate results
                self.aggregate_results(enumerator, url)

                # Add new links to queue (if not at max depth)
                if depth < self.max_depth:
                    for link in enumerator.internal_links:
                        if link not in self.visited:
                            self.queue.put((link, depth + 1))

                self.pages_analyzed += 1

                # Rate limiting
                if self.delay > 0:
                    time.sleep(self.delay)

            except requests.RequestException as e:
                print(f"{Colors.YELLOW}  Failed to fetch: {str(e)[:50]}{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}  Error processing: {str(e)[:50]}{Colors.END}")

        print(f"\n{Colors.BOLD}Crawl complete: {self.pages_analyzed} pages analyzed{Colors.END}\n")

    def aggregate_results(self, enumerator, source_url):
        """Aggregate results from each page"""
        # Extract page title
        title_tag = enumerator.soup.find('title')
        page_title = title_tag.get_text().strip() if title_tag else "Untitled"
        self.page_titles[source_url] = page_title

        # Add source URL to forms for tracking
        for form in enumerator.forms:
            form['source_url'] = source_url
            form['page_title'] = page_title
            self.all_forms.append(form)

        # Aggregate comments with source tracking
        for comment in enumerator.comments:
            self.all_comments[source_url].append(comment)

        # Aggregate endpoints with source tracking
        for endpoint in enumerator.endpoints:
            self.all_endpoints[source_url].add(endpoint)

        # Aggregate interesting findings with source tracking
        for category, items in enumerator.interesting.items():
            for item in items:
                self.all_interesting[category][source_url].add(item)

    def generate_report(self):
        """Generate detailed aggregated report with source tracking"""
        print(f"\n{Colors.BOLD}RECURSIVE ENUMERATION REPORT{Colors.END}")
        print("=" * 50)
        print(f"Start URL: {self.start_url}")
        print(f"Pages crawled: {len(self.visited)}")
        print(f"Pages analyzed: {self.pages_analyzed}\n")

        # List all pages found
        print(f"{Colors.HEADER}[PAGES DISCOVERED]{Colors.END}")
        print("-" * 30)
        for idx, (url, title) in enumerate(sorted(self.page_titles.items()), 1):
            # Shorten URL for display
            short_url = url.replace(self.start_url.rstrip('/'), '')
            if not short_url:
                short_url = '/'
            print(f"  {idx}. {Colors.GREEN}{short_url}{Colors.END} - {title}")

        # Forms section with source tracking
        if self.all_forms:
            print(f"\n{Colors.HEADER}[FORMS] {len(self.all_forms)} total found{Colors.END}")
            print("-" * 30)

            # Group forms by source page
            forms_by_page = defaultdict(list)
            for form in self.all_forms:
                forms_by_page[form['source_url']].append(form)

            for source_url, forms in sorted(forms_by_page.items()):
                # Show page source
                short_url = source_url.replace(self.start_url.rstrip('/'), '') or '/'
                print(f"\n  {Colors.BLUE}From {short_url}:{Colors.END}")

                for form in forms:
                    # Show form with full details
                    action = form['action'] if form['action'] != '/' else f"(submits to {short_url})"
                    print(f"    {Colors.BOLD}{form['method']} {action}{Colors.END}")

                    # Show inputs
                    inputs_to_show = form['inputs'] if self.full_output else form['inputs'][:5]
                    for inp in inputs_to_show:
                        value_display = f" = '{inp['value']}'" if inp['value'] and inp['type'] == 'hidden' else ""
                        type_display = f"({inp['type']})" if inp['type'] != 'text' else ""
                        print(f"      • {inp['name']} {type_display}{value_display}")
                    if not self.full_output and len(form['inputs']) > 5:
                        print(f"      ... and {len(form['inputs']) - 5} more inputs")

        # Comments section with counts per page
        if self.all_comments:
            total_comments = sum(len(comments) for comments in self.all_comments.values())
            print(f"\n{Colors.HEADER}[COMMENTS] {total_comments} total found{Colors.END}")
            print("-" * 30)

            # Show comment counts by page
            for source_url, comments in sorted(self.all_comments.items()):
                if comments:
                    short_url = source_url.replace(self.start_url.rstrip('/'), '') or '/'
                    unique_comments = list(set(comments))
                    print(f"\n  {Colors.BLUE}{short_url}: {len(comments)} comments ({len(unique_comments)} unique){Colors.END}")

                    # Show comments (all if full_output, sample otherwise)
                    comments_to_show = unique_comments if self.full_output else unique_comments[:3]
                    for comment in comments_to_show:
                        display = comment if self.full_output else (comment[:80] + "..." if len(comment) > 80 else comment)
                        display = display.replace('\n', ' ')
                        print(f"    • {display}")

                    # Show truncation notice if not full output
                    if not self.full_output and len(unique_comments) > 3:
                        print(f"    ... and {len(unique_comments) - 3} more (use --full to see all)")

        # Endpoints section grouped by source
        if self.all_endpoints:
            all_unique_endpoints = set()
            for endpoints in self.all_endpoints.values():
                all_unique_endpoints.update(endpoints)

            print(f"\n{Colors.HEADER}[ENDPOINTS] {len(all_unique_endpoints)} unique across all pages{Colors.END}")
            print("-" * 30)

            # Categorize endpoints
            api_endpoints = defaultdict(set)
            admin_endpoints = defaultdict(set)
            upload_endpoints = defaultdict(set)

            for source_url, endpoints in self.all_endpoints.items():
                short_url = source_url.replace(self.start_url.rstrip('/'), '') or '/'
                for endpoint in endpoints:
                    if '/api/' in endpoint or '/ajax/' in endpoint:
                        api_endpoints[short_url].add(endpoint)
                    elif re.search(r'(admin|manage|control)', endpoint, re.I):
                        admin_endpoints[short_url].add(endpoint)
                    elif 'upload' in endpoint.lower():
                        upload_endpoints[short_url].add(endpoint)

            # Display categorized endpoints
            if api_endpoints:
                print(f"\n  {Colors.YELLOW}API Endpoints:{Colors.END}")
                for page, endpoints in sorted(api_endpoints.items()):
                    print(f"    From {page}:")
                    endpoints_list = sorted(endpoints)
                    endpoints_to_show = endpoints_list if self.full_output else endpoints_list[:5]
                    for endpoint in endpoints_to_show:
                        print(f"      • {endpoint}")
                    if not self.full_output and len(endpoints_list) > 5:
                        print(f"      ... and {len(endpoints_list) - 5} more (use --full to see all)")

            if admin_endpoints:
                print(f"\n  {Colors.RED}Admin/Management:{Colors.END}")
                for page, endpoints in sorted(admin_endpoints.items()):
                    print(f"    From {page}:")
                    endpoints_list = sorted(endpoints)
                    endpoints_to_show = endpoints_list if self.full_output else endpoints_list[:5]
                    for endpoint in endpoints_to_show:
                        print(f"      • {endpoint}")
                    if not self.full_output and len(endpoints_list) > 5:
                        print(f"      ... and {len(endpoints_list) - 5} more (use --full to see all)")

            if upload_endpoints:
                print(f"\n  {Colors.RED}File Upload Endpoints:{Colors.END}")
                for page, endpoints in sorted(upload_endpoints.items()):
                    print(f"    From {page}:")
                    for endpoint in sorted(endpoints):
                        print(f"      • {endpoint}")

        # Interesting findings with source tracking
        if any(self.all_interesting.values()):
            print(f"\n{Colors.HEADER}[INTERESTING FINDINGS]{Colors.END}")
            print("-" * 30)

            # Emails
            if self.all_interesting['emails']:
                all_emails = set()
                for page_emails in self.all_interesting['emails'].values():
                    all_emails.update(page_emails)

                print(f"\n  {Colors.GREEN}Emails ({len(all_emails)} unique):{Colors.END}")
                for email in sorted(all_emails):
                    # Find which pages contain this email
                    pages = [url.replace(self.start_url.rstrip('/'), '') or '/'
                            for url, emails in self.all_interesting['emails'].items()
                            if email in emails]
                    print(f"    • {email} (found on: {', '.join(pages[:3])})")

            # File uploads
            if self.all_interesting['file_uploads']:
                print(f"\n  {Colors.RED}File Upload Forms:{Colors.END}")
                for source_url, uploads in self.all_interesting['file_uploads'].items():
                    short_url = source_url.replace(self.start_url.rstrip('/'), '') or '/'
                    for upload in uploads:
                        print(f"    • {upload} (on {short_url})")

            # IPs
            if self.all_interesting['ips']:
                all_ips = set()
                for page_ips in self.all_interesting['ips'].values():
                    all_ips.update(page_ips)

                print(f"\n  {Colors.BLUE}IP Addresses ({len(all_ips)} unique):{Colors.END}")
                for ip in sorted(all_ips):
                    print(f"    • {ip}")

            # Sensitive comments
            if self.all_interesting['sensitive_comments']:
                print(f"\n  {Colors.RED}Sensitive Comments:{Colors.END}")
                for source_url, comments in list(self.all_interesting['sensitive_comments'].items())[:5]:
                    short_url = source_url.replace(self.start_url.rstrip('/'), '') or '/'
                    for comment in list(comments)[:2]:
                        display = comment[:80] + "..." if len(comment) > 80 else comment
                        print(f"    • {display} (on {short_url})")

        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.END}")
        print("-" * 30)
        print(f"  Pages crawled: {len(self.visited)}")
        print(f"  Pages successful: {self.pages_analyzed}")
        print(f"  Total forms: {len(self.all_forms)}")
        total_comments = sum(len(comments) for comments in self.all_comments.values())
        print(f"  Total comments: {total_comments}")
        all_unique_endpoints = set()
        for endpoints in self.all_endpoints.values():
            all_unique_endpoints.update(endpoints)
        print(f"  Unique endpoints: {len(all_unique_endpoints)}")

        total_findings = 0
        for category_data in self.all_interesting.values():
            for page_data in category_data.values():
                total_findings += len(page_data)
        print(f"  Interesting findings: {total_findings}")

def main():
    parser = argparse.ArgumentParser(
        description='HTML Enumeration Tool - Find forms, comments, and endpoints',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 html_enum.py http://target.com
  python3 html_enum.py -f saved_page.html
  python3 html_enum.py http://target.com -c "session=abc123"
  python3 html_enum.py http://target.com -r -d 2 --delay 1
  python3 html_enum.py http://target.com -r --full  # Show all comments/endpoints
        """
    )

    parser.add_argument('target', help='URL or file path to enumerate')
    parser.add_argument('-f', '--file', action='store_true',
                       help='Target is a local HTML file')
    parser.add_argument('-c', '--cookie', help='Cookie string for authentication')
    parser.add_argument('-H', '--header', action='append',
                       help='Additional headers (can be used multiple times)')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively crawl and enumerate all linked pages')
    parser.add_argument('-d', '--depth', type=int, default=3,
                       help='Maximum crawl depth for recursive mode (default: 3)')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests in seconds for recursive mode (default: 0.5)')
    parser.add_argument('--full', action='store_true',
                       help='Show full untruncated output (all comments, endpoints, etc.)')

    args = parser.parse_args()

    try:
        # Build headers dict
        headers = {}
        if args.cookie:
            headers['Cookie'] = args.cookie
        if args.header:
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

        if args.file:
            # Cannot use recursive mode with file input
            if args.recursive:
                print(f"{Colors.RED}Error: Recursive mode not supported with file input{Colors.END}")
                sys.exit(1)

            # Read from file
            with open(args.target, 'r', encoding='utf-8') as f:
                content = f.read()
            base_url = None

            # Run single page enumeration
            enumerator = HTMLEnumerator(content, base_url, full_output=args.full)
            enumerator.enumerate()
            enumerator.generate_report()

        elif args.recursive:
            # Recursive crawling mode
            crawler = RecursiveCrawler(
                args.target,
                headers=headers,
                max_depth=args.depth,
                delay=args.delay,
                full_output=args.full
            )
            crawler.crawl()
            crawler.generate_report()

        else:
            # Single URL enumeration
            print(f"Fetching: {args.target}")
            response = requests.get(args.target, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            content = response.text
            base_url = args.target

            # Run enumeration
            enumerator = HTMLEnumerator(content, base_url, full_output=args.full)
            enumerator.enumerate()
            enumerator.generate_report()

    except FileNotFoundError:
        print(f"{Colors.RED}Error: File not found: {args.target}{Colors.END}")
        sys.exit(1)
    except requests.RequestException as e:
        print(f"{Colors.RED}Error fetching URL: {e}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    main()