#!/usr/bin/env python3
"""
Parameter Extractor - Extract and save form parameters as variables
Useful for CSRF tokens, ViewState, session tokens, etc.
"""

import requests
import argparse
import sys
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from pathlib import Path

try:
    from crack.themes import Colors
except ImportError:
    try:
        from crack.themes import Colors
    except ImportError:
        # Fallback colors
        class Colors:
            BLUE = '\033[94m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            CYAN = '\033[96m'
            BOLD = '\033[1m'
            END = '\033[0m'


class ParamExtractor:
    def __init__(self, url, output_format='bash', save_html=False, headers=None):
        self.url = url
        self.output_format = output_format
        self.save_html = save_html
        self.session = requests.Session()

        # Set default headers
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) Crack Toolkit'

        # Apply custom headers
        if headers:
            self.session.headers.update(headers)

        self.params = {}
        self.forms = []
        self.html_content = None

    def fetch_page(self):
        """Fetch the target page"""
        print(f"{Colors.BLUE}[*] Fetching: {self.url}{Colors.END}")

        try:
            resp = self.session.get(self.url, timeout=10)
            resp.raise_for_status()
            self.html_content = resp.text

            print(f"{Colors.GREEN}[✓] Status: {resp.status_code} | Size: {len(resp.content)} bytes{Colors.END}")

            # Save HTML if requested
            if self.save_html:
                filename = self._get_html_filename()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.html_content)
                print(f"{Colors.CYAN}[*] Saved HTML to: {filename}{Colors.END}")

            return True

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Error fetching page: {e}{Colors.END}")
            return False

    def _get_html_filename(self):
        """Generate filename for saved HTML"""
        parsed = urlparse(self.url)
        hostname = parsed.netloc.replace(':', '_')
        path = parsed.path.strip('/').replace('/', '_') or 'index'
        return f"{hostname}_{path}.html"

    def extract_forms(self):
        """Extract all forms and their parameters"""
        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        print(f"\n{Colors.BOLD}[FORMS DISCOVERED]{Colors.END}")
        print("=" * 60)

        if not forms:
            print(f"{Colors.YELLOW}No forms found on this page{Colors.END}")
            return

        for idx, form in enumerate(forms, 1):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'id': form.get('id', ''),
                'name': form.get('name', ''),
                'inputs': []
            }

            # Resolve relative action URLs
            if form_data['action']:
                form_data['action'] = urljoin(self.url, form_data['action'])

            # Extract all inputs
            inputs = form.find_all(['input', 'textarea', 'select'])

            for inp in inputs:
                input_data = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                    'id': inp.get('id', ''),
                }

                # Handle select dropdowns
                if inp.name == 'select':
                    input_data['type'] = 'select'
                    selected = inp.find('option', selected=True)
                    if selected:
                        input_data['value'] = selected.get('value', '')

                # Handle textareas
                if inp.name == 'textarea':
                    input_data['type'] = 'textarea'
                    input_data['value'] = inp.get_text(strip=True)

                if input_data['name']:  # Only add if it has a name
                    form_data['inputs'].append(input_data)

                    # Store in params dict with form prefix
                    param_key = input_data['name']
                    self.params[param_key] = input_data['value']

            self.forms.append(form_data)

            # Display form info
            print(f"\n{Colors.CYAN}Form #{idx}:{Colors.END}")
            print(f"  Action: {form_data['action'] or '(current page)'}")
            print(f"  Method: {form_data['method']}")
            if form_data['id']:
                print(f"  ID: {form_data['id']}")
            if form_data['name']:
                print(f"  Name: {form_data['name']}")
            print(f"  Parameters: {len(form_data['inputs'])} found")

            # Show parameter details
            if form_data['inputs']:
                print(f"\n  {Colors.BOLD}Parameters:{Colors.END}")
                for inp in form_data['inputs']:
                    name = inp['name']
                    value = inp['value']
                    input_type = inp['type']

                    # Classify parameter importance
                    priority = self._classify_param(name, input_type)
                    color = {
                        'HIGH': Colors.RED,
                        'MEDIUM': Colors.YELLOW,
                        'LOW': Colors.END
                    }.get(priority, Colors.END)

                    # Truncate long values
                    display_value = value
                    if len(value) > 60:
                        display_value = value[:60] + '...'

                    print(f"    {color}• {name}{Colors.END} [{input_type}]")
                    if value:
                        print(f"      Value: {display_value}")

    def _classify_param(self, name, input_type):
        """Classify parameter importance"""
        name_lower = name.lower()

        # High priority: tokens, authentication, ASP.NET state
        high_patterns = [
            r'csrf', r'token', r'_token', r'authenticity',
            r'viewstate', r'eventvalidation', r'viewstategenerator',
            r'session', r'nonce', r'anti.?forgery'
        ]

        # Medium priority: user input fields
        medium_patterns = [
            r'user', r'name', r'email', r'pass', r'login',
            r'search', r'query', r'id$', r'message', r'comment'
        ]

        for pattern in high_patterns:
            if re.search(pattern, name_lower):
                return 'HIGH'

        for pattern in medium_patterns:
            if re.search(pattern, name_lower):
                return 'MEDIUM'

        # Hidden fields are generally important
        if input_type == 'hidden':
            return 'MEDIUM'

        return 'LOW'

    def extract_meta_tokens(self):
        """Extract CSRF tokens from meta tags"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # Common CSRF meta tag patterns
        csrf_patterns = [
            {'name': 'csrf-token'},
            {'name': 'csrf_token'},
            {'name': '_csrf'},
            {'property': 'csrf-token'},
        ]

        for pattern in csrf_patterns:
            meta = soup.find('meta', attrs=pattern)
            if meta and meta.get('content'):
                key = pattern.get('name') or pattern.get('property')
                self.params[f"meta_{key}"] = meta.get('content')
                print(f"{Colors.YELLOW}[*] Found meta token: {key}{Colors.END}")

    def generate_output(self):
        """Generate output in requested format"""
        if not self.params:
            print(f"\n{Colors.YELLOW}[!] No parameters found{Colors.END}")
            return

        print(f"\n{Colors.BOLD}[EXTRACTED PARAMETERS]{Colors.END}")
        print("=" * 60)
        print(f"Total parameters: {len(self.params)}\n")

        if self.output_format == 'bash':
            self._output_bash()
        elif self.output_format == 'json':
            self._output_json()
        elif self.output_format == 'python':
            self._output_python()
        elif self.output_format == 'curl':
            self._output_curl()
        elif self.output_format == 'env':
            self._output_env()

    def _output_bash(self):
        """Output as bash export statements"""
        from urllib.parse import quote

        print(f"{Colors.CYAN}# Bash export format (URL-encoded){Colors.END}")
        print(f"{Colors.CYAN}# Quick load all variables:{Colors.END}")

        # Build one-liner command with URL encoding
        export_vars = []
        for key, value in self.params.items():
            var_name = self._sanitize_var_name(key)
            # URL encode the value and escape for bash
            url_encoded = quote(value, safe='')
            escaped_value = url_encoded.replace("'", "'\\''")
            export_vars.append(f"{var_name}='{escaped_value}'")

        oneliner = ' '.join(export_vars)
        print(f"{Colors.YELLOW}{oneliner}{Colors.END}\n")

        print(f"{Colors.CYAN}# Or export individually:{Colors.END}")
        for key, value in self.params.items():
            # Sanitize variable name for bash
            var_name = self._sanitize_var_name(key)
            # URL encode the value and escape for bash
            url_encoded = quote(value, safe='')
            escaped_value = url_encoded.replace("'", "'\\''")
            print(f"export {var_name}='{escaped_value}'")

        # Dynamic curl usage example
        if self.params:
            curl_parts = []
            for key in self.params.keys():
                var_name = self._sanitize_var_name(key)
                curl_parts.append(f'-d "{key}=${var_name}"')

            curl_example = ' \\\n  '.join(curl_parts)
            print(f"\n{Colors.GREEN}# Usage in curl:{Colors.END}")
            print(f"curl -X POST [URL] \\")
            print(f"  {curl_example}")

    def _output_json(self):
        """Output as JSON"""
        print(json.dumps(self.params, indent=2))

    def _output_python(self):
        """Output as Python dict"""
        print(f"{Colors.CYAN}# Python dictionary format{Colors.END}\n")
        print("params = {")
        for key, value in self.params.items():
            # Escape single quotes and backslashes
            escaped_value = value.replace('\\', '\\\\').replace("'", "\\'")
            print(f"    '{key}': '{escaped_value}',")
        print("}")

    def _output_curl(self):
        """Output as curl data parameter"""
        if not self.forms:
            print(f"{Colors.YELLOW}[!] No forms found - cannot generate curl command{Colors.END}")
            return

        form = self.forms[0]  # Use first form
        data_parts = []

        for inp in form['inputs']:
            name = inp['name']
            value = inp['value']
            # URL encode the parts
            from urllib.parse import quote
            data_parts.append(f"{quote(name)}={quote(value)}")

        data_string = '&'.join(data_parts)

        print(f"{Colors.CYAN}# Curl command with extracted parameters{Colors.END}\n")
        print(f"curl -X {form['method']} '{form['action'] or self.url}' \\")
        print(f"  -H 'Content-Type: application/x-www-form-urlencoded' \\")
        print(f"  --data '{data_string}'")

        # Add demo with modified value - find first user-input text field
        demo_parts = []
        demo_modified = False
        for inp in form['inputs']:
            name = inp['name']
            value = inp['value']

            # Dynamically find first text/email input (not hidden, not button)
            if not demo_modified and inp['type'] in ['text', 'email', 'search'] and not value:
                # This is likely a user input field - modify it for demo
                value = "admin' OR '1'='1"
                demo_modified = True
                modified_field = name

            from urllib.parse import quote
            demo_parts.append(f"{quote(name)}={quote(value)}")

        # Only show demo if we found a field to modify
        if demo_modified:
            demo_string = '&'.join(demo_parts)
            print(f"\n{Colors.GREEN}# Example with modified '{modified_field}' (SQL injection test):{Colors.END}")
            print(f"curl -X {form['method']} '{form['action'] or self.url}' \\")
            print(f"  -H 'Content-Type: application/x-www-form-urlencoded' \\")
            print(f"  --data '{demo_string}'")

    def _output_env(self):
        """Output as .env file format"""
        print(f"{Colors.CYAN}# .env file format{Colors.END}\n")

        for key, value in self.params.items():
            # Sanitize variable name
            var_name = self._sanitize_var_name(key)
            # Quote value if it contains spaces or special chars
            if ' ' in value or '"' in value or "'" in value:
                escaped_value = value.replace('"', '\\"')
                print(f'{var_name}="{escaped_value}"')
            else:
                print(f'{var_name}={value}')

    def _sanitize_var_name(self, name):
        """Sanitize parameter name for use as shell variable"""
        # Replace invalid characters with underscore
        sanitized = re.sub(r'[^A-Za-z0-9_]', '_', name)
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = '_' + sanitized
        # Convert to uppercase for consistency
        return sanitized.upper()

    def save_to_file(self, filename):
        """Save parameters to file (without color codes)"""
        # Temporarily disable colors
        original_colors = {}
        for attr in dir(Colors):
            if not attr.startswith('_'):
                original_colors[attr] = getattr(Colors, attr)
                setattr(Colors, attr, '')

        try:
            # Redirect stdout to file
            import io
            from contextlib import redirect_stdout

            with open(filename, 'w') as f:
                with redirect_stdout(f):
                    self.generate_output()
        finally:
            # Restore colors
            for attr, value in original_colors.items():
                setattr(Colors, attr, value)

        print(f"\n{Colors.GREEN}[✓] Saved to: {filename}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract form parameters and save as variables',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract ViewState and save as bash variables
  crack param-extract http://target.com/login.aspx

  # Source the output to use variables
  source <(crack param-extract http://target.com/login.aspx)
  echo $__VIEWSTATE

  # Save HTML and output JSON
  crack param-extract http://target.com/form.php -f json --save-html

  # Generate curl command with all parameters
  crack param-extract http://target.com/login -f curl

  # Save to file for reuse
  crack param-extract http://target.com/login -o params.env -f env

  # With custom headers
  crack param-extract http://target.com/login -H "Cookie: session=abc123"

Educational Use:
  This tool extracts dynamic tokens (CSRF, ViewState, nonces) for manual testing.
  Always refresh tokens before each request in real penetration tests.

  ASP.NET Applications:
    - __VIEWSTATE: Application state (changes frequently)
    - __EVENTVALIDATION: Request validation token
    - __VIEWSTATEGENERATOR: ViewState encryption key

  These must be extracted fresh for each request.
        """
    )

    parser.add_argument('url', help='Target URL to extract parameters from')
    parser.add_argument('-f', '--format', default='bash',
                       choices=['bash', 'json', 'python', 'curl', 'env'],
                       help='Output format (default: bash)')
    parser.add_argument('--save-html', action='store_true',
                       help='Save fetched HTML to file')
    parser.add_argument('-o', '--output', help='Save output to file')
    parser.add_argument('-H', '--header', action='append',
                       help='Custom header (can be used multiple times)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Parse custom headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()

    # Create extractor
    extractor = ParamExtractor(
        args.url,
        output_format=args.format,
        save_html=args.save_html,
        headers=headers
    )

    # Fetch page
    if not extractor.fetch_page():
        sys.exit(1)

    # Extract forms and meta tokens
    extractor.extract_forms()
    extractor.extract_meta_tokens()

    # Generate output
    if args.output:
        extractor.save_to_file(args.output)
    else:
        extractor.generate_output()


if __name__ == '__main__':
    main()
