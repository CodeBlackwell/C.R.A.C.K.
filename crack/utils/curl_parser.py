#!/usr/bin/env python3
"""
Curl Command Parser
Parses curl commands (like those exported from Burp Suite) into components
"""

import shlex
import re
from urllib.parse import parse_qs, urlparse, unquote

class CurlParser:
    def __init__(self, curl_command):
        """
        Parse a curl command string

        Args:
            curl_command: Full curl command string
        """
        self.curl_command = curl_command.strip()
        self.method = 'GET'
        self.url = None
        self.headers = {}
        self.data = None
        self.params = {}
        self.fixes_applied = []  # Track what we fixed

    def fix_burp_curl(self, curl_cmd):
        """
        Fix common malformations in Burp Suite curl exports
        Also handles echo-mangled formats

        Args:
            curl_cmd: The curl command string

        Returns:
            str: Fixed curl command
        """
        original = curl_cmd

        # Pattern -2: Fix Burp Suite backticks → single quotes
        # Burp exports use backticks instead of quotes: curl -X `POST` → curl -X 'POST'
        if '`' in curl_cmd:
            backtick_count = curl_cmd.count('`')
            curl_cmd = curl_cmd.replace('`', "'")
            self.fixes_applied.append(f"Replaced {backtick_count} backtick(s) with single quotes")

        # Pattern -1: Fix line continuations (multiline curl with backslashes)
        # "curl -X 'POST' \\n    -H 'Host: ...' \\n" → "curl -X 'POST' -H 'Host: ...'"
        if '\\\n' in curl_cmd or '\\ \n' in curl_cmd:
            # Remove backslash-newline and any leading whitespace on next line
            # Use raw string with explicit newline: r'\\' matches one \, then \s* then actual \n
            curl_cmd = re.sub(r'\\\s*' + '\n' + r'\s*', ' ', curl_cmd)
            self.fixes_applied.append("Removed line continuation characters")

        # Pattern 0: Detect and fix echo-mangled backslashes
        # When using echo "curl ...\' ...", backslashes might be added
        if r"\'" in curl_cmd or r'\"' in curl_cmd:
            curl_cmd = curl_cmd.replace(r"\'", "'")
            curl_cmd = curl_cmd.replace(r'\"', '"')
            self.fixes_applied.append("Removed echo-added backslash escapes")

        # Pattern 1: Fix quotes after flags (e.g., "-X POST'" → "-X POST")
        # Match: flag value' where value is not quoted
        pattern1 = r"(-[A-Za-z])\s+([A-Z]+)'"
        if re.search(pattern1, curl_cmd):
            curl_cmd = re.sub(pattern1, r"\1 \2", curl_cmd)
            self.fixes_applied.append("Removed misplaced quotes after flag values")

        # Pattern 2: Fix header format (e.g., "-H Host: value'" → "-H 'Host: value'")
        # Match: -H followed by unquoted header with trailing quote
        pattern2 = r"-H\s+([A-Za-z\-]+):\s*([^'\"]+?)'"
        matches = re.findall(pattern2, curl_cmd)
        if matches:
            for header_name, header_value in matches:
                # Clean up the value (remove trailing whitespace/quotes)
                header_value = header_value.strip()
                old_pattern = f"-H {header_name}: {header_value}'"
                new_pattern = f"-H '{header_name}: {header_value}'"
                curl_cmd = curl_cmd.replace(old_pattern, new_pattern)
            self.fixes_applied.append(f"Fixed {len(matches)} malformed header(s)")

        # Pattern 3: Fix --data-binary without quotes
        # Match: --data-binary VALUE' (should be --data-binary 'VALUE')
        pattern3 = r"--data-binary\s+([^'\"][^\s]+)"
        if re.search(pattern3, curl_cmd):
            def quote_data(match):
                data = match.group(1)
                # Remove trailing quote if present
                data = data.rstrip("'")
                return f"--data-binary '{data}'"
            curl_cmd = re.sub(pattern3, quote_data, curl_cmd)
            self.fixes_applied.append("Fixed unquoted --data-binary value")

        # Pattern 4: Fix URL with leading quote (e.g., "'http://..." at end)
        # Match: URL at the end that might have quotes in wrong places
        # Issue 2: Make pattern more specific - only match standalone quoted URL, not after valid closing quote
        # OLD: r"'\s*(https?://[^\s'\"]+)'?\s*$" was too greedy
        # NEW: Only match if URL has misplaced quotes (not preceded by a complete argument)
        pattern4 = r"(?<!\w)'\s*(https?://[^\s'\"]+)(?<!')\s*$"
        if re.search(pattern4, curl_cmd):
            # Only apply fix if we don't have a properly closed quote before the URL
            # Check if there's a complete 'arg' pattern before the URL
            if not re.search(r"'[^']+'\s+https?://", curl_cmd):
                curl_cmd = re.sub(pattern4, r" '\1'", curl_cmd)
                self.fixes_applied.append("Fixed URL quoting")

        # Pattern 5: Fix standalone quotes between arguments
        # Remove quotes that are not part of any argument
        pattern5 = r"\s+'\s+-"
        if re.search(pattern5, curl_cmd):
            curl_cmd = re.sub(pattern5, r" -", curl_cmd)
            self.fixes_applied.append("Removed standalone quote marks")

        # Pattern 6: Fix unmatched quotes at end of command
        # Count quotes and balance them
        single_quote_count = curl_cmd.count("'")
        if single_quote_count % 2 != 0:
            # Odd number of quotes - try to fix by removing trailing orphans
            if curl_cmd.rstrip().endswith("'"):
                # Check if this is a real closing quote or orphan
                # Real pattern: 'value' or "value'
                # Orphan pattern: something'
                # Look back to see if there's a matching opening quote nearby
                temp = curl_cmd.rstrip()
                # Remove the last quote if it looks like an orphan
                if not re.search(r"['\"][\w\-]+\s*'$", temp):
                    curl_cmd = temp[:-1] + " "
                    self.fixes_applied.append("Removed orphaned trailing quote")

        return curl_cmd

    def manual_parse_curl(self, curl_cmd):
        """
        Fallback parser when shlex fails
        More forgiving of quote issues - extracts key components directly

        Args:
            curl_cmd: The curl command string

        Returns:
            list: Tokens extracted manually
        """
        self.fixes_applied.append("Used fallback parser for severely malformed command")

        tokens = ['curl']

        # Extract method
        method_match = re.search(r'-X\s+(\w+)', curl_cmd)
        if method_match:
            tokens.extend(['-X', method_match.group(1)])

        # Extract headers - be very forgiving
        # Match: -H followed by anything up to next -H or --data or http
        header_pattern = r"-H\s+['\"]?([^'\"]*?:\s*[^'\"]*?)['\"]?\s+(?=-H|--data|http)"
        for match in re.finditer(header_pattern, curl_cmd):
            header = match.group(1).strip()
            tokens.extend(['-H', header])

        # Extract data - match --data-binary or --data
        # Use separate quote patterns to avoid escaping issues
        data_pattern = r"--data(?:-binary|-raw)?\s+(.+?)(?=\s+http|\s*$)"
        data_match = re.search(data_pattern, curl_cmd)
        if data_match:
            data = data_match.group(1).strip()
            # Remove surrounding quotes if present
            if (data.startswith("'") and data.endswith("'")) or \
               (data.startswith('"') and data.endswith('"')):
                data = data[1:-1]
            tokens.extend(['--data-binary', data])

        # Extract URL - match http/https
        url_match = re.search(r'(https?://[^\s\'\"]+)', curl_cmd)
        if url_match:
            tokens.append(url_match.group(1))

        return tokens

    def parse(self):
        """
        Parse the curl command and extract all components

        Returns:
            dict: Parsed components (method, url, headers, data, params)
        """
        # Apply Burp fixes FIRST (handles line continuations, backticks, etc.)
        # This needs to happen before join() so we can detect \\\n properly
        fixed = self.fix_burp_curl(self.curl_command)

        # Handle remaining multiline commands (join with space)
        cleaned = ' '.join(line.strip() for line in fixed.split('\n'))

        try:
            tokens = shlex.split(cleaned)
        except ValueError as e:
            # shlex failed - try manual parsing as fallback
            try:
                tokens = self.manual_parse_curl(cleaned)
            except Exception as fallback_error:
                # Both parsers failed
                raise ValueError(
                    f"Failed to parse curl command with both parsers.\n"
                    f"Shlex error: {e}\n"
                    f"Fallback error: {fallback_error}\n"
                    f"Tip: Save curl to file and pipe instead of using echo"
                )

        # Issue 1: Check if tokens is empty BEFORE accessing tokens[0]
        if not tokens:
            # Empty command - return default values without raising exception
            return {
                'method': self.method,
                'url': self.url,
                'headers': self.headers,
                'data': self.data,
                'params': self.params
            }

        if tokens[0] != 'curl':
            raise ValueError("Not a valid curl command (must start with 'curl')")

        # Parse tokens
        i = 1  # Skip 'curl'
        while i < len(tokens):
            token = tokens[i]

            # Issue 2: Add boundary checks to prevent index errors
            if token in ['-X', '--request']:
                if i + 1 < len(tokens):
                    self.method = tokens[i + 1].upper()
                    i += 2
                else:
                    i += 1
            elif token in ['-H', '--header']:
                if i + 1 < len(tokens):
                    header = tokens[i + 1]
                    if ':' in header:
                        key, val = header.split(':', 1)
                        self.headers[key.strip()] = val.strip()
                    i += 2
                else:
                    i += 1
            elif token in ['-d', '--data', '--data-binary', '--data-urlencode', '--data-raw']:
                if i + 1 < len(tokens):
                    self.data = tokens[i + 1]
                    if self.method == 'GET':
                        self.method = 'POST'  # Auto-detect POST when data is present
                    i += 2
                else:
                    i += 1
            elif token in ['-u', '--user']:
                if i + 1 < len(tokens):
                    # Basic auth
                    self.headers['Authorization'] = f"Basic {tokens[i + 1]}"
                    i += 2
                else:
                    i += 1
            elif token in ['-A', '--user-agent']:
                if i + 1 < len(tokens):
                    self.headers['User-Agent'] = tokens[i + 1]
                    i += 2
                else:
                    i += 1
            elif token in ['-e', '--referer']:
                if i + 1 < len(tokens):
                    self.headers['Referer'] = tokens[i + 1]
                    i += 2
                else:
                    i += 1
            elif token in ['-b', '--cookie']:
                if i + 1 < len(tokens):
                    self.headers['Cookie'] = tokens[i + 1]
                    i += 2
                else:
                    i += 1
            elif not token.startswith('-'):
                # This should be the URL
                self.url = token
                i += 1
            else:
                # Skip unknown flags (might be single flags like -i, -s, -k)
                i += 1

        # Fallback URL extraction if not found in tokens
        if not self.url:
            # Find the LAST http/https URL (not in headers)
            # Headers are like "-H Something: http://..." so skip those
            # The target URL is typically at the end: "curl [opts] URL"
            url_matches = re.finditer(r'(?<!-H\s)(?<!:\s)(https?://[^\s\'\"]+)', cleaned)
            matches_list = list(url_matches)
            if matches_list:
                # Take the last match (the target URL)
                self.url = matches_list[-1].group(1)
                self.fixes_applied.append("Extracted URL via regex fallback")

        # Parse parameters from POST data or URL query string
        self._extract_params()

        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'data': self.data,
            'params': self.params
        }

    def _extract_params(self):
        """Extract parameters from POST data or URL query string"""
        if self.data:
            # Parse POST data
            try:
                # Issue 3: Keep parse_qs list format (don't convert to strings)
                self.params = parse_qs(self.data, keep_blank_values=True)
            except Exception:
                # If parsing fails, data might be JSON or other format
                pass
        elif self.url:
            # Parse URL query string
            parsed_url = urlparse(self.url)
            if parsed_url.query:
                # Issue 3: Keep parse_qs list format (don't convert to strings)
                self.params = parse_qs(parsed_url.query, keep_blank_values=True)

    def get_testable_params(self):
        """
        Get list of parameters that are likely testable (exclude tokens, ViewState, etc.)

        Returns:
            list: Tuples of (param_name, priority) where priority is 'high', 'medium', 'low'
        """
        if not self.params:
            return []

        testable = []

        # Non-testable patterns (case-insensitive)
        skip_patterns = [
            r'^__VIEWSTATE',
            r'^__EVENTVALIDATION',
            r'^__VIEWSTATEGENERATOR',
            r'^csrf',
            r'^token$',
            r'^_token',
            r'^authenticity_token',
            r'^submit$',
            r'^button$',
        ]

        # High priority patterns (user input fields)
        high_priority_patterns = [
            r'user', r'name', r'login', r'email', r'pass', r'pwd',
            r'search', r'query', r'q$', r'id$', r'pid', r'uid',
            r'filter', r'keyword', r'term'
        ]

        # Medium priority patterns
        medium_priority_patterns = [
            r'page', r'sort', r'order', r'category', r'cat',
            r'type', r'status', r'action'
        ]

        for param_name in self.params.keys():
            # Skip non-testable params
            if any(re.search(pattern, param_name, re.I) for pattern in skip_patterns):
                continue

            # Determine priority
            priority = 'low'
            if any(re.search(pattern, param_name, re.I) for pattern in high_priority_patterns):
                priority = 'high'
            elif any(re.search(pattern, param_name, re.I) for pattern in medium_priority_patterns):
                priority = 'medium'

            testable.append((param_name, priority))

        # Sort by priority (high first)
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        testable.sort(key=lambda x: priority_order[x[1]])

        return testable

def parse_curl_command(curl_command):
    """
    Convenience function to parse a curl command

    Args:
        curl_command: Full curl command string

    Returns:
        dict: Parsed components
    """
    parser = CurlParser(curl_command)
    return parser.parse()
