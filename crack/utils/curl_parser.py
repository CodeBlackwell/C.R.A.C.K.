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

    def parse(self):
        """
        Parse the curl command and extract all components

        Returns:
            dict: Parsed components (method, url, headers, data, params)
        """
        # Handle multiline commands (join with space)
        cleaned = ' '.join(line.strip() for line in self.curl_command.split('\n'))

        try:
            tokens = shlex.split(cleaned)
        except ValueError as e:
            raise ValueError(f"Failed to parse curl command: {e}")

        if not tokens or tokens[0] != 'curl':
            raise ValueError("Not a valid curl command (must start with 'curl')")

        # Parse tokens
        i = 1  # Skip 'curl'
        while i < len(tokens):
            token = tokens[i]

            if token in ['-X', '--request']:
                self.method = tokens[i + 1].upper()
                i += 2
            elif token in ['-H', '--header']:
                header = tokens[i + 1]
                if ':' in header:
                    key, val = header.split(':', 1)
                    self.headers[key.strip()] = val.strip()
                i += 2
            elif token in ['-d', '--data', '--data-binary', '--data-urlencode', '--data-raw']:
                self.data = tokens[i + 1]
                if self.method == 'GET':
                    self.method = 'POST'  # Auto-detect POST when data is present
                i += 2
            elif token in ['-u', '--user']:
                # Basic auth
                self.headers['Authorization'] = f"Basic {tokens[i + 1]}"
                i += 2
            elif token in ['-A', '--user-agent']:
                self.headers['User-Agent'] = tokens[i + 1]
                i += 2
            elif token in ['-e', '--referer']:
                self.headers['Referer'] = tokens[i + 1]
                i += 2
            elif token in ['-b', '--cookie']:
                self.headers['Cookie'] = tokens[i + 1]
                i += 2
            elif not token.startswith('-'):
                # This should be the URL
                self.url = token
                i += 1
            else:
                # Skip unknown flags (might be single flags like -i, -s, -k)
                i += 1

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
                self.params = parse_qs(self.data, keep_blank_values=True)
                # Convert lists to single values for simplicity
                self.params = {k: v[0] if isinstance(v, list) else v
                              for k, v in self.params.items()}
            except Exception:
                # If parsing fails, data might be JSON or other format
                pass
        elif self.url:
            # Parse URL query string
            parsed_url = urlparse(self.url)
            if parsed_url.query:
                self.params = parse_qs(parsed_url.query, keep_blank_values=True)
                self.params = {k: v[0] if isinstance(v, list) else v
                              for k, v in self.params.items()}

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
