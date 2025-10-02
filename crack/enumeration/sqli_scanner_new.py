#!/usr/bin/env python3
"""
SQL Injection Scanner - Wrapper for modularized version
This script maintains backward compatibility with the old location
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqli.sqli_scanner import main

if __name__ == '__main__':
    main()