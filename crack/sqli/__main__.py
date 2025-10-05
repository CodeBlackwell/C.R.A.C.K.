#!/usr/bin/env python3
"""
Allow the sqli module to be run as a script with python -m crack.enumeration.sqli
"""

from .sqli_scanner import main

if __name__ == '__main__':
    main()