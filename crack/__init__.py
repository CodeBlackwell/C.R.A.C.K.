"""
C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit
A professional penetration testing toolkit for OSCP preparation

Package structure:
- crack.core: Foundation layer (config, themes, utils)
- crack.tools.recon: Reconnaissance tools (network, web, sqli)
- crack.tools.post: Post-exploitation tools (bloodtrail, prism, sessions)
- crack.reference: Command reference system
- crack.db: Database management
"""

__version__ = "1.0.0"
__author__ = "OSCP Student"
__description__ = "Comprehensive Recon & Attack Creation Kit - Professional pentesting tools"

# Export structure for easier access
__all__ = [
    "core",
    "tools",
    "reference",
    "db",
]
