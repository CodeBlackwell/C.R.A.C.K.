"""
C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit
A professional penetration testing toolkit for OSCP preparation
"""

__version__ = "1.0.0"
__author__ = "OSCP Student"
__description__ = "Comprehensive Recon & Attack Creation Kit - Professional pentesting tools"

# Import main modules for easier access
from . import enumeration
from . import utils

__all__ = ["enumeration", "utils"]