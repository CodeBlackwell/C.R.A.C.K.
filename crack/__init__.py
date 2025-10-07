"""
C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit
A professional penetration testing toolkit for OSCP preparation
"""

__version__ = "1.0.0"
__author__ = "OSCP Student"
__description__ = "Comprehensive Recon & Attack Creation Kit - Professional pentesting tools"

# Import main modules for easier access
from . import network
from . import web
from . import sqli
from . import exploit
from . import utils
from . import reference
from . import track

__all__ = ["network", "web", "sqli", "exploit", "utils", "reference", "track"]