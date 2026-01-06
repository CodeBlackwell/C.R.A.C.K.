"""
Pytest configuration for BloodTrail tests.

Adds the bloodtrail package to sys.path to allow relative imports.
"""

import sys
from pathlib import Path

# Add bloodtrail parent to path so 'from bloodtrail.core...' works
bloodtrail_path = Path(__file__).parent.parent
if str(bloodtrail_path) not in sys.path:
    sys.path.insert(0, str(bloodtrail_path.parent))

# Also add as 'bloodtrail' for shorter imports
if str(bloodtrail_path) not in sys.path:
    sys.path.insert(0, str(bloodtrail_path))
