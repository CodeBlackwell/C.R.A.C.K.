"""
DEPRECATED: This module has moved to crack.themes.colors

For backward compatibility, this module re-exports from the new location.
Please update imports to: from crack.themes import Colors

Migration:
    # Old (deprecated):
    from crack.utils.colors import Colors

    # New (recommended):
    from crack.themes import Colors
"""

import warnings

warnings.warn(
    "crack.utils.colors is deprecated. Use themes.colors instead.",
    DeprecationWarning,
    stacklevel=2
)

from themes.colors import Colors

__all__ = ['Colors']