"""
TUI Panels - Modular panel components for CRACK Track TUI

Panels are full-screen views that manage their own state and rendering.
Each panel follows the pattern from PANEL_DEVELOPER_GUIDE.md:
- Data Source (from profile, recommendations, etc.)
- Render Method (returns Rich Panel)
- Input Processing (optional, handled by session)
"""

from .dashboard_panel import DashboardPanel

__all__ = ['DashboardPanel']
