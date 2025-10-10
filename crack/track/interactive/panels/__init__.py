"""
TUI Panels - Modular panel components for CRACK Track TUI

Panels are full-screen views that manage their own state and rendering.
Each panel follows the pattern from PANEL_DEVELOPER_GUIDE.md:
- Data Source (from profile, recommendations, etc.)
- Render Method (returns Rich Panel)
- Input Processing (optional, handled by session)
"""

from .dashboard_panel import DashboardPanel
from .task_workspace_panel import TaskWorkspacePanel
from .findings_panel import FindingsPanel
from .task_list_panel import TaskListPanel

__all__ = ['DashboardPanel', 'TaskWorkspacePanel', 'FindingsPanel', 'TaskListPanel']
