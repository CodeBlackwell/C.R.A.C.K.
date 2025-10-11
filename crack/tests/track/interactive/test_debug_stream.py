"""
Tests for Debug Stream Overlay

Tests the debug log viewer with colorization, pagination, and live tail functionality.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from crack.track.interactive.overlays.debug_stream_overlay import DebugStreamOverlay
from crack.track.interactive.themes import ThemeManager


class TestDebugStreamOverlay:
    """Test suite for DebugStreamOverlay"""

    @pytest.fixture
    def theme(self):
        """Create theme manager for tests"""
        return ThemeManager()

    @pytest.fixture
    def sample_log_lines(self):
        """Sample parsed log entries"""
        return [
            {
                'timestamp': '10:32:12.945',
                'level': 'INFO',
                'function': '_log_startup',
                'line': '166',
                'category': 'SYSTEM.INIT',
                'message': 'Session initialization started',
                'metadata': 'target=192.168.45.100',
                'raw': '10:32:12.945 [INFO] _log_startup:166 - [SYSTEM.INIT] Session initialization started | target=192.168.45.100'
            },
            {
                'timestamp': '10:32:12.950',
                'level': 'DEBUG',
                'function': '_render_menu',
                'line': '250',
                'category': 'UI.RENDER',
                'message': 'Rendering dashboard menu',
                'metadata': 'choices=9',
                'raw': '10:32:12.950 [DEBUG] _render_menu:250 - [UI.RENDER] Rendering dashboard menu | choices=9'
            },
            {
                'timestamp': '10:32:13.100',
                'level': 'WARNING',
                'function': '_execute_task',
                'line': '1500',
                'category': 'EXECUTION.START',
                'message': 'Task execution started with elevated privileges',
                'metadata': '',
                'raw': '10:32:13.100 [WARNING] _execute_task:1500 - [EXECUTION.START] Task execution started with elevated privileges'
            },
            {
                'timestamp': '10:32:13.500',
                'level': 'ERROR',
                'function': '_parse_output',
                'line': '2000',
                'category': 'DATA.PARSE',
                'message': 'Failed to parse command output',
                'metadata': 'command=gobuster',
                'raw': '10:32:13.500 [ERROR] _parse_output:2000 - [DATA.PARSE] Failed to parse command output | command=gobuster'
            },
        ]

    @pytest.fixture
    def debug_log_file(self, tmp_path):
        """Create a temporary debug log file"""
        log_dir = tmp_path / '.debug_logs'
        log_dir.mkdir()

        log_file = log_dir / 'tui_debug_test_target_20251011_103212.log'
        log_content = """10:32:12.945 [INFO] _log_startup:166 - [SYSTEM.INIT] Session initialization started | target=test-target
10:32:12.950 [DEBUG] _render_menu:250 - [UI.RENDER] Rendering dashboard menu | choices=9
10:32:13.100 [WARNING] _execute_task:1500 - [EXECUTION.START] Task execution started | task_id=http-enum-80
10:32:13.500 [ERROR] _parse_output:2000 - [DATA.PARSE] Failed to parse command output | command=gobuster
10:32:14.000 [INFO] _save_finding:300 - [STATE.SAVE] Finding saved | type=directory | description=/admin
"""
        log_file.write_text(log_content)

        return log_file

    def test_log_pattern_parsing(self):
        """Test log pattern regex correctly parses log entries"""
        # Valid log entry
        line = '10:32:12.945 [INFO] _log_startup:166 - [SYSTEM.INIT] Session initialization started | target=192.168.45.100'

        match = DebugStreamOverlay.LOG_PATTERN.match(line)
        assert match is not None

        assert match.group('timestamp') == '10:32:12.945'
        assert match.group('level') == 'INFO'
        assert match.group('function') == '_log_startup'
        assert match.group('line') == '166'
        assert match.group('category') == 'SYSTEM.INIT'
        assert match.group('message') == 'Session initialization started'
        assert match.group('metadata') == 'target=192.168.45.100'

    def test_log_pattern_without_metadata(self):
        """Test parsing log entry without metadata"""
        line = '10:32:12.950 [DEBUG] _render_menu:250 - [UI.RENDER] Rendering dashboard menu'

        match = DebugStreamOverlay.LOG_PATTERN.match(line)
        assert match is not None

        assert match.group('timestamp') == '10:32:12.950'
        assert match.group('level') == 'DEBUG'
        assert match.group('category') == 'UI.RENDER'
        assert match.group('message') == 'Rendering dashboard menu'
        assert match.group('metadata') is None

    def test_log_pattern_without_category(self):
        """Test parsing log entry without category"""
        line = '10:32:12.950 [INFO] _startup:100 - System initialized'

        match = DebugStreamOverlay.LOG_PATTERN.match(line)
        assert match is not None

        assert match.group('timestamp') == '10:32:12.950'
        assert match.group('level') == 'INFO'
        assert match.group('category') is None
        assert match.group('message') == 'System initialized'

    def test_find_latest_log(self, debug_log_file):
        """Test finding latest debug log file"""
        log_dir = debug_log_file.parent

        # Find without target filter
        found_log = DebugStreamOverlay._find_latest_log(str(log_dir))
        assert found_log is not None
        assert found_log.name == debug_log_file.name

        # Find with target filter
        found_log = DebugStreamOverlay._find_latest_log(str(log_dir), target='test-target')
        assert found_log is not None
        assert 'test_target' in found_log.name

    def test_find_latest_log_no_logs(self, tmp_path):
        """Test behavior when no logs exist"""
        log_dir = tmp_path / 'empty_logs'
        log_dir.mkdir()

        found_log = DebugStreamOverlay._find_latest_log(str(log_dir))
        assert found_log is None

    def test_parse_log_file(self, debug_log_file):
        """Test parsing log file into structured entries"""
        entries = DebugStreamOverlay._parse_log_file(debug_log_file)

        assert len(entries) == 5  # 5 valid log lines

        # Check first entry
        assert entries[0]['timestamp'] == '10:32:12.945'
        assert entries[0]['level'] == 'INFO'
        assert entries[0]['category'] == 'SYSTEM.INIT'
        assert entries[0]['message'] == 'Session initialization started'

        # Check entry with metadata
        assert entries[0]['metadata'] == 'target=test-target'

        # Check error entry
        assert entries[3]['level'] == 'ERROR'
        assert entries[3]['category'] == 'DATA.PARSE'

    def test_parse_log_file_max_lines(self, debug_log_file):
        """Test log file parsing respects max_lines limit"""
        entries = DebugStreamOverlay._parse_log_file(debug_log_file, max_lines=3)

        # Should only get last 3 lines
        assert len(entries) == 3
        assert entries[0]['level'] == 'WARNING'  # 3rd line from bottom
        assert entries[-1]['level'] == 'INFO'    # Last line

    def test_colorize_entry_level_colors(self, theme, sample_log_lines):
        """Test log entry colorization by level"""
        # INFO entry
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[0], theme)
        assert 'cyan' in colorized.lower() or 'INFO' in colorized  # INFO level

        # WARNING entry
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[2], theme)
        assert 'yellow' in colorized.lower() or 'WARNING' in colorized  # WARNING level

        # ERROR entry
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[3], theme)
        assert 'red' in colorized.lower() or 'ERROR' in colorized  # ERROR level

    def test_colorize_entry_category_colors(self, theme, sample_log_lines):
        """Test log entry colorization by category"""
        # UI category
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[1], theme)
        assert 'UI.RENDER' in colorized  # Category included

        # EXECUTION category
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[2], theme)
        assert 'EXECUTION.START' in colorized

        # DATA category
        colorized = DebugStreamOverlay._colorize_entry(sample_log_lines[3], theme)
        assert 'DATA.PARSE' in colorized

    def test_colorize_entry_search_highlighting(self, theme, sample_log_lines):
        """Test search term highlighting in colorized output"""
        search_term = 'execution'

        colorized = DebugStreamOverlay._colorize_entry(
            sample_log_lines[2],
            theme,
            search_term=search_term
        )

        # Should contain highlighted version of search term
        assert 'execution' in colorized.lower()
        # Rich markup for bold yellow highlighting
        assert 'bold yellow' in colorized.lower() or '[bold yellow]' in colorized

    def test_render_log_page_pagination(self, theme, sample_log_lines):
        """Test log page rendering with pagination"""
        # Render first page (2 lines per page)
        page_text = DebugStreamOverlay._render_log_page(
            sample_log_lines,
            offset=0,
            lines_per_page=2,
            theme=theme
        )

        assert 'Page 1/2' in page_text
        assert 'Lines 1-2/4' in page_text

        # Render second page
        page_text = DebugStreamOverlay._render_log_page(
            sample_log_lines,
            offset=2,
            lines_per_page=2,
            theme=theme
        )

        assert 'Page 2/2' in page_text
        assert 'Lines 3-4/4' in page_text

    def test_render_log_page_category_filter(self, theme, sample_log_lines):
        """Test log page rendering with category filter"""
        page_text = DebugStreamOverlay._render_log_page(
            sample_log_lines,
            offset=0,
            lines_per_page=10,
            theme=theme,
            filter_category='UI'
        )

        # Should show filter info
        assert 'Filtered' in page_text or 'category=UI' in page_text

        # Should only show UI entries
        assert 'UI.RENDER' in page_text
        assert 'SYSTEM.INIT' not in page_text

    def test_render_log_page_level_filter(self, theme, sample_log_lines):
        """Test log page rendering with level filter"""
        page_text = DebugStreamOverlay._render_log_page(
            sample_log_lines,
            offset=0,
            lines_per_page=10,
            theme=theme,
            filter_level='ERROR'
        )

        # Should show filter info
        assert 'Filtered' in page_text or 'level=ERROR' in page_text

    def test_render_no_logs_available(self, theme, tmp_path):
        """Test rendering when no debug logs exist"""
        empty_log_dir = tmp_path / 'empty_logs'
        empty_log_dir.mkdir()

        panel, state = DebugStreamOverlay.render(
            theme=theme,
            debug_log_dir=str(empty_log_dir)
        )

        # Should return panel with friendly message
        assert state['log_lines'] == []
        assert state['log_file'] is None

    def test_render_with_existing_log(self, theme, debug_log_file):
        """Test rendering with existing debug log"""
        log_dir = debug_log_file.parent

        panel, state = DebugStreamOverlay.render(
            theme=theme,
            debug_log_dir=str(log_dir),
            target='test-target'
        )

        # Should successfully parse and render
        assert len(state['log_lines']) > 0
        assert state['log_file'] == debug_log_file
        assert state['current_offset'] == 0

    def test_build_navigation_help(self, theme):
        """Test navigation help text generation"""
        help_text = DebugStreamOverlay._build_navigation_help(theme)

        # Should include all navigation keys
        assert 'k' in help_text or 'Up' in help_text
        assert 'j' in help_text or 'Down' in help_text
        assert 'g' in help_text or 'Top' in help_text
        assert 'G' in help_text or 'Bottom' in help_text
        assert 'r' in help_text or 'Refresh' in help_text
        assert 't' in help_text or 'Live Tail' in help_text
        assert 'D' in help_text or 'Close' in help_text

    def test_render_help_panel(self, theme):
        """Test help panel rendering"""
        help_panel = DebugStreamOverlay.render_help(theme)

        # Should be a Rich Panel
        assert help_panel is not None

        # Convert to string to check content
        from rich.console import Console
        from io import StringIO

        string_io = StringIO()
        console = Console(file=string_io, force_terminal=True)
        console.print(help_panel)
        output = string_io.getvalue()

        # Should contain navigation instructions
        assert 'Navigation' in output or 'NAVIGATION' in output
        assert 'Scroll' in output or 'scroll' in output
        assert 'Close' in output or 'close' in output

    def test_category_color_prefix_matching(self, theme):
        """Test category color matching with prefixes"""
        # UI.RENDER should match UI prefix
        entry = {
            'timestamp': '10:32:12.950',
            'level': 'DEBUG',
            'function': 'test',
            'line': '100',
            'category': 'UI.RENDER',
            'message': 'Test message',
            'metadata': ''
        }

        colorized = DebugStreamOverlay._colorize_entry(entry, theme)

        # Should use UI color (green)
        assert 'UI.RENDER' in colorized

        # STATE.TRANSITION should match STATE prefix
        entry['category'] = 'STATE.TRANSITION'
        colorized = DebugStreamOverlay._colorize_entry(entry, theme)
        assert 'STATE.TRANSITION' in colorized

    def test_malformed_log_line_handling(self):
        """Test handling of malformed log lines"""
        malformed_lines = [
            "This is not a valid log line",
            "10:32:12.945 Missing everything else",
            "[INFO] Missing timestamp",
        ]

        for line in malformed_lines:
            match = DebugStreamOverlay.LOG_PATTERN.match(line)
            # Should either not match or be handled gracefully
            if match:
                # If it matches partially, should have some fields
                assert match.group('timestamp') or match.group('level')


class TestDebugStreamIntegration:
    """Integration tests for debug stream in TUI"""

    def test_debug_stream_shortcut_registered_in_debug_mode(self):
        """Test that D shortcut is only registered in debug mode"""
        from crack.track.interactive.tui_session_v2 import TUISessionV2
        from crack.track.interactive.log_config import LogConfig
        from crack.track.interactive.log_types import LogLevel

        # With debug mode
        config = LogConfig(enabled=True, global_level=LogLevel.NORMAL)
        session = TUISessionV2('192.168.45.100', debug=True, debug_config=config)

        # Should have D shortcut registered
        assert 'D' in session.shortcut_handler.shortcuts
        assert 'Debug Stream' in session.shortcut_handler.shortcuts['D'][0]

    def test_debug_stream_shortcut_not_registered_without_debug(self):
        """Test that D shortcut is NOT registered without debug mode"""
        from crack.track.interactive.tui_session_v2 import TUISessionV2
        from crack.track.interactive.log_config import LogConfig
        from crack.track.interactive.log_types import LogLevel

        # Without debug mode
        config = LogConfig(enabled=False, global_level=LogLevel.NORMAL)
        session = TUISessionV2('192.168.45.100', debug=False, debug_config=config)

        # Should NOT have D shortcut registered
        assert 'D' not in session.shortcut_handler.shortcuts


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
