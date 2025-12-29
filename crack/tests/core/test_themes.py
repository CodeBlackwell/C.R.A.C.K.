"""
Tests for Theme System - Color theming and application.

Business Value Focus:
- Theme selection must persist across restarts
- Color application must be consistent across modules
- Fallback to default theme when invalid theme is configured
- Theme switching must update colors immediately

TIER 4: INTEGRATION CONTRACTS (Medium) - Theme loading, color mapping
TIER 5: PERFORMANCE CONTRACTS (Lower) - Fast theme switching
"""

import json
import pytest
from pathlib import Path


class TestThemeManagerInitialization:
    """Tests for ThemeManager initialization and config loading"""

    def test_defaults_to_oscp_theme(self, theme_config_path: Path):
        """
        BV: New users get OSCP theme without configuration.

        Scenario:
          Given: No config file exists
          When: ThemeManager is instantiated
          Then: OSCP theme is active
        """
        from core.themes.manager import ThemeManager

        manager = ThemeManager(config_path=str(theme_config_path))

        assert manager.get_theme_name() == 'oscp'

    def test_loads_theme_from_config(self, theme_config_path: Path):
        """
        BV: User's theme preference is restored on startup.

        Scenario:
          Given: Config file with theme.current = 'dark'
          When: ThemeManager loads
          Then: Dark theme is active
        """
        from core.themes.manager import ThemeManager

        theme_config_path.parent.mkdir(parents=True, exist_ok=True)
        theme_config_path.write_text(json.dumps({'theme': {'current': 'dark'}}))

        manager = ThemeManager(config_path=str(theme_config_path))

        assert manager.get_theme_name() == 'dark'

    def test_falls_back_on_invalid_theme(self, theme_config_path: Path):
        """
        BV: Invalid theme in config doesn't crash application.

        Scenario:
          Given: Config with theme.current = 'nonexistent'
          When: ThemeManager loads
          Then: Falls back to OSCP theme
        """
        from core.themes.manager import ThemeManager

        theme_config_path.parent.mkdir(parents=True, exist_ok=True)
        theme_config_path.write_text(json.dumps({'theme': {'current': 'nonexistent_theme'}}))

        manager = ThemeManager(config_path=str(theme_config_path))

        assert manager.get_theme_name() == 'oscp'

    def test_handles_corrupted_config(self, theme_config_path: Path):
        """
        BV: Corrupted config file doesn't prevent theme loading.

        Scenario:
          Given: Config file with invalid JSON
          When: ThemeManager loads
          Then: Default theme is used without exception
        """
        from core.themes.manager import ThemeManager

        theme_config_path.parent.mkdir(parents=True, exist_ok=True)
        theme_config_path.write_text("{ invalid json }")

        # Should not raise exception
        manager = ThemeManager(config_path=str(theme_config_path))

        assert manager.get_theme_name() == 'oscp'


class TestThemeManagerSetTheme:
    """Tests for theme switching"""

    def test_set_theme_changes_active_theme(self, theme_manager):
        """
        BV: Users can switch themes dynamically.

        Scenario:
          Given: ThemeManager with OSCP theme
          When: set_theme('dark') is called
          Then: Dark theme becomes active
        """
        assert theme_manager.get_theme_name() == 'oscp'

        result = theme_manager.set_theme('dark')

        assert result is True
        assert theme_manager.get_theme_name() == 'dark'

    def test_set_theme_persists_to_config(self, theme_manager, theme_config_path: Path):
        """
        BV: Theme preference survives application restart.

        Scenario:
          Given: ThemeManager
          When: set_theme('nord') is called
          Then: Config file is updated
        """
        theme_manager.set_theme('nord')

        saved = json.loads(theme_config_path.read_text())

        assert saved['theme']['current'] == 'nord'

    def test_set_theme_returns_false_for_invalid(self, theme_manager):
        """
        BV: Invalid theme name doesn't corrupt state.

        Scenario:
          Given: ThemeManager with OSCP theme
          When: set_theme('nonexistent') is called
          Then: Returns False, theme unchanged
        """
        original_theme = theme_manager.get_theme_name()

        result = theme_manager.set_theme('nonexistent_theme')

        assert result is False
        assert theme_manager.get_theme_name() == original_theme


class TestThemeManagerColors:
    """Tests for color retrieval"""

    def test_get_color_returns_theme_color(self, theme_manager):
        """
        BV: Modules get consistent colors from theme.

        Scenario:
          Given: ThemeManager with OSCP theme
          When: get_color('primary') is called
          Then: Returns 'cyan' (OSCP primary color)
        """
        color = theme_manager.get_color('primary')

        assert color == 'cyan'

    def test_get_color_returns_fallback_for_unknown(self, theme_manager):
        """
        BV: Unknown color roles return safe fallback.

        Scenario:
          Given: ThemeManager
          When: get_color('nonexistent', fallback='white') is called
          Then: Returns 'white'
        """
        color = theme_manager.get_color('nonexistent_role', fallback='white')

        assert color == 'white'

    def test_get_component_color_returns_correct(self, theme_manager):
        """
        BV: Component-specific colors are accessible.

        Scenario:
          Given: OSCP theme
          When: get_component_color('panel_border') is called
          Then: Returns 'cyan'
        """
        color = theme_manager.get_component_color('panel_border')

        assert color == 'cyan'

    def test_different_themes_have_different_primary(self, theme_config_path: Path):
        """
        BV: Theme switching actually changes colors.

        Scenario:
          Given: ThemeManager
          When: Switching from OSCP to Dracula theme
          Then: Primary color changes
        """
        from core.themes.manager import ThemeManager

        manager = ThemeManager(config_path=str(theme_config_path))

        oscp_primary = manager.get_color('primary')
        manager.set_theme('dracula')
        dracula_primary = manager.get_color('primary')

        assert oscp_primary != dracula_primary
        assert dracula_primary == 'magenta'


class TestThemeManagerConvenienceMethods:
    """Tests for convenience color formatting methods"""

    def test_primary_wraps_text_in_markup(self, theme_manager):
        """
        BV: Rich markup is correctly applied for UI rendering.

        Scenario:
          Given: OSCP theme (primary = cyan)
          When: primary('test') is called
          Then: Returns '[cyan]test[/cyan]'
        """
        result = theme_manager.primary('test')

        assert result == '[cyan]test[/cyan]'

    def test_success_uses_green(self, theme_manager):
        """
        BV: Success messages are consistently green.

        Scenario:
          Given: Any theme
          When: success('OK') is called
          Then: Returns text wrapped in success color
        """
        result = theme_manager.success('OK')

        assert '[green]' in result
        assert 'OK' in result

    def test_warning_uses_yellow(self, theme_manager):
        """
        BV: Warning messages are consistently yellow.

        Scenario:
          Given: Any theme
          When: warning('Alert') is called
          Then: Returns text wrapped in warning color
        """
        result = theme_manager.warning('Alert')

        assert '[yellow]' in result
        assert 'Alert' in result

    def test_danger_uses_red(self, theme_manager):
        """
        BV: Error/danger messages are consistently red.

        Scenario:
          Given: Any theme
          When: danger('Error') is called
          Then: Returns text wrapped in danger color
        """
        result = theme_manager.danger('Error')

        assert '[red]' in result
        assert 'Error' in result


class TestThemePresets:
    """Tests for built-in theme presets"""

    def test_get_theme_names_returns_all_builtin(self):
        """
        BV: Users can see all available themes.

        Scenario:
          Given: Theme presets module
          When: get_theme_names() is called
          Then: Returns list including oscp, dark, light, nord, dracula, mono
        """
        from core.themes.presets import get_theme_names

        names = get_theme_names()

        assert 'oscp' in names
        assert 'dark' in names
        assert 'light' in names
        assert 'nord' in names
        assert 'dracula' in names
        assert 'mono' in names

    def test_get_theme_returns_valid_structure(self):
        """
        BV: Theme structure is consistent for all presets.

        Scenario:
          Given: Theme presets module
          When: get_theme('oscp') is called
          Then: Returns dict with 'colors' and 'components' keys
        """
        from core.themes.presets import get_theme

        theme = get_theme('oscp')

        assert 'colors' in theme
        assert 'components' in theme
        assert 'name' in theme
        assert 'description' in theme

    def test_get_theme_raises_for_unknown(self):
        """
        BV: Clear error when requesting non-existent theme.

        Scenario:
          Given: Theme presets module
          When: get_theme('nonexistent') is called
          Then: Raises KeyError with helpful message
        """
        from core.themes.presets import get_theme

        with pytest.raises(KeyError) as exc_info:
            get_theme('nonexistent_theme')

        assert 'not found' in str(exc_info.value)

    def test_list_themes_returns_metadata(self):
        """
        BV: Theme list includes human-readable descriptions.

        Scenario:
          Given: Theme presets module
          When: list_themes() is called
          Then: Returns list of dicts with name, display_name, description
        """
        from core.themes.presets import list_themes

        themes = list_themes()

        assert len(themes) >= 6  # At least builtin themes

        for theme in themes:
            assert 'name' in theme
            assert 'display_name' in theme
            assert 'description' in theme


class TestColorsClass:
    """Tests for Colors ANSI code class"""

    def test_from_rich_converts_simple_color(self):
        """
        BV: Rich color names convert to ANSI codes.

        Scenario:
          Given: Colors class
          When: from_rich('cyan') is called
          Then: Returns ANSI escape code for cyan
        """
        from core.themes.colors import Colors

        ansi = Colors.from_rich('cyan')

        assert ansi == '\033[36m'

    def test_from_rich_handles_bold_modifier(self):
        """
        BV: Bold modifier is correctly prepended.

        Scenario:
          Given: Colors class
          When: from_rich('bold cyan') is called
          Then: Returns bold + cyan ANSI codes
        """
        from core.themes.colors import Colors

        ansi = Colors.from_rich('bold cyan')

        assert '\033[1m' in ansi  # Bold
        assert '\033[36m' in ansi  # Cyan

    def test_from_rich_handles_hex_color(self):
        """
        BV: Hex colors are converted to 24-bit ANSI.

        Scenario:
          Given: Colors class
          When: from_rich('#689d6a') is called
          Then: Returns ANSI true color escape code
        """
        from core.themes.colors import Colors

        ansi = Colors.from_rich('#689d6a')

        assert '\033[38;2;' in ansi  # True color prefix

    def test_strip_removes_ansi_codes(self):
        """
        BV: Colored text can be cleaned for logging/export.

        Scenario:
          Given: Text with ANSI codes
          When: Colors.strip(text) is called
          Then: Returns plain text without codes
        """
        from core.themes.colors import Colors

        colored = '\033[91mRed text\033[0m'

        result = Colors.strip(colored)

        assert result == 'Red text'
        assert '\033' not in result

    def test_disable_clears_all_codes(self):
        """
        BV: Colors can be disabled for non-terminal output.

        Scenario:
          Given: Colors class
          When: Colors.disable() is called
          Then: All color codes become empty strings
        """
        from core.themes.colors import Colors

        Colors.disable()

        assert Colors.RED == ''
        assert Colors.BOLD == ''

        # Cleanup
        Colors.enable()

    def test_enable_restores_codes(self):
        """
        BV: Colors can be re-enabled after disabling.

        Scenario:
          Given: Colors disabled
          When: Colors.enable() is called
          Then: Color codes are restored
        """
        from core.themes.colors import Colors

        Colors.disable()
        Colors.enable()

        assert Colors.RED != ''
        assert Colors.BOLD != ''


class TestReferenceTheme:
    """Tests for ReferenceTheme ANSI color wrapper"""

    def test_primary_returns_colored_text(self):
        """
        BV: Primary color is applied in terminal output.

        Scenario:
          Given: ReferenceTheme instance
          When: primary('text') is called
          Then: Returns text with ANSI color codes
        """
        from core.themes.colors import ReferenceTheme

        theme = ReferenceTheme()

        result = theme.primary('test')

        assert 'test' in result
        assert '\033[' in result  # Contains ANSI codes

    def test_disabled_returns_plain_text(self):
        """
        BV: Theme can be disabled for clean output.

        Scenario:
          Given: ReferenceTheme with enabled=False
          When: primary('text') is called
          Then: Returns plain text without ANSI codes
        """
        from core.themes.colors import ReferenceTheme

        theme = ReferenceTheme(enabled=False)

        result = theme.primary('test')

        assert result == 'test'
        assert '\033[' not in result

    def test_banner_title_uses_bold_red(self):
        """
        BV: Banner titles are prominently styled.

        Scenario:
          Given: ReferenceTheme instance
          When: banner_title('CRACK') is called
          Then: Returns bold + danger color wrapped text
        """
        from core.themes.colors import ReferenceTheme, Colors

        theme = ReferenceTheme()

        result = theme.banner_title('CRACK')

        assert 'CRACK' in result
        assert Colors.BOLD in result or '\033[1m' in result


class TestThemeManagerInfo:
    """Tests for theme information retrieval"""

    def test_get_theme_info_returns_metadata(self, theme_manager):
        """
        BV: Theme info is available for UI display.

        Scenario:
          Given: ThemeManager with OSCP theme
          When: get_theme_info() is called
          Then: Returns dict with name, display_name, description
        """
        info = theme_manager.get_theme_info()

        assert info['name'] == 'oscp'
        assert 'display_name' in info
        assert 'description' in info

    def test_list_themes_returns_all_available(self, theme_manager):
        """
        BV: All themes are listed for selection UI.

        Scenario:
          Given: ThemeManager
          When: list_themes() is called
          Then: Returns list with at least 6 themes
        """
        themes = theme_manager.list_themes()

        assert len(themes) >= 6


class TestThemeStateColors:
    """Tests for state-specific color methods"""

    def test_task_state_color_returns_correct(self, theme_manager):
        """
        BV: Task states have distinct colors for visual differentiation.

        Scenario:
          Given: OSCP theme
          When: task_state_color('completed') is called
          Then: Returns 'green'
        """
        color = theme_manager.task_state_color('completed')

        assert color == 'green'

    def test_task_state_color_handles_hyphen_underscore(self, theme_manager):
        """
        BV: State names work with either hyphens or underscores.

        Scenario:
          Given: OSCP theme
          When: task_state_color('in-progress') and task_state_color('in_progress')
          Then: Both return same color
        """
        hyphen = theme_manager.task_state_color('in-progress')
        underscore = theme_manager.task_state_color('in_progress')

        assert hyphen == underscore

    def test_port_state_color_open_is_green(self, theme_manager):
        """
        BV: Open ports are visually distinct (green = good).

        Scenario:
          Given: OSCP theme
          When: port_state_color('open') is called
          Then: Returns 'green'
        """
        color = theme_manager.port_state_color('open')

        assert color == 'green'
