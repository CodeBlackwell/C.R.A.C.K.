"""
Log Configuration - Precision filtering and configuration management

Manages what gets logged based on categories, modules, verbosity levels,
and output targets. Supports multiple configuration sources.
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, Optional, List, Any

from .log_types import LogCategory, LogLevel, OutputTarget, LogFormat, parse_category_spec


@dataclass
class LogConfig:
    """
    Configuration for precision debug logging

    Supports multiple filtering dimensions:
    - Categories: Which log categories to enable
    - Modules: Which Python modules to log from
    - Levels: Verbosity level per category
    - Targets: Where to send log output
    """

    # Core settings
    enabled: bool = False
    global_level: LogLevel = LogLevel.NORMAL
    output_target: OutputTarget = OutputTarget.FILE
    log_format: LogFormat = LogFormat.TEXT

    # Filtering
    enabled_categories: Set[LogCategory] = field(default_factory=set)
    category_levels: Dict[LogCategory, LogLevel] = field(default_factory=dict)
    enabled_modules: Set[str] = field(default_factory=set)
    disabled_modules: Set[str] = field(default_factory=set)

    # Performance
    buffer_size: int = 100  # Buffer log messages before flushing
    include_timing: bool = False  # Include execution timing in logs

    def should_log(
        self,
        category: Optional[LogCategory] = None,
        level: LogLevel = LogLevel.NORMAL,
        module: Optional[str] = None,
        function: Optional[str] = None
    ) -> bool:
        """
        Determine if a log message should be recorded

        Args:
            category: Log category
            level: Message verbosity level
            module: Source module name
            function: Source function name

        Returns:
            True if message should be logged
        """
        if not self.enabled:
            return False

        # Check module filters
        if module:
            # Explicit module disable takes precedence
            if module in self.disabled_modules:
                return False
            # If module filters exist, must match
            if self.enabled_modules and module not in self.enabled_modules:
                return False

        # Check category filters
        if category:
            # If specific categories enabled, check if this matches
            if self.enabled_categories:
                if not self._category_matches_filter(category):
                    return False

            # Check category-specific level
            category_level = self._get_category_level(category)
            if level.value > category_level.value:
                return False
        else:
            # No category specified, use global level
            if level.value > self.global_level.value:
                return False

        return True

    def _category_matches_filter(self, category: LogCategory) -> bool:
        """Check if category matches enabled filters"""
        for enabled_cat in self.enabled_categories:
            # Exact match
            if category == enabled_cat:
                return True
            # Child of enabled parent (e.g., UI.INPUT matches UI)
            if category.is_child_of(enabled_cat):
                return True
            # Parent enabled (e.g., UI matches when UI.INPUT is enabled)
            if enabled_cat.is_child_of(category):
                return True
        return False

    def _get_category_level(self, category: LogCategory) -> LogLevel:
        """Get effective log level for a category"""
        # Check for exact match
        if category in self.category_levels:
            return self.category_levels[category]

        # Check for parent category level
        parent = category.get_parent()
        while parent:
            if parent in self.category_levels:
                return self.category_levels[parent]
            parent = parent.get_parent()

        # Fall back to global level
        return self.global_level

    def enable_category(
        self,
        category: LogCategory,
        level: Optional[LogLevel] = None
    ):
        """Enable a log category with optional level"""
        self.enabled_categories.add(category)
        if level:
            self.category_levels[category] = level

    def disable_category(self, category: LogCategory):
        """Disable a log category"""
        self.enabled_categories.discard(category)
        self.category_levels.pop(category, None)

    def enable_module(self, module: str):
        """Enable logging from a specific module"""
        self.enabled_modules.add(module)
        self.disabled_modules.discard(module)

    def disable_module(self, module: str):
        """Disable logging from a specific module"""
        self.disabled_modules.add(module)
        self.enabled_modules.discard(module)

    def set_category_level(self, category: LogCategory, level: LogLevel):
        """Set verbosity level for a category"""
        self.category_levels[category] = level

    @classmethod
    def from_string(cls, config_str: str) -> 'LogConfig':
        """
        Parse configuration from string

        Format: "CATEGORY:LEVEL,CATEGORY2:LEVEL2,..."
        Examples:
        - "UI.INPUT:VERBOSE,STATE:NORMAL"
        - "UI:TRACE"
        - "EXECUTION,DATA.PARSE:VERBOSE"

        Args:
            config_str: Configuration string

        Returns:
            LogConfig instance
        """
        config = cls(enabled=True)

        if not config_str or config_str.lower() in ('all', 'true', '1'):
            # Enable all categories at default level
            config.enabled_categories = set(LogCategory)
            return config

        # Parse individual category specs
        specs = [s.strip() for s in config_str.split(',') if s.strip()]
        for spec in specs:
            try:
                category, level = parse_category_spec(spec)
                config.enable_category(category, level)
            except ValueError as e:
                print(f"Warning: Invalid category spec '{spec}': {e}")

        return config

    @classmethod
    def from_cli_args(
        cls,
        categories: Optional[str] = None,
        modules: Optional[str] = None,
        level: Optional[str] = None,
        output: Optional[str] = None,
        format: Optional[str] = None
    ) -> 'LogConfig':
        """
        Create config from CLI arguments

        Args:
            categories: Comma-separated category specs
            modules: Comma-separated module names
            level: Global log level
            output: Output target (file, console, both)
            format: Log format (text, json, compact)

        Returns:
            LogConfig instance
        """
        config = cls(enabled=True)

        # Parse categories
        if categories:
            config = cls.from_string(categories)

        # Parse modules
        if modules:
            for module in modules.split(','):
                module = module.strip()
                if module.startswith('!'):
                    config.disable_module(module[1:])
                else:
                    config.enable_module(module)

        # Parse global level
        if level:
            try:
                config.global_level = LogLevel[level.upper()]
            except KeyError:
                print(f"Warning: Invalid log level '{level}'")

        # Parse output target
        if output:
            try:
                config.output_target = OutputTarget[output.upper()]
            except KeyError:
                print(f"Warning: Invalid output target '{output}'")

        # Parse format
        if format:
            try:
                config.log_format = LogFormat[format.upper()]
            except KeyError:
                print(f"Warning: Invalid log format '{format}'")

        return config

    @classmethod
    def from_file(cls, file_path: Path) -> 'LogConfig':
        """
        Load configuration from JSON file

        Example format:
        {
            "enabled": true,
            "global_level": "NORMAL",
            "categories": {
                "UI.INPUT": "VERBOSE",
                "STATE": "NORMAL"
            },
            "modules": ["session", "prompts"],
            "output_target": "file",
            "log_format": "text"
        }

        Args:
            file_path: Path to config file

        Returns:
            LogConfig instance
        """
        with open(file_path, 'r') as f:
            data = json.load(f)

        config = cls(enabled=data.get('enabled', True))

        # Global level
        if 'global_level' in data:
            try:
                config.global_level = LogLevel[data['global_level'].upper()]
            except KeyError:
                pass

        # Categories
        if 'categories' in data:
            for cat_str, level_str in data['categories'].items():
                try:
                    category, _ = parse_category_spec(cat_str)
                    level = LogLevel[level_str.upper()]
                    config.enable_category(category, level)
                except (ValueError, KeyError) as e:
                    print(f"Warning: Invalid category config '{cat_str}': {e}")

        # Modules
        if 'modules' in data:
            for module in data['modules']:
                config.enable_module(module)

        if 'disabled_modules' in data:
            for module in data['disabled_modules']:
                config.disable_module(module)

        # Output target
        if 'output_target' in data:
            try:
                config.output_target = OutputTarget[data['output_target'].upper()]
            except KeyError:
                pass

        # Log format
        if 'log_format' in data:
            try:
                config.log_format = LogFormat[data['log_format'].upper()]
            except KeyError:
                pass

        # Performance settings
        if 'buffer_size' in data:
            config.buffer_size = int(data['buffer_size'])
        if 'include_timing' in data:
            config.include_timing = bool(data['include_timing'])

        return config

    @classmethod
    def from_env(cls) -> 'LogConfig':
        """
        Load configuration from environment variables

        Environment variables:
        - CRACK_DEBUG_ENABLED: Enable debug logging (1/true/yes)
        - CRACK_DEBUG_CATEGORIES: Category specs (same as CLI)
        - CRACK_DEBUG_MODULES: Module names
        - CRACK_DEBUG_LEVEL: Global log level
        - CRACK_DEBUG_OUTPUT: Output target
        - CRACK_DEBUG_FORMAT: Log format

        Returns:
            LogConfig instance
        """
        enabled = os.getenv('CRACK_DEBUG_ENABLED', '').lower() in ('1', 'true', 'yes')
        if not enabled:
            return cls(enabled=False)

        return cls.from_cli_args(
            categories=os.getenv('CRACK_DEBUG_CATEGORIES'),
            modules=os.getenv('CRACK_DEBUG_MODULES'),
            level=os.getenv('CRACK_DEBUG_LEVEL'),
            output=os.getenv('CRACK_DEBUG_OUTPUT'),
            format=os.getenv('CRACK_DEBUG_FORMAT')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration to dictionary"""
        return {
            'enabled': self.enabled,
            'global_level': self.global_level.name,
            'categories': {
                cat.value: level.name
                for cat, level in self.category_levels.items()
            },
            'enabled_categories': [cat.value for cat in self.enabled_categories],
            'modules': list(self.enabled_modules),
            'disabled_modules': list(self.disabled_modules),
            'output_target': self.output_target.value,
            'log_format': self.log_format.value,
            'buffer_size': self.buffer_size,
            'include_timing': self.include_timing
        }

    def to_file(self, file_path: Path):
        """Save configuration to JSON file"""
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def __repr__(self) -> str:
        """String representation for debugging"""
        if not self.enabled:
            return "LogConfig(disabled)"

        parts = [f"LogConfig(enabled={self.enabled}"]
        if self.enabled_categories:
            cats = ','.join(c.value for c in sorted(self.enabled_categories, key=lambda x: x.value))
            parts.append(f"categories={cats}")
        if self.enabled_modules:
            mods = ','.join(sorted(self.enabled_modules))
            parts.append(f"modules={mods}")
        parts.append(f"level={self.global_level.name}")
        return ' '.join(parts) + ")"
