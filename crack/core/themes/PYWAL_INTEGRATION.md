# Pywal Theme Integration for CRACK

## Overview

CRACK now supports 250+ additional color themes from the pywal16 library. Pywal themes integrate seamlessly with the existing 6 built-in themes.

## Installation

Pywal16 is automatically installed with CRACK:

```bash
# Standard installation (includes pywal16)
pip install -e .

# Or from PyPI when published
pip install crack
```

Pywal16 is now a core dependency - all 250+ themes are available by default!

## Usage

### Check Availability

```python
from themes import is_pywal_available

if is_pywal_available():
    print("Pywal themes available!")
else:
    print("Install pywal16 to enable 250+ additional themes")
```

### List All Themes

```python
from themes import get_theme_names, list_themes

# Get all theme names (built-in + pywal)
all_names = get_theme_names()
print(f"Total themes: {len(all_names)}")

# Get detailed theme metadata
themes = list_themes()
for theme in themes:
    print(f"{theme['name']}: {theme['display_name']}")
```

### Using Pywal Themes

```python
from themes import ThemeManager

# Initialize theme manager
tm = ThemeManager()

# Switch to a pywal theme (prefix with 'pw_')
tm.set_theme('pw_gruvbox')
tm.set_theme('pw_nord')
tm.set_theme('pw_dracula')
tm.set_theme('pw_solarized')

# Use theme colors normally
primary = tm.get_color('primary')
success = tm.get_color('success')
```

## Theme Naming Convention

- **Built-in themes**: `oscp`, `dark`, `light`, `nord`, `dracula`, `mono`
- **Pywal themes**: `pw_<theme_name>` (e.g., `pw_gruvbox`, `pw_nord`)

The `pw_` prefix prevents naming collisions between built-in and pywal themes.

## Popular Pywal Themes

Some recommended pywal themes to try:

- `pw_gruvbox` - Retro groove color scheme
- `pw_nord` - Arctic, north-bluish color palette
- `pw_dracula` - Dark theme with vibrant colors
- `pw_solarized` - Precision colors for machines and people
- `pw_monokai` - Sublime Text default color scheme
- `pw_onedark` - Atom One Dark theme
- `pw_tokyo-night` - Clean, dark theme

## Architecture

### Color Mapping

Pywal themes use Base16 color scheme (16 colors: color0-15). These are mapped to CRACK's semantic roles:

- **Primary** (cyan) ← color4 (Blue)
- **Secondary** (magenta) ← color5 (Purple)
- **Success** (green) ← color2 (Green)
- **Warning** (yellow) ← color3 (Yellow)
- **Danger** (red) ← color1 (Red)
- **Info** (cyan) ← color6 (Cyan)
- **Muted** (dim) ← color8 (Bright Black)

### Graceful Fallback

If pywal16 is not installed:
- Only built-in themes (6) are available
- No errors or warnings during normal operation
- `is_pywal_available()` returns `False`
- `get_theme_names()` returns only built-in themes

## Theme Files

- `themes/pywal_adapter.py` - Pywal integration adapter
- `themes/presets.py` - Theme registry (built-in + pywal)
- `themes/manager.py` - Theme manager (uses presets)
- `themes/__init__.py` - Public API exports

## Testing

```bash
# Test pywal availability
python3 -c "from themes import is_pywal_available; print(is_pywal_available())"

# List all themes
python3 -c "from themes import get_theme_names; print(len(get_theme_names()))"

# Test theme switching
python3 -c "
from themes import ThemeManager
tm = ThemeManager()
print(f'Current: {tm.get_theme_name()}')
tm.set_theme('pw_gruvbox')  # Only works if pywal16 installed
print(f'Switched to: {tm.get_theme_name()}')
"
```

## Troubleshooting

### ImportError: No module named 'pywal'

**Solution**: Install pywal16:
```bash
pip install pywal16
```

### Theme not found: 'pw_gruvbox'

**Causes**:
1. pywal16 not installed
2. Theme name typo (use `get_theme_names()` to list all)

**Solution**: Verify pywal16 is installed and theme name is correct:
```python
from themes import is_pywal_available, get_theme_names
print(f"Pywal available: {is_pywal_available()}")
print(f"Available themes: {get_theme_names()}")
```

### No pywal themes showing up

**Check**:
1. Is pywal16 installed? `pip show pywal16`
2. Is import working? `python3 -c "import pywal; print('OK')"`
3. Check theme count: `python3 -c "from themes import get_theme_names; print(len(get_theme_names()))"`

Expected: 6 themes without pywal, 256+ with pywal

## Contributing

To add more theme sources (beyond pywal):

1. Create adapter module in `themes/` (e.g., `gogh_adapter.py`)
2. Implement `get_all_<source>_themes()` returning dict matching BUILT_IN_THEMES format
3. Update `themes/presets.py` to merge your themes in `get_all_themes()`
4. Update `themes/__init__.py` exports
5. Add documentation

## License

Pywal themes are maintained by the pywal project. CRACK's integration is MIT licensed.
