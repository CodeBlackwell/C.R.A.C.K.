# CRACK Theme Selector - User Guide

## Overview

The `crack config theme` command launches an interactive theme selector that supports:
- 6 built-in themes (always available)
- 250+ pywal themes (optional, requires pywal16)
- Real-time theme preview
- Search and filtering
- Keyboard navigation

## Quick Start

```bash
# Launch theme selector
crack config theme
```

## Navigation

### Basic Navigation
- **↑/↓ Arrow Keys** - Navigate up/down through themes
- **Page Up/Down** - Jump 10 themes at a time
- **Home/End** - Jump to first/last theme
- **Enter** - Select current theme
- **q or ESC** - Cancel and exit

### Search & Filter
- **/** - Search themes by name or description
- **f** - Toggle filter mode (All → Built-in → Pywal → All)
- **c** - Clear all filters and search

## Features

### 1. Theme Preview

Each selected theme shows a live preview:
```
● Primary  ● Secondary
✓ Success  ⚠ Warning  ✗ Error
(Muted text for hints)
```

Colors update in real-time as you navigate.

### 2. Search Functionality

Press `/` to search themes:
```
Search themes:
Enter search text (or press Enter to cancel):

  > gruvbox
```

Searches in:
- Theme name
- Display name
- Description

### 3. Filter Modes

Press `f` to cycle through filter modes:

1. **All** (default) - Show all themes
2. **Built-in** - Show only 6 built-in themes
3. **Pywal** - Show only pywal themes (if installed)

### 4. Theme Statistics

Top bar shows theme counts:
```
Total: 256  │  Built-in: 6  │  Pywal: 250
```

### 5. Pywal Theme Badge

Pywal themes display with a `[pywal]` badge:
```
▶ gruvbox [pywal] (current)
```

The `pw_` prefix is hidden for cleaner display.

### 6. Windowed Display

With 250+ themes, the selector shows a scrolling window:
```
... 42 more above ...

  oscp
  dark
▶ nord (current)
  dracula
  gruvbox [pywal]

... 245 more below ...
```

Shows 20 themes at a time centered on selection.

## Built-in Themes

Always available (no installation required):

| Theme | Description |
|-------|-------------|
| **oscp** | Cyan-heavy OSCP workflow optimized |
| **dark** | Dark terminal with muted colors |
| **light** | Light terminal with darker text |
| **nord** | Arctic blue color palette |
| **dracula** | Dark with vibrant accents |
| **mono** | Monochrome grayscale |

## Pywal Themes

### Installation

Pywal16 is automatically installed with CRACK - no extra steps needed!

```bash
# Standard installation includes all 250+ pywal themes
pip install -e .
```

### Popular Pywal Themes

Some recommended themes to try:

- **gruvbox** - Retro groove color scheme
- **nord** - Arctic, north-bluish palette
- **dracula** - Dark theme with vibrant colors
- **solarized** - Precision colors
- **monokai** - Sublime Text default
- **onedark** - Atom One Dark
- **tokyo-night** - Clean dark theme
- **catppuccin** - Soothing pastel theme
- **everforest** - Green forest theme
- **material** - Material Design colors

### Finding Themes

When pywal is installed, you'll have access to 250+ themes. Use search:

```bash
# In theme selector, press /
Search: gruvbox    # Finds gruvbox-dark, gruvbox-light
Search: nord       # Finds nord, nord-light
Search: tokyo      # Finds tokyo-night variants
```

## Usage Examples

### Switch to Built-in Theme

1. Run `crack config theme`
2. Navigate to `nord` with ↑/↓
3. Press `Enter`
4. Theme saved to `~/.crack/config.json`

### Search for Pywal Theme

1. Run `crack config theme`
2. Press `/` to search
3. Type `gruvbox`
4. Press `Enter` to search
5. Navigate and select theme

### Filter to Only Pywal Themes

1. Run `crack config theme`
2. Press `f` to cycle to "Pywal" filter
3. Browse only pywal themes
4. Press `c` to clear filter

## Theme Persistence

Selected themes are saved to `~/.crack/config.json`:

```json
{
  "theme": {
    "current": "nord"
  }
}
```

All CRACK tools (reference, track, etc.) will use the selected theme.

## Keyboard Shortcuts Summary

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate up/down |
| Page Up/Down | Jump 10 themes |
| Home/End | Jump to start/end |
| / | Search themes |
| f | Cycle filter mode |
| c | Clear filters |
| Enter | Select theme |
| q/ESC | Cancel |

## Tips

1. **Search First** - With 250+ themes, search narrows options quickly
2. **Preview Before Selecting** - Colors update as you navigate
3. **Filter by Source** - Use `f` to see only built-in or pywal themes
4. **Clear Often** - Press `c` to reset view when lost
5. **Install Pywal** - Unlock 250+ themes for variety

## Troubleshooting

### No Pywal Themes Showing

**Cause**: pywal16 not installed

**Solution**:
```bash
pip install pywal16
```

### Search Returns No Results

**Cause**: No themes match search term

**Solution**: Press `c` to clear filters and try again

### Theme Selector Won't Launch

**Cause**: Not running in interactive terminal

**Solution**: Run directly in terminal, not through pipe/script

### Selected Theme Not Applied

**Check**:
1. Theme was saved: `grep theme ~/.crack/config.json`
2. Restart CRACK tools to pick up new theme
3. Verify theme name: `crack config get theme.current`

## Python API

For programmatic theme selection:

```python
from themes import ThemeManager, list_themes

# List all themes
themes = list_themes()
for theme in themes:
    print(f"{theme['name']}: {theme['display_name']}")

# Switch theme
tm = ThemeManager()
tm.set_theme('nord')

# Get current theme
current = tm.get_theme_name()
```

## See Also

- `themes/PYWAL_INTEGRATION.md` - Pywal integration details
- `crack config --help` - Config management
- `~/.crack/config.json` - Configuration file
