import { MantineThemeOverride } from '@mantine/core';

/**
 * Custom Mantine theme for CRACK Electron App
 * Extends default dark theme with semantic colors for step content rendering
 */
export const theme: MantineThemeOverride = {
  primaryColor: 'cyan',
  fontFamily: 'Inter, system-ui, sans-serif',
  fontFamilyMonospace: 'JetBrains Mono, Monaco, Courier, monospace',

  colors: {
    // Extend cyan for primary accents (already in Mantine, but defining for clarity)
    // cyan[0-9] available by default

    // Custom dark backgrounds (using 'dark' color scale)
    dark: [
      '#C1C2C5', // 0 - lightest
      '#A6A7AB',
      '#909296',
      '#5c5f66',
      '#373A40', // 4 - borders
      '#2C2E33', // 5 - tertiary background
      '#25262b', // 6 - secondary background
      '#1A1B1E', // 7 - primary background
      '#141517', // 8 - darker
      '#101113', // 9 - darkest (code background)
    ],
  },

  other: {
    // Semantic color mappings for step content types
    stepContent: {
      // Major section headers (PREREQUISITES CHECK:, VERIFICATION METHODS:)
      majorHeader: 'cyan.4',        // Cyan - primary accent

      // Subsection headers (LINUX (Impacket):, METHOD 1:)
      subsectionHeader: 'blue.4',   // Blue - secondary accent

      // Emphasis keywords (OPSEC:, CRITICAL:, IMPORTANT:, NOTE:)
      emphasis: 'yellow.5',         // Yellow - attention

      // Success indicators (SUCCESS:, EXPECTED:, ✓)
      success: 'green.5',           // Green - positive

      // Failure indicators (FAILURE:, ERROR:, ✗, -)
      failure: 'red.5',             // Red - negative

      // Warning indicators (WARNING:, CAUTION:)
      warning: 'orange.5',          // Orange - caution

      // Info indicators (INFO:, TIP:, EXAM TIP:)
      info: 'blue.3',               // Light blue - informational

      // Command text color
      commandText: 'green.3',       // Light green for visibility

      // Command background
      commandBg: 'dark.9',          // Very dark green-tinted

      // Code block background
      codeBlockBg: 'dark.8',        // Darker background

      // List bullet colors
      listBullet: 'cyan.6',         // Cyan bullets

      // Default prose text
      prose: 'dimmed',              // Mantine's dimmed text
    },
  },
};

export default theme;
