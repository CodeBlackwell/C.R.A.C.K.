/**
 * Vitest Configuration for B.R.E.A.C.H. IPC Handler Tests
 *
 * Configures testing for Electron main process IPC handlers with:
 * - Mock support for Neo4j driver and node-pty
 * - Path aliases matching tsconfig.json
 * - Isolated test environments
 */

import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Run in Node environment (for main process tests)
    environment: 'node',

    // Test file patterns
    include: ['tests/**/*.spec.ts', 'tests/**/*.test.ts'],

    // Mock setup
    setupFiles: ['./tests/setup.ts'],

    // Global test timeout
    testTimeout: 10000,

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/main/ipc/**/*.ts'],
      exclude: ['**/*.d.ts', '**/__mocks__/**'],
    },

    // Mock directory for auto-mocking
    mockReset: true,
    clearMocks: true,
    restoreMocks: true,

    // Parallel execution safety
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true, // Isolate tests for deterministic execution
      },
    },

    // Reporter
    reporters: ['verbose'],
  },

  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src/renderer/src'),
      '@shared': path.resolve(__dirname, '../shared'),
      // Mock electron in tests
      electron: path.resolve(__dirname, './tests/__mocks__/electron.ts'),
    },
  },
});
