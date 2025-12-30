/**
 * Vitest Configuration for Crackpedia
 *
 * Business Value Focus:
 * - Test IPC handlers for Neo4j connectivity
 * - Verify search functionality works correctly
 * - Ensure graph data formatting is accurate
 */

import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.spec.ts'],
    exclude: ['node_modules', 'dist', 'dist-electron'],
    mockReset: true,
    clearMocks: true,
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/main/**/*.ts'],
      exclude: ['src/main/debug.ts'],
    },
    testTimeout: 10000,
    hookTimeout: 10000,
    // Ensure tests run in isolation
    isolate: true,
    // Use threads for parallel execution safety
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
      },
    },
  },
  resolve: {
    alias: {
      '@main': path.resolve(__dirname, 'src/main'),
      '@preload': path.resolve(__dirname, 'src/preload'),
      '@renderer': path.resolve(__dirname, 'src/renderer/src'),
    },
  },
});
