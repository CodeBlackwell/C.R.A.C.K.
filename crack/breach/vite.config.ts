import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import electron from 'vite-plugin-electron';
import renderer from 'vite-plugin-electron-renderer';
import { resolve } from 'path';

const sharedPath = resolve(__dirname, '../shared');

export default defineConfig({
  plugins: [
    react(),
    electron([
      {
        // Main process
        entry: 'src/main/index.ts',
        onstart(options) {
          options.startup();
        },
        vite: {
          resolve: {
            alias: {
              '@shared': sharedPath,
            },
          },
          build: {
            outDir: 'dist-electron/main',
            rollupOptions: {
              external: ['node-pty', 'neo4j-driver'],
            },
          },
        },
      },
      {
        // Preload script
        entry: 'src/preload/index.ts',
        vite: {
          resolve: {
            alias: {
              '@shared': sharedPath,
            },
          },
          build: {
            outDir: 'dist-electron/preload',
          },
        },
      },
    ]),
    renderer(),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/renderer/src'),
      '@shared': sharedPath,
    },
  },
  server: {
    host: true,
    port: 5174,
  },
  build: {
    outDir: 'dist',
  },
  // Inject debug flags at build time for renderer
  define: {
    __DEBUG__: JSON.stringify(process.env.DEBUG === 'true'),
    __DEBUG_CATEGORIES__: JSON.stringify(process.env.DEBUG_CATEGORIES || '*'),
    __DEBUG_LEVEL__: JSON.stringify(process.env.DEBUG_LEVEL || 'INFO'),
  },
});
