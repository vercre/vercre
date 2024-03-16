import path from 'path';

import { defineConfig, searchForWorkspaceRoot } from 'vite';
import react from '@vitejs/plugin-react';
import mkcert from 'vite-plugin-mkcert';
import topLevelAwait from 'vite-plugin-top-level-await';
import wasm from 'vite-plugin-wasm';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    mkcert(),
    topLevelAwait(),
    wasm(),
  ],
  server: {
    
    port: 3000,
    // host: 'dev.vercre.io',
    fs: {
      allow: [
        searchForWorkspaceRoot(process.cwd()),
        '../../pkg'
      ]
    }
  },
  resolve: {
    // eslint-disable-next-line no-undef
    alias: { '@': path.resolve(__dirname, './src') },
  },
  optimizeDeps: {
    include: ['shared_types/types/shared_types', 'shared_types/bincode/mod'],
  }
});
