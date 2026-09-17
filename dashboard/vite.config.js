import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In dev, `npm run dev` serves the UI on :3000 and proxies API + WS to the
// PhishGuard hub (`npx phishguard dashboard --no-open`, default port 4173).
// In prod the hub serves the built files from dashboard/dist itself.
const HUB = process.env.PHISHGUARD_HUB || 'http://localhost:4173';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': { target: HUB, changeOrigin: true, secure: false },
      '/ws': { target: HUB.replace(/^http/, 'ws'), ws: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
