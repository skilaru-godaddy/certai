import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/analyze': 'http://localhost:3001',
      '/stream': 'http://localhost:3001',
      '/job': 'http://localhost:3001',
      '/publish': 'http://localhost:3001',
    },
  },
});
