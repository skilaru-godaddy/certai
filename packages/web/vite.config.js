import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({
    plugins: [react(), tailwindcss()],
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
