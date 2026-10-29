import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    host: true,
    proxy: {
      '/probe/ml': { target: 'http://127.0.0.1:8000', changeOrigin: true, rewrite: (path) => path.replace(/^\/probe\/ml/, '') },
      '/probe/zap': { target: 'http://127.0.0.1:8091', changeOrigin: true, rewrite: (path) => path.replace(/^\/probe\/zap/, '') },
      '/probe/catalog': { target: 'http://127.0.0.1:4173', changeOrigin: true, rewrite: (path) => path.replace(/^\/probe\/catalog/, '') },
      '/probe/api': { target: 'http://127.0.0.1:5001', changeOrigin: true, rewrite: (path) => path.replace(/^\/probe\/api/, '') }
    }
  }
});
