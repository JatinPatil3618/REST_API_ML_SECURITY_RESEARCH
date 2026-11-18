import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const gateway = env.VITE_GATEWAY_URL || 'http://localhost:8080';
  const gatewayOrigin = new URL(gateway).origin;
  // Inline style attributes are part of the catalog components. Script sources stay same-origin.
  const contentSecurityPolicy = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    `connect-src 'self' ${gatewayOrigin} https://fonts.googleapis.com https://fonts.gstatic.com`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'"
  ].join('; ');

  return {
    plugins: [react()],
    server: {
      port: 5173,
      host: true
    },
    preview: {
      port: 4173,
      host: '127.0.0.1',
      strictPort: true,
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': contentSecurityPolicy
      }
    }
  };
});
