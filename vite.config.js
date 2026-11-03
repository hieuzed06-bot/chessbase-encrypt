import { defineConfig } from 'vite';

const developmentWebSocketPolicy = {
  name: 'development-websocket-csp',
  transformIndexHtml(html, context) {
    if (!context.server) return html;
    return html.replace("connect-src 'none'", "connect-src 'self' ws: wss:");
  },
};

export default defineConfig({
  base: './',
  plugins: [developmentWebSocketPolicy],
  esbuild: { jsx: 'automatic' },
  server: { host: '0.0.0.0' },
  build: { outDir: 'dist', emptyOutDir: true },
});
