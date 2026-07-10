import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    exclude: ['tests/visual/**', 'node_modules/**']
  },
  server: {
    host: '127.0.0.1',
    port: 5174
  }
});
