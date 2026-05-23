import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // Code-split heavyweights so the initial JS payload stays lean.
    // Framer Motion + react-markdown together are ~200KB and aren't
    // needed for first paint of the marketing landing.
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'motion':       ['framer-motion'],
          'markdown':     ['react-markdown', 'remark-gfm'],
        },
      },
    },
  },
  server: {
    host: '127.0.0.1',
    proxy: {
      '/scan': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        proxyTimeout: 120000,
        timeout: 120000,
      },
      '/health': 'http://127.0.0.1:8000',
    }
  }
})
