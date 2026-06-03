import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api to the FastAPI backend on :8000.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
  // `vite preview` (used when the dev watcher hits the host inotify limit) needs its
  // own proxy block to forward /api to the FastAPI backend.
  preview: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
