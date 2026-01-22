import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/react/',
  build: {
    outDir: '../wwwroot/react',
    emptyOutDir: true
  },
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:7235',
        secure: false,
        changeOrigin: true
      },
      '/authentication': {
        target: 'https://localhost:7235',
        secure: false,
        changeOrigin: true
      }
    }
  }
})
