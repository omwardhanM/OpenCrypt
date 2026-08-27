import { resolve } from 'path'
import { defineConfig } from 'vite'

export default defineConfig({
  // Relative base path allows deployment on Cloudflare Pages (opencrypt.pages.dev), GitHub Pages, custom domains, and subdirectories
  base: './',
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, 'index.html'),
        docs: resolve(import.meta.dirname, 'docs/index.html'),
      },
    },
  },
})
