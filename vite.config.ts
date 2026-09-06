import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        /*
         * Split by change-frequency and by who needs them. React is required to
         * paint anything; ogl/gsap only matter once the decorative layers run,
         * so on a low-tier device they are cached separately and never block
         * first paint. recharts is already lazy-imported by the dashboard.
         */
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return;
          if (/[\/]node_modules[\/](react|react-dom|scheduler)[\/]/.test(id)) return 'react';
          if (id.includes('node_modules/motion') || id.includes('node_modules/framer-motion')) return 'motion';
          if (id.includes('node_modules/ogl')) return 'webgl';
          if (id.includes('node_modules/gsap')) return 'gsap';
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: false,
  },
});
