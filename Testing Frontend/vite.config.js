import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    // @elvoroz/authnest-server v1.0.9 deliberately dropped localhost:5173/5174 from
    // its default allowed-origins list (those are the AuthNest SaaS's own
    // dashboard dev ports, not generic client-app defaults). 5175 is still
    // in the default allow-list, so we run here instead of Vite's default
    // 5173 to avoid CORS failures without needing any dashboard changes.
    port: 5175,
    proxy: {
      "/api": "http://localhost:9000/",
      // "/authnest": "http://localhost:9000/",
    },
  },
  define: {
    // @elvoroz/authnest-react's useAuth.js reads process.env.NODE_ENV directly.
    // Vite (unlike webpack/CRA) does not define process.env in the
    // browser bundle by default, so without this the reference throws
    // "process is not defined" and auth silently fails to initialize.
    'process.env.NODE_ENV': JSON.stringify(mode),
  },
  build: {
    sourcemap: false
  }
}))
