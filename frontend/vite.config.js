import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import { resolve } from "path"

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": {
        target: "http://web:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, "")
      }
    }
  },
  base: mode === "demo" ? "/demo/" : "/",
  build: mode === "demo" ? {
    outDir: "../website/demo",
    rollupOptions: {
      input: resolve(__dirname, "demo.html"),
    },
  } : {},
}))
