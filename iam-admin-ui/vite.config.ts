import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  base: "/admin/",
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/admin/oauth-login": {
        target: "http://localhost:8080",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/admin\/oauth-login/, "/admin/login")
      },
      "/admin/callback": { target: "http://localhost:8080", changeOrigin: true },
      "/admin/logout": { target: "http://localhost:8080", changeOrigin: true },
      "/sso": { target: "http://localhost:8080", changeOrigin: true },
      "/oauth2": { target: "http://localhost:8080", changeOrigin: true }
    }
  },
  preview: {
    port: 4173
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.spec.ts"]
  }
});
