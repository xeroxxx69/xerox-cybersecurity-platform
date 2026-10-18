import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import fs from "fs";

function spaFallbackPlugin(): Plugin {
  return {
    name: "spa-fallback-404",
    closeBundle() {
      const distDir = path.resolve(__dirname, "./dist");
      const indexPath = path.join(distDir, "index.html");
      const notFoundPath = path.join(distDir, "404.html");
      if (fs.existsSync(indexPath)) {
        fs.copyFileSync(indexPath, notFoundPath);
      }
    },
  };
}

function productionConfigValidationPlugin(): Plugin {
  return {
    name: "validate-production-api-config",
    configResolved(config) {
      if (config.mode === "production" || config.command === "build") {
        const apiUrl = process.env.VITE_API_URL;
        if (apiUrl) {
          const trimmed = apiUrl.trim();
          try {
            const parsed = new URL(trimmed);
            if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
              throw new Error(
                `[BUILD ERROR] VITE_API_URL is configured as "${trimmed}". Production builds cannot target localhost endpoints.`
              );
            }
            if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
              throw new Error(
                `[BUILD ERROR] VITE_API_URL must use HTTP or HTTPS protocol, got "${parsed.protocol}".`
              );
            }
          } catch (e: any) {
            if (e.message.startsWith("[BUILD ERROR]")) {
              throw e;
            }
            throw new Error(`[BUILD ERROR] Malformed VITE_API_URL "${trimmed}": ${e.message}`);
          }
        }
      }
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  base: "/xerox-cybersecurity-platform/",
  plugins: [react(), spaFallbackPlugin(), productionConfigValidationPlugin()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    port: 4173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
