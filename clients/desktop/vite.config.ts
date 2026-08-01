import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Tauri serves the built assets from disk; relative paths keep it portable.
  base: "./",
  build: { outDir: "dist", emptyOutDir: true, target: "es2021" },
  server: { port: 1420, strictPort: true },
  test: { environment: "jsdom", globals: true },
});
