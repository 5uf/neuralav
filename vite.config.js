import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [solidPlugin()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
  },
  // 3. to make use of `TAURI_ENV_DEBUG` and other env variables
  // https://v2.tauri.app/reference/environment-variables/
  envPrefix: ["VITE_", "TAURI_ENV_"],
}));
