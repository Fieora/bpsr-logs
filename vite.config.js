import devtoolsJson from "vite-plugin-devtools-json";
import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [sveltekit(), devtoolsJson()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: false,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { // 3. tell vite to ignore watching `src-tauri`
    ignored: ["**/src-tauri/**"] }
  }
}));
