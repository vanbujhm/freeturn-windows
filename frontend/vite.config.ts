import { writeFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

// Сборка идёт в dist: эту папку встраивает frontend/embed.go. Сборка очищает dist, а
// .gitkeep в git отслеживается, поэтому плагин возвращает его после сборки.
export default defineConfig({
  build: { outDir: "dist", emptyOutDir: true },
  test: { include: ["src/**/*.test.ts"], environment: "node" },
  plugins: [
    {
      name: "keep-gitkeep",
      closeBundle() {
        writeFileSync("dist/.gitkeep", "");
      },
    },
  ],
});
