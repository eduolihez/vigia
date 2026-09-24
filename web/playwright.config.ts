import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3000",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // In CI the server is started and torn down by the workflow itself (see
  // .github/workflows/ci.yml): Playwright's own webServer teardown sends
  // SIGTERM through `corepack pnpm run start`, which does not reliably
  // propagate to the underlying `next-server` child process on the Actions
  // Ubuntu runner, so the job hangs waiting for a process that never exits.
  webServer: process.env.CI
    ? undefined
    : {
        command: "corepack pnpm run start",
        url: "http://127.0.0.1:3000",
        reuseExistingServer: true,
        timeout: 60_000,
      },
});
