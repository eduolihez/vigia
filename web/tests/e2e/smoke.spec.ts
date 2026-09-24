/**
 * Playwright smoke test (brief Phase 5 acceptance criterion). Runs against the
 * built Next.js app — every API call is mocked via route interception rather than
 * left to hit a real (or refused) backend connection: a real CI runner was observed
 * to hang indefinitely on a connection-refused fetch to localhost:8000 (reproducible
 * in GitHub Actions, not reproducible locally via curl or a normal browser — some
 * environments silently drop the packets instead of sending RST, so the OS-level
 * connect() never returns). Mocking removes that variable entirely: these tests
 * check that the pages render, navigate, and use real API response shapes
 * correctly — not real backend integration, which needs Ollama and is verified
 * manually (see CLAUDE.md).
 */

import { expect, test, type Page } from "@playwright/test";

const API_ORIGIN = "http://localhost:8000";

async function mockApi(page: Page) {
  await page.route(`${API_ORIGIN}/scans`, (route) => route.fulfill({ json: [] }));
  await page.route(`${API_ORIGIN}/ethics`, (route) =>
    route.fulfill({ json: { accepted: true, notice: "test notice" } }),
  );
}

test("dashboard loads and shows the nav + heading", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Vigía" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("link", { name: "New scan" })).toBeVisible();
});

test("dashboard shows the empty state with no scans", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByText("No scans yet.")).toBeVisible();
});

test("navigating to New scan shows the form", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await page.getByRole("navigation").getByRole("link", { name: "New scan" }).click();
  await expect(page).toHaveURL(/\/scans\/new$/);
  await expect(page.getByRole("heading", { name: "New scan" })).toBeVisible();
});

test("new scan form is enabled once the ethics notice is accepted", async ({ page }) => {
  await mockApi(page);
  await page.goto("/scans/new");
  await expect(page.getByLabel("Target domain")).toBeEnabled();
  await expect(page.getByRole("button", { name: "Start passive scan" })).toBeVisible();
});

test("nav links move between dashboard and new-scan", async ({ page }) => {
  await mockApi(page);
  await page.goto("/scans/new");
  await page.getByRole("navigation").getByRole("link", { name: "Dashboard" }).click();
  await expect(page).toHaveURL("http://127.0.0.1:3000/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});

test("a findings page for an unknown scan id renders without crashing", async ({ page }) => {
  // Scoped to the API's own origin (127.0.0.1:8000), not "**/scans/*/findings" —
  // that broader glob also matches this test's own page navigation
  // (127.0.0.1:3000/scans/does-not-exist/findings) and replaces the HTML page
  // itself with the mocked JSON, which is not what's being tested here.
  await page.route(`${API_ORIGIN}/scans/*/findings`, (route) => route.fulfill({ json: [] }));
  await page.goto("/scans/does-not-exist/findings");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
});
