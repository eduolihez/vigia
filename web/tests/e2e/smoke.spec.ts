/**
 * Playwright smoke test (brief Phase 5 acceptance criterion). Runs against the
 * built Next.js app with NO backend running — CI has no Ollama/API to talk to, so
 * these tests only assert the pages themselves render and navigate without
 * crashing. Full scan-launched-and-followed-from-the-UI behavior (including the
 * "API unreachable" error banner, verified manually to appear within a few
 * seconds) is checked against a real local Ollama instance — see CLAUDE.md. A
 * headless Playwright browser was observed to hang indefinitely on the initial
 * fetch to a refused connection in this environment (not reproducible via curl or
 * a normal browser), so no test here depends on that fetch settling.
 */

import { expect, test } from "@playwright/test";

test("dashboard loads and shows the nav + heading", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Vigía" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("link", { name: "New scan" })).toBeVisible();
});

test("navigating to New scan shows the form", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("navigation").getByRole("link", { name: "New scan" }).click();
  await expect(page).toHaveURL(/\/scans\/new$/);
  await expect(page.getByRole("heading", { name: "New scan" })).toBeVisible();
});

test("new scan form's domain field is present", async ({ page }) => {
  await page.goto("/scans/new");
  await expect(page.getByLabel("Target domain")).toBeVisible();
  await expect(page.getByRole("button", { name: "Start passive scan" })).toBeVisible();
});

test("nav links move between dashboard and new-scan", async ({ page }) => {
  await page.goto("/scans/new");
  await page.getByRole("navigation").getByRole("link", { name: "Dashboard" }).click();
  await expect(page).toHaveURL("http://127.0.0.1:3000/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});

test("a findings page for an unknown scan id renders without crashing", async ({ page }) => {
  await page.goto("/scans/does-not-exist/findings");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
});
