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

test("selecting active mode shows the verification token after creating a scan", async ({
  page,
}) => {
  await mockApi(page);
  await page.route(`${API_ORIGIN}/scans`, (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        status: 201,
        json: {
          id: "scan-active-1",
          domain: "example.com",
          status: "pending",
          mode: "active",
          verification_token: "vigia-verify=abc123",
        },
      });
    }
    return route.fulfill({ json: [] });
  });
  // The live page fetches the scan's own status on mount (ADR-020) — mock it too,
  // scoped to the API's own origin, so navigating there doesn't hit a real backend.
  await page.route(`${API_ORIGIN}/scans/scan-active-1`, (route) =>
    route.fulfill({
      json: {
        id: "scan-active-1",
        domain: "example.com",
        mode: "active",
        status: "pending",
        verified: false,
        verification_token: "vigia-verify=abc123",
        started_at: null,
        finished_at: null,
        findings_count: 0,
        max_severity: null,
      },
    }),
  );
  // The live page also opens an EventSource to the stream endpoint — mock it too
  // so it doesn't hang waiting for a real backend connection.
  await page.route(`${API_ORIGIN}/scans/scan-active-1/stream`, (route) =>
    route.fulfill({ status: 200, contentType: "text/event-stream", body: "" }),
  );

  await page.goto("/scans/new");
  await page.getByLabel("Target domain").fill("example.com");
  await page.getByLabel("Active (requires domain ownership verification)").check();
  await page.getByRole("button", { name: "Create active scan" }).click();

  await expect(page.getByRole("heading", { name: "Verify domain ownership" })).toBeVisible();
  await expect(page.getByText("vigia-verify=abc123")).toBeVisible();
  await page.getByRole("button", { name: "I've published it — continue" }).click();
  await expect(page).toHaveURL(/\/scans\/scan-active-1\/live$/);
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

test("an audit page for an unknown scan id renders without crashing", async ({ page }) => {
  await page.route(`${API_ORIGIN}/scans/*/audit`, (route) =>
    route.fulfill({ status: 404, json: { detail: "No tool calls found for this scan id" } }),
  );
  await page.goto("/scans/does-not-exist/audit");
  await expect(page.getByRole("heading", { name: "Audit log" })).toBeVisible();
  await expect(page.getByText("No tool calls recorded for this scan yet.")).toBeVisible();
});

test("a graph page for an unknown scan id renders without crashing", async ({ page }) => {
  await page.route(`${API_ORIGIN}/scans/*/assets`, (route) => route.fulfill({ json: [] }));
  await page.route(`${API_ORIGIN}/scans/*/findings`, (route) => route.fulfill({ json: [] }));
  await page.goto("/scans/does-not-exist/graph");
  await expect(page.getByRole("heading", { name: "Asset graph" })).toBeVisible();
  await expect(page.getByText("No assets discovered yet for this scan.")).toBeVisible();
});

test("a report page shows the generate button without any API calls", async ({ page }) => {
  await page.goto("/scans/does-not-exist/report");
  await expect(page.getByRole("heading", { name: "Report" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Generate report" })).toBeVisible();
});

test("the scan sub-nav links to findings/report/graph/audit", async ({ page }) => {
  await page.route(`${API_ORIGIN}/scans/*/findings`, (route) => route.fulfill({ json: [] }));
  await page.goto("/scans/does-not-exist/findings");
  const subNav = page.getByRole("navigation").nth(1);
  await expect(subNav.getByRole("link", { name: "View report" })).toBeVisible();
  await expect(subNav.getByRole("link", { name: "View graph" })).toBeVisible();
  await expect(subNav.getByRole("link", { name: "View audit log" })).toBeVisible();
});

test("navigating to Settings shows the settings page", async ({ page }) => {
  await mockApi(page);
  await page.route(`${API_ORIGIN}/settings`, (route) =>
    route.fulfill({
      json: {
        planner_model: "qwen3.6:35b",
        extractor_model: "granite4.1:8b",
        scan_max_steps: 60,
        scan_max_minutes: 20,
        scan_max_deep_dives: 5,
        configured_api_keys: {
          censys_api_id: false,
          censys_api_secret: false,
          github_token: true,
          hibp_api_key: false,
        },
      },
    }),
  );
  await page.goto("/");
  await page.getByRole("navigation").getByRole("link", { name: "Settings" }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await expect(page.getByLabel("Planner model")).toHaveValue("qwen3.6:35b");
  await expect(page.getByText("Configured", { exact: true })).toBeVisible();
});

test("the locale switcher changes the dashboard to Spanish", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.getByLabel("Language").selectOption("es");
  await expect(page.getByRole("heading", { name: "Panel" })).toBeVisible();
});
