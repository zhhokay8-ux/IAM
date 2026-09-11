import { expect, test } from "@playwright/test";
import { adminMe, mockAdminApi } from "./mock";

test("admin login page does not store tokens", async ({ page }) => {
  await page.route("**/api/admin/me", (route) =>
    route.fulfill({ status: 401, json: { code: "IAM-4010", message: "Unauthorized", traceId: "t" } })
  );
  await page.goto("/admin/login");
  await expect(page.getByTestId("sign-in")).toBeVisible();
  const ls = await page.evaluate(() => Object.keys(localStorage));
  expect(ls).toEqual([]);
});

test("dashboard charts load from existing admin API", async ({ page }) => {
  await mockAdminApi(page);
  await page.goto("/admin/dashboard");
  await expect(page.getByTestId("user-menu")).toContainText(adminMe.username);
  await expect(page.getByTestId("trend-chart")).toBeVisible();
});

test("client create shows one-time secret confirmation", async ({ page }) => {
  await mockAdminApi(page);
  await page.goto("/admin/clients");
  await page.getByTestId("create-client").click();
  await page.getByTestId("client-id").fill("new-app");
  await page.getByTestId("submit-client").click();
  await expect(page.getByTestId("one-time-secret")).toHaveText("one-time-secret");
  await page.getByTestId("secret-ack").click();
  await page.getByTestId("secret-done").click();
});

test("client disable and rotate secret", async ({ page }) => {
  await mockAdminApi(page);
  await page.goto("/admin/clients/portal");
  await page.getByTestId("disable-client").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();
  await page.getByTestId("rotate-secret").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();
  await expect(page.getByText("rotated-secret")).toBeVisible();
});

test("resource create and permission change", async ({ page }) => {
  await mockAdminApi(page);
  await page.goto("/admin/resources");
  await page.getByTestId("create-resource").click();
  await page.getByTestId("resource-code").fill("RS1");
  await page.getByTestId("submit-resource").click();
  await page.goto("/admin/permissions");
  await page.getByTestId("save-permissions").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();
});

test("user disable session revoke token revoke audit key rotate logout", async ({ page }) => {
  await mockAdminApi(page);
  await page.goto("/admin/users/" + adminMe.subjectId);
  await page.getByTestId("disable-user").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();

  await page.goto("/admin/sessions");
  await page.getByPlaceholder("subject_id (required)").fill(adminMe.subjectId);
  await page.getByRole("button", { name: "Load" }).click();
  await page.getByTestId("revoke-session").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();

  await page.goto("/admin/tokens");
  await expect(page.getByText("Token 是敏感数据")).toBeVisible();
  await page.getByTestId("token-input").fill("eyJhbGciOi.secret");
  await page.getByTestId("revoke-token").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();

  await page.goto("/admin/audit");
  await page.getByTestId("audit-search").click();
  await expect(page.locator(".el-table").getByText("CLIENT_DISABLED")).toBeVisible();

  await page.goto("/admin/signing-keys");
  await page.getByTestId("rotate-key").click();
  await page.getByRole("button", { name: "Yes", exact: true }).click();

  await page.getByTestId("user-menu").click();
  await page.getByTestId("logout").click();
  await expect(page.getByTestId("sign-in")).toBeVisible();
});
