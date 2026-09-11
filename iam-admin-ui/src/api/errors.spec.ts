import { describe, expect, it } from "vitest";
import { parseApiError, userMessage } from "./errors";
import { can, P } from "../permissions";

describe("ApiErrorResponse mapping", () => {
  it("reads backend code and traceId instead of assuming {code:0,data:{}}", () => {
    const err = parseApiError(403, { traceId: "tr-1", code: "IAM-4081", message: "Admin permission denied" });
    expect(err.code).toBe("IAM-4081");
    expect(err.traceId).toBe("tr-1");
    expect(userMessage(err)).toContain("无权限");
  });

  it("maps 409 and 500", () => {
    expect(userMessage(parseApiError(409, { code: "IAM-4091", message: "duplicate" }))).toContain("冲突");
    expect(userMessage(parseApiError(500, { code: "IAM-5000", message: "Internal server error" }))).toContain("系统异常");
  });
});

describe("RBAC helper", () => {
  it("hides by permission set without treating UI as security", () => {
    expect(can(["admin.client.read"], P.CLIENT_WRITE)).toBe(false);
    expect(can(["admin.client.write"], P.CLIENT_WRITE)).toBe(true);
  });
});
