import { describe, expect, it } from "vitest";
import { ApiError } from "@/utils/apiError";

describe("ApiError", () => {
  it("captures status, detail, and response body", () => {
    const err = new ApiError(401, "Unauthorized", { detail: "Bad token" });
    expect(err.status).toBe(401);
    expect(err.message).toBe("Unauthorized");
    expect(err.body).toEqual({ detail: "Bad token" });
    expect(err).toBeInstanceOf(Error);
  });

  it("isAuthError() true for 401, false for others", () => {
    expect(new ApiError(401, "x").isAuthError()).toBe(true);
    expect(new ApiError(403, "x").isAuthError()).toBe(false);
    expect(new ApiError(500, "x").isAuthError()).toBe(false);
  });
});
