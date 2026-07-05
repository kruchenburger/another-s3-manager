import { describe, expect, it } from "vitest";
import { ApiError, getErrorCode, getErrorMessage } from "@/utils/apiError";

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

describe("getErrorMessage", () => {
  it("reads structured dict detail (PR1 shape)", () => {
    const err = new ApiError(400, "Bad Request", {
      detail: { code: "InvalidRegion", message: "Region is invalid for R2" },
    });
    expect(getErrorMessage(err)).toBe("Region is invalid for R2");
  });

  it("reads legacy string detail", () => {
    const err = new ApiError(403, "Forbidden", { detail: "Cannot list buckets" });
    expect(getErrorMessage(err)).toBe("Cannot list buckets");
  });

  it("falls back to ApiError.message when body has no detail", () => {
    const err = new ApiError(500, "Internal Server Error", {});
    expect(getErrorMessage(err)).toBe("Internal Server Error");
  });

  it("prepends the HTTP status when only statusText is available", () => {
    const err = new ApiError(502, "Bad Gateway");
    expect(getErrorMessage(err)).toBe("502 Bad Gateway");
  });

  it("treats TypeError (fetch network failure) as a friendly app-unreachable message", () => {
    const err = new TypeError("Failed to fetch");
    expect(getErrorMessage(err)).toBe(
      "The app isn't responding right now. Try refreshing the page, or contact your admin if this keeps happening.",
    );
  });

  it("returns the message for generic Error", () => {
    expect(getErrorMessage(new Error("oops"))).toBe("oops");
  });

  it("returns 'Unknown error' for null / undefined / non-error values", () => {
    expect(getErrorMessage(null)).toBe("Unknown error");
    expect(getErrorMessage(undefined)).toBe("Unknown error");
    expect(getErrorMessage(42)).toBe("Unknown error");
  });

  it("ignores a dict detail that has no message field", () => {
    const err = new ApiError(400, "Bad Request", {
      detail: { code: "Whatever" },
    });
    // Falls back to the ApiError.message since detail.message is missing.
    expect(getErrorMessage(err)).toBe("Bad Request");
  });
});

describe("getErrorCode", () => {
  it("returns the code from a dict-shape detail", () => {
    const err = new ApiError(400, "Bad Request", {
      detail: { code: "InvalidRegion", message: "x" },
    });
    expect(getErrorCode(err)).toBe("InvalidRegion");
  });

  it("returns null for string detail", () => {
    const err = new ApiError(403, "Forbidden", { detail: "Cannot list" });
    expect(getErrorCode(err)).toBeNull();
  });

  it("returns null for non-ApiError", () => {
    expect(getErrorCode(new Error("x"))).toBeNull();
    expect(getErrorCode(null)).toBeNull();
  });

  it("returns null when detail is dict without code", () => {
    const err = new ApiError(400, "Bad Request", {
      detail: { message: "no code here" },
    });
    expect(getErrorCode(err)).toBeNull();
  });
});
