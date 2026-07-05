import { afterEach, describe, expect, it } from "vitest";
import { getCsrfToken, setCsrfToken, clearCsrfToken } from "@/utils/csrf";

describe("csrf token storage", () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  it("returns null when no token stored", () => {
    expect(getCsrfToken()).toBeNull();
  });

  it("roundtrips set → get", () => {
    setCsrfToken("abc-123");
    expect(getCsrfToken()).toBe("abc-123");
  });

  it("clearCsrfToken removes the stored value", () => {
    setCsrfToken("abc-123");
    clearCsrfToken();
    expect(getCsrfToken()).toBeNull();
  });
});
