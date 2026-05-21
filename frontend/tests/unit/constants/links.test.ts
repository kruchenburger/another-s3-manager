import { describe, it, expect } from "vitest";
import { GITHUB_URL } from "@/constants/links";

describe("GITHUB_URL", () => {
  it("points at the another-s3-manager repository on github.com", () => {
    expect(GITHUB_URL).toBe("https://github.com/kruchenburger/another-s3-manager");
  });

  it("is an https URL (so target=_blank rel=noopener is meaningful)", () => {
    expect(GITHUB_URL.startsWith("https://")).toBe(true);
  });
});
