import { describe, it, expect } from "vitest";
import { safeReturnTo } from "@/features/auth/utils/safeReturnTo";

describe("safeReturnTo", () => {
  it.each([
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "/a\n",
    "x",
    "/" + "x".repeat(2048),
    null,
  ])("refuses unsafe navigation", (value) => {
    expect(safeReturnTo(value)).toBe("/");
  });
  it("preserves pathname and search", () => {
    expect(safeReturnTo("/bucket?path=a%2Fb")).toBe("/bucket?path=a%2Fb");
  });
});
