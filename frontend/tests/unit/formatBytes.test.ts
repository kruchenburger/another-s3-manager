import { describe, expect, it } from "vitest";
import { formatBytes } from "@/utils/formatBytes";

describe("formatBytes", () => {
  it("returns 0 B for 0", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("formats bytes under 1 KB", () => {
    expect(formatBytes(512)).toBe("512 B");
  });

  it("formats KB", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("formats MB", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(2.5 * 1024 * 1024)).toBe("2.5 MB");
  });

  it("formats GB", () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.0 GB");
  });

  it("rounds to 1 decimal", () => {
    expect(formatBytes(1234567)).toBe("1.2 MB");
  });
});
