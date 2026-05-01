import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatDate } from "@/utils/formatDate";

describe("formatDate", () => {
  beforeEach(() => {
    // Freeze "now" to 2026-04-30T12:00:00Z for relative-time tests
    vi.setSystemTime(new Date("2026-04-30T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("formats less than a minute ago", () => {
    expect(formatDate("2026-04-30T11:59:30Z")).toBe("just now");
  });

  it("formats minutes ago", () => {
    expect(formatDate("2026-04-30T11:55:00Z")).toBe("5 minutes ago");
    expect(formatDate("2026-04-30T11:59:00Z")).toBe("1 minute ago");
  });

  it("formats hours ago", () => {
    expect(formatDate("2026-04-30T10:00:00Z")).toBe("2 hours ago");
    expect(formatDate("2026-04-30T11:00:00Z")).toBe("1 hour ago");
  });

  it("formats days ago when within a week", () => {
    expect(formatDate("2026-04-28T12:00:00Z")).toBe("2 days ago");
    expect(formatDate("2026-04-29T12:00:00Z")).toBe("1 day ago");
  });

  it("formats absolute date when older than 7 days", () => {
    // > 7 days → "Apr 22, 2026" style
    const result = formatDate("2026-04-22T12:00:00Z");
    expect(result).toMatch(/Apr 22, 2026/);
  });
});
