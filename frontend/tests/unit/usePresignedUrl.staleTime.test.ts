import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";
import { presignedStaleTime } from "@/features/files/hooks/usePresignedUrl";

describe("presignedStaleTime", () => {
  beforeEach(() => vi.setSystemTime(new Date("2026-06-11T12:00:00Z")));
  afterEach(() => vi.useRealTimers());

  it("returns ~80% of the remaining lifetime", () => {
    const expiresAt = "2026-06-11T13:00:00Z"; // 1h remaining
    const ms = presignedStaleTime(expiresAt);
    expect(ms).toBeGreaterThan(47 * 60 * 1000);
    expect(ms).toBeLessThan(49 * 60 * 1000);
  });

  it("floors at 30s for nearly-expired URLs", () => {
    const expiresAt = "2026-06-11T12:00:05Z"; // 5s left
    expect(presignedStaleTime(expiresAt)).toBe(30_000);
  });

  it("floors at 30s for already-expired URLs", () => {
    const expiresAt = "2026-06-11T11:00:00Z"; // past
    expect(presignedStaleTime(expiresAt)).toBe(30_000);
  });

  it("returns the floor when expires_at is missing/invalid", () => {
    expect(presignedStaleTime(undefined)).toBe(30_000);
    expect(presignedStaleTime("not-a-date")).toBe(30_000);
  });
});
