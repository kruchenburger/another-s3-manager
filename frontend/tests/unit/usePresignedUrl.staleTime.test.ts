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

  it("returns 80% of the remaining time for a nearly-expired URL (no floor)", () => {
    const expiresAt = "2026-06-11T12:00:05Z"; // 5s left → 4s fresh
    expect(presignedStaleTime(expiresAt)).toBe(4_000);
  });

  it("returns 0 for an already-expired URL (immediately stale)", () => {
    const expiresAt = "2026-06-11T11:00:00Z"; // past
    expect(presignedStaleTime(expiresAt)).toBe(0);
  });

  it("returns 0 when expires_at is missing/invalid", () => {
    expect(presignedStaleTime(undefined)).toBe(0);
    expect(presignedStaleTime("not-a-date")).toBe(0);
  });
});
