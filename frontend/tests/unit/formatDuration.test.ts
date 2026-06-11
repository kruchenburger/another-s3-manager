import { describe, expect, it } from "vitest";
import { formatDuration } from "@/utils/formatDuration";

describe("formatDuration", () => {
  it("formats minutes", () => {
    expect(formatDuration(60)).toBe("1 minute");
    expect(formatDuration(300)).toBe("5 minutes");
    expect(formatDuration(900)).toBe("15 minutes");
  });

  it("formats hours", () => {
    expect(formatDuration(3600)).toBe("1 hour");
    expect(formatDuration(21600)).toBe("6 hours");
    expect(formatDuration(43200)).toBe("12 hours");
  });

  it("formats days", () => {
    expect(formatDuration(86400)).toBe("1 day");
    expect(formatDuration(259200)).toBe("3 days");
    expect(formatDuration(604800)).toBe("7 days");
  });
});
