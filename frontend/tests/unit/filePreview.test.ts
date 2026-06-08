import { describe, it, expect } from "vitest";
import { getPreviewType } from "@/utils/filePreview";

describe("getPreviewType", () => {
  it("recognises media regardless of the admin list (empty list)", () => {
    expect(getPreviewType("a.png", [])).toBe("image");
    expect(getPreviewType("a.JPG", [])).toBe("image");
    expect(getPreviewType("a.mp4", [])).toBe("video");
    expect(getPreviewType("a.pdf", [])).toBe("pdf");
  });

  it("previews the built-in default text extensions (empty admin list)", () => {
    expect(getPreviewType("a.txt", [])).toBe("text");
    expect(getPreviewType("a.md", [])).toBe("text");
    expect(getPreviewType("a.json", [])).toBe("text");
  });

  it("admin list ADDS to the defaults rather than replacing them (union)", () => {
    // Admin custom extensions become previewable...
    expect(getPreviewType("a.ts", ["ts", "tsx"])).toBe("text");
    expect(getPreviewType("a.tsx", ["ts", "tsx"])).toBe("text");
    // ...and the built-in defaults STAY previewable even with a non-empty list
    // (the old "replace" behaviour hid them — bad UX).
    expect(getPreviewType("a.md", ["ts", "tsx"])).toBe("text");
    expect(getPreviewType("a.txt", ["ts", "tsx"])).toBe("text");
    // Still null for something in neither set.
    expect(getPreviewType("a.bin", ["ts", "tsx"])).toBe(null);
  });

  it("media always wins even when the admin list is non-empty", () => {
    expect(getPreviewType("a.png", ["ts"])).toBe("image");
    expect(getPreviewType("a.pdf", ["ts"])).toBe("pdf");
  });

  it("returns null for unknown, extensionless, and directory-like names", () => {
    expect(getPreviewType("a.bin", [])).toBe(null);
    expect(getPreviewType("noext", [])).toBe(null);
    expect(getPreviewType("a.exe", ["ts"])).toBe(null);
  });

  it("normalises case", () => {
    expect(getPreviewType("FILE.TS", ["ts"])).toBe("text");
  });
});
