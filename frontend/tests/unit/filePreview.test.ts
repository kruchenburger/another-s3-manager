import { describe, it, expect } from "vitest";
import { getPreviewType } from "@/utils/filePreview";

describe("getPreviewType", () => {
  it("recognises media regardless of the admin list (empty list)", () => {
    expect(getPreviewType("a.png", [])).toBe("image");
    expect(getPreviewType("a.JPG", [])).toBe("image");
    expect(getPreviewType("a.mp4", [])).toBe("video");
    expect(getPreviewType("a.pdf", [])).toBe("pdf");
  });

  it("falls back to default text extensions when the admin list is empty", () => {
    expect(getPreviewType("a.txt", [])).toBe("text");
    expect(getPreviewType("a.md", [])).toBe("text");
    expect(getPreviewType("a.json", [])).toBe("text");
  });

  it("uses the admin list for text when it is non-empty", () => {
    expect(getPreviewType("a.ts", ["ts", "tsx"])).toBe("text");
    expect(getPreviewType("a.tsx", ["ts", "tsx"])).toBe("text");
    expect(getPreviewType("a.md", ["ts", "tsx"])).toBe(null);
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
