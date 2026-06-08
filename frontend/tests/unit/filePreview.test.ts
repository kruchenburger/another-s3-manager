import { describe, it, expect } from "vitest";
import { getPreviewType } from "@/utils/filePreview";

describe("getPreviewType", () => {
  it("recognises media regardless of the list (even empty)", () => {
    expect(getPreviewType("a.png", [])).toBe("image");
    expect(getPreviewType("a.JPG", [])).toBe("image");
    expect(getPreviewType("a.mp4", [])).toBe("video");
    expect(getPreviewType("a.pdf", [])).toBe("pdf");
  });

  it("text preview is purely list-driven", () => {
    // In the list -> text.
    expect(getPreviewType("a.txt", ["txt", "md"])).toBe("text");
    expect(getPreviewType("a.md", ["txt", "md"])).toBe("text");
    expect(getPreviewType("a.ts", ["ts"])).toBe("text");
    // Not in the list -> no text preview (the list is the single source of truth).
    expect(getPreviewType("a.json", ["txt"])).toBe(null);
  });

  it("an empty list disables ALL text preview (admin cleared it)", () => {
    expect(getPreviewType("a.txt", [])).toBe(null);
    expect(getPreviewType("a.md", [])).toBe(null);
    // ...but media still previews, independent of the list.
    expect(getPreviewType("a.png", [])).toBe("image");
  });

  it("media always wins even when its ext is also in the list", () => {
    expect(getPreviewType("a.png", ["png", "ts"])).toBe("image");
    expect(getPreviewType("a.pdf", ["pdf"])).toBe("pdf");
  });

  it("returns null for unknown and extensionless names", () => {
    expect(getPreviewType("a.bin", ["txt"])).toBe(null);
    expect(getPreviewType("noext", ["txt"])).toBe(null);
  });

  it("normalises case", () => {
    expect(getPreviewType("FILE.TS", ["ts"])).toBe("text");
  });
});
