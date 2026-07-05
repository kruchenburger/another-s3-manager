import { describe, expect, it } from "vitest";
import { Braces, File, FileText, Folder, Image, Package } from "lucide-react";
import { getFileIcon } from "@/utils/fileIcon";

describe("getFileIcon", () => {
  it("maps known extensions to icon + tint", () => {
    expect(getFileIcon("photo.png", false).Icon).toBe(Image);
    expect(getFileIcon("photo.png", false).color).toBe("var(--mantine-color-teal-5)");
    expect(getFileIcon("config.json", false).Icon).toBe(Braces);
    expect(getFileIcon("backup.tar.gz", false).Icon).toBe(Package); // last segment wins
    expect(getFileIcon("backup.tar.gz", false).color).toBe("var(--mantine-color-indigo-4)");
  });

  it("is case-insensitive", () => {
    expect(getFileIcon("PHOTO.PNG", false).Icon).toBe(Image);
  });

  it("text files get FileText with no tint", () => {
    const spec = getFileIcon("notes.md", false);
    expect(spec.Icon).toBe(FileText);
    expect(spec.color).toBeUndefined();
  });

  it("unknown extension and extension-less names fall back to neutral File", () => {
    expect(getFileIcon("archive.xyz", false).Icon).toBe(File);
    expect(getFileIcon("README", false).Icon).toBe(File);
    expect(getFileIcon(".env", false).Icon).toBe(File);
    expect(getFileIcon("archive.xyz", false).color).toBe("var(--mantine-color-slate-5)");
  });

  it("directories always get the accent Folder regardless of name", () => {
    const spec = getFileIcon("photo.png", true);
    expect(spec.Icon).toBe(Folder);
    expect(spec.color).toBe("var(--mantine-color-mutedSlateBlue-6)");
  });
});
