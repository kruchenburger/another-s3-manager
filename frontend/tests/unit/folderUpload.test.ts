import { describe, it, expect } from "vitest";
import { expandDirectoryEntries, filesFromFolderInput } from "@/utils/folderUpload";

// --- Test doubles for the FileSystemEntry API ---
// jsdom does not implement FileSystemEntry / DirectoryReader. The walker only
// touches: entry.isFile, entry.isDirectory, entry.name, entry.file(cb) (for
// files), entry.createReader().readEntries(cb) (for directories). We mock just
// that surface.

interface FakeFileEntry {
  isFile: true;
  isDirectory: false;
  name: string;
  file: (cb: (f: File) => void) => void;
}

interface FakeDirEntry {
  isFile: false;
  isDirectory: true;
  name: string;
  createReader: () => {
    readEntries: (cb: (entries: Array<FakeFileEntry | FakeDirEntry>) => void) => void;
  };
}

function fakeFileEntry(name: string, body = "x"): FakeFileEntry {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (cb) => {
      cb(new File([body], name));
    },
  };
}

function fakeDirEntry(
  name: string,
  children: Array<FakeFileEntry | FakeDirEntry>,
  // Optional: when set > 1, readEntries returns children in chunks to simulate
  // the real API which paginates. The walker MUST call readEntries until it
  // returns an empty array.
  pageSize?: number,
): FakeDirEntry {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader: () => {
      const remaining = [...children];
      const size = pageSize ?? remaining.length;
      return {
        readEntries: (cb) => {
          const chunk = remaining.splice(0, size);
          cb(chunk);
        },
      };
    },
  };
}

function fakeDataTransferItem(entry: FakeFileEntry | FakeDirEntry) {
  return {
    kind: "file" as const,
    webkitGetAsEntry: () => entry,
  };
}

describe("expandDirectoryEntries", () => {
  it("returns a single file entry as one item with relativePath = name", async () => {
    const items = [fakeDataTransferItem(fakeFileEntry("hello.txt"))];
    const result = await expandDirectoryEntries(items as unknown as DataTransferItem[]);
    expect(result).toHaveLength(1);
    expect(result[0].relativePath).toBe("hello.txt");
    expect(result[0].file.name).toBe("hello.txt");
  });

  it("walks a flat folder one level deep", async () => {
    const folder = fakeDirEntry("docs", [
      fakeFileEntry("a.txt"),
      fakeFileEntry("b.txt"),
    ]);
    const result = await expandDirectoryEntries([fakeDataTransferItem(folder)] as unknown as DataTransferItem[]);
    expect(result.map((r) => r.relativePath).sort()).toEqual(["docs/a.txt", "docs/b.txt"]);
  });

  it("recurses into nested folders preserving the full relative path", async () => {
    const inner = fakeDirEntry("sub", [fakeFileEntry("deep.txt")]);
    const outer = fakeDirEntry("docs", [fakeFileEntry("top.txt"), inner]);
    const result = await expandDirectoryEntries([fakeDataTransferItem(outer)] as unknown as DataTransferItem[]);
    expect(result.map((r) => r.relativePath).sort()).toEqual(["docs/sub/deep.txt", "docs/top.txt"]);
  });

  it("handles paginated readEntries (real API returns batches)", async () => {
    // 25 files paginated 10 at a time — walker must drain by re-calling
    // readEntries until it returns []. If the walker reads only one page,
    // we'd see 10 files; if it correctly drains, we see 25.
    const children = Array.from({ length: 25 }, (_, i) => fakeFileEntry(`f${i}.txt`));
    const folder = fakeDirEntry("big", children, 10);
    const result = await expandDirectoryEntries([fakeDataTransferItem(folder)] as unknown as DataTransferItem[]);
    expect(result).toHaveLength(25);
  });

  it("skips DataTransferItems whose kind is not 'file'", async () => {
    const stringItem = { kind: "string" as const, webkitGetAsEntry: () => null };
    const fileItem = fakeDataTransferItem(fakeFileEntry("ok.txt"));
    const result = await expandDirectoryEntries([stringItem, fileItem] as unknown as DataTransferItem[]);
    expect(result).toHaveLength(1);
    expect(result[0].relativePath).toBe("ok.txt");
  });

  it("falls back gracefully when webkitGetAsEntry returns null (legacy browser)", async () => {
    // Some browsers expose `kind: "file"` items whose webkitGetAsEntry()
    // returns null (older Safari, some mobile WebViews). The walker should
    // try getAsFile() and treat it as a top-level file.
    const file = new File(["x"], "legacy.txt");
    const legacyItem = {
      kind: "file" as const,
      webkitGetAsEntry: () => null,
      getAsFile: () => file,
    };
    const result = await expandDirectoryEntries([legacyItem] as unknown as DataTransferItem[]);
    expect(result).toHaveLength(1);
    expect(result[0].file).toBe(file);
    expect(result[0].relativePath).toBe("legacy.txt");
  });

  it("returns an empty array when an empty folder is dropped", async () => {
    const empty = fakeDirEntry("empty", []);
    const result = await expandDirectoryEntries([fakeDataTransferItem(empty)] as unknown as DataTransferItem[]);
    expect(result).toEqual([]);
  });
});

describe("filesFromFolderInput", () => {
  it("projects webkitRelativePath onto FileWithRelativePath", () => {
    // Create File objects and assign webkitRelativePath via Object.defineProperty
    // (it's a read-only property; tests must define it explicitly).
    const f1 = new File(["a"], "a.txt");
    Object.defineProperty(f1, "webkitRelativePath", { value: "docs/a.txt" });
    const f2 = new File(["b"], "b.txt");
    Object.defineProperty(f2, "webkitRelativePath", { value: "docs/sub/b.txt" });

    // Build a FileList-like object. The function only iterates it, so an
    // array works for the test.
    const result = filesFromFolderInput([f1, f2] as unknown as FileList);
    expect(result.map((r) => r.relativePath).sort()).toEqual(["docs/a.txt", "docs/sub/b.txt"]);
  });

  it("falls back to file.name when webkitRelativePath is empty", () => {
    // Older browsers / non-folder inputs leave webkitRelativePath as "".
    const f = new File(["x"], "plain.txt");
    // No defineProperty: default is "" per the spec.
    const result = filesFromFolderInput([f] as unknown as FileList);
    expect(result).toHaveLength(1);
    expect(result[0].relativePath).toBe("plain.txt");
  });
});
