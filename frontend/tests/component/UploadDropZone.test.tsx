import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { UploadDropZone } from "@/components/Upload/UploadDropZone";

// --- Drag-drop event helpers ---

interface FakeEntry {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  file?: (cb: (f: File) => void) => void;
  createReader?: () => { readEntries: (cb: (es: FakeEntry[]) => void) => void };
}

function fileEntry(name: string): FakeEntry {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (cb) => cb(new File(["x"], name)),
  };
}

function dirEntry(name: string, children: FakeEntry[]): FakeEntry {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader: () => {
      let drained = false;
      return {
        readEntries: (cb) => {
          if (drained) {
            cb([]);
          } else {
            drained = true;
            cb(children);
          }
        },
      };
    },
  };
}

function dragEvent(name: string, entries: FakeEntry[]) {
  // window.dispatchEvent goes through the type=string overload; we use a
  // CustomEvent-shaped object with the dataTransfer property the handler reads.
  const items = entries.map((entry) => ({
    kind: "file" as const,
    webkitGetAsEntry: () => entry,
    getAsFile: () => null,
  }));
  const event = new Event(name, { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: { items, files: [], types: ["Files"] },
  });
  return event;
}

describe("UploadDropZone — folder drop", () => {
  // The component attaches drag listeners on `window` in a useEffect. We render
  // the component, dispatch a drop event on `window`, and inspect the onDrop
  // callback's arguments.

  let onDrop: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onDrop = vi.fn();
    render(
      <MantineProvider>
        <UploadDropZone currentPath="" onDrop={onDrop} />
      </MantineProvider>,
    );
  });

  afterEach(() => {
    // Ensure subsequent renders' useEffect cleanups don't double-attach.
    onDrop.mockReset();
  });

  it("flattens a single dropped file to one FileWithRelativePath", async () => {
    window.dispatchEvent(dragEvent("drop", [fileEntry("hello.txt")]));
    // The handler is async (walker awaits); wait for the callback.
    await vi.waitFor(() => expect(onDrop).toHaveBeenCalled());
    const arg = onDrop.mock.calls[0][0];
    expect(arg).toHaveLength(1);
    expect(arg[0].relativePath).toBe("hello.txt");
  });

  it("walks a dropped folder and emits relative paths preserving the folder name", async () => {
    const dropped = dirEntry("docs", [fileEntry("a.txt"), dirEntry("sub", [fileEntry("b.txt")])]);
    window.dispatchEvent(dragEvent("drop", [dropped]));
    await vi.waitFor(() => expect(onDrop).toHaveBeenCalled());
    const arg = onDrop.mock.calls[0][0] as Array<{ relativePath: string }>;
    expect(arg.map((x) => x.relativePath).sort()).toEqual(["docs/a.txt", "docs/sub/b.txt"]);
  });
});
