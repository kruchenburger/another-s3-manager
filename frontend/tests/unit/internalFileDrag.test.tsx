import { describe, expect, it, vi, afterEach } from "vitest";
import {
  renderHook,
  act,
  render,
  screen,
  fireEvent,
  cleanup,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { UploadDropZone } from "@/components/Upload/UploadDropZone";
import { useInternalFileDrag } from "@/features/files/hooks/useInternalFileDrag";
import {
  INTERNAL_DRAG_TYPE,
  itemIdentity,
} from "@/features/files/utils/folderOperations";
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function transfer() {
  const values: Record<string, string> = {};
  return {
    types: [INTERNAL_DRAG_TYPE],
    effectAllowed: "none",
    dropEffect: "none",
    setData: (key: string, value: string) => {
      values[key] = value;
    },
    getData: (key: string) => values[key] ?? "",
    files: [],
    items: [],
  };
}
describe("internal drag", () => {
  it("does not show upload overlay or invoke OS upload", () => {
    const upload = vi.fn();
    render(
      <MantineProvider>
        <UploadDropZone currentPath="" onDrop={upload} />
      </MantineProvider>,
    );
    const dataTransfer = transfer();
    const readItems = vi.fn(() => []);
    Object.defineProperty(dataTransfer, "items", { get: readItems });
    fireEvent.dragEnter(window, { dataTransfer });
    fireEvent.drop(window, { dataTransfer });
    expect(screen.queryByText("Drop here to upload")).not.toBeInTheDocument();
    expect(upload).not.toHaveBeenCalled();
    expect(readItems).not.toHaveBeenCalled();
  });
  it("drags the whole selection, rejects descendants and confirms valid targets", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
    } as MediaQueryList);
    const folder = { path: "a/x", kind: "folder" as const };
    const file = { path: "a/y", kind: "file" as const };
    const drop = vi.fn();
    const { result } = renderHook(() =>
      useInternalFileDrag({
        bucket: "b",
        role: "r",
        items: [folder, file],
        selected: new Set([itemIdentity(folder), itemIdentity(file)]),
        disabled: false,
        onDrop: drop,
      }),
    );
    const dataTransfer = transfer();
    const event = {
      dataTransfer,
      preventDefault: vi.fn(),
      stopPropagation: vi.fn(),
    };
    act(() =>
      result.current.row(folder).onDragStart!(
        event as unknown as React.DragEvent<HTMLElement>,
      ),
    );
    expect(JSON.parse(dataTransfer.getData(INTERNAL_DRAG_TYPE)).items).toEqual([
      folder,
      file,
    ]);
    act(() =>
      result.current.target("a/x/child").onDrop!(
        event as unknown as React.DragEvent<HTMLElement>,
      ),
    );
    expect(drop).not.toHaveBeenCalled();
    act(() =>
      result.current.target("dest").onDrop!(
        event as unknown as React.DragEvent<HTMLElement>,
      ),
    );
    expect(drop).toHaveBeenCalledWith({
      items: [folder, file],
      destination: "dest",
    });
  });
  it("drags only an unselected item and rejects foreign or malformed payloads", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
    } as MediaQueryList);
    const x = { path: "x", kind: "file" as const };
    const y = { path: "y", kind: "file" as const };
    const drop = vi.fn();
    const { result } = renderHook(() =>
      useInternalFileDrag({
        bucket: "b",
        role: "r",
        items: [x, y],
        selected: new Set([itemIdentity(x)]),
        disabled: false,
        onDrop: drop,
      }),
    );
    const dataTransfer = transfer();
    const event = {
      dataTransfer,
      preventDefault: vi.fn(),
      stopPropagation: vi.fn(),
    } as unknown as React.DragEvent<HTMLElement>;
    act(() => result.current.row(y).onDragStart!(event));
    expect(JSON.parse(dataTransfer.getData(INTERNAL_DRAG_TYPE)).items).toEqual([
      y,
    ]);
    for (const value of [
      "broken",
      JSON.stringify({ bucket: "foreign", role: "r", items: [y] }),
      JSON.stringify({ bucket: "b", role: "foreign", items: [y] }),
      JSON.stringify({
        bucket: "b",
        role: "r",
        items: [{ path: 7, kind: "file" }],
      }),
    ]) {
      dataTransfer.setData(INTERNAL_DRAG_TYPE, value);
      act(() => result.current.target("dest").onDrop!(event));
    }
    expect(drop).not.toHaveBeenCalled();
  });
});
