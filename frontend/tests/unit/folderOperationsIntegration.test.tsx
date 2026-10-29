import {
  act,
  cleanup,
  renderHook,
  waitFor,
  render,
  screen,
  fireEvent,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { FileActions } from "@/components/FileBrowser/FileActions";
import { FileRowActionsMenu } from "@/components/FileBrowser/FileRowActionsMenu";
import { BulkActionBar } from "@/components/FileBrowser/BulkActionBar";
import { describe, expect, it, vi, afterEach } from "vitest";
import { useFolderOperations } from "@/features/files/hooks/useFolderOperations";
import * as api from "@/features/files/api/filesApi";
vi.mock("@/features/files/jobs/MoveJobsProvider", () => ({
  useMoveJobs: () => ({ add: vi.fn() }),
}));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
describe("shared move flow", () => {
  it("exposes Move on desktop, mobile and bulk surfaces with no Rename action", async () => {
    const move = vi.fn();
    render(
      <MantineProvider>
        <FileActions
          isDirectory
          canPreview={false}
          onDelete={vi.fn()}
          onMove={move}
        />
        <FileRowActionsMenu
          isDirectory
          canPreview={false}
          filename="x"
          onDownload={vi.fn()}
          onCopyUrl={vi.fn()}
          onPreview={vi.fn()}
          onDelete={vi.fn()}
          onMove={move}
        />
        <BulkActionBar
          count={2}
          onClear={vi.fn()}
          onCopyUrls={vi.fn()}
          onDelete={vi.fn()}
          onMove={move}
        />
      </MantineProvider>,
    );
    await screen.findByRole("region", {
      name: "Bulk actions for selected files",
    });
    const buttons = screen.getAllByRole("button", { name: "Move to…" });
    expect(buttons).toHaveLength(2);
    fireEvent.click(buttons[0]);
    fireEvent.click(buttons[1]);
    fireEvent.click(screen.getByRole("button", { name: "Actions for x" }));
    fireEvent.click(await screen.findByRole("menuitem", { name: "Move to…" }));
    expect(move).toHaveBeenCalledTimes(3);
    expect(
      screen.queryByRole("menuitem", { name: /^Rename$/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^Rename$/i }),
    ).not.toBeInTheDocument();
  });
  it("disables desktop and bulk Move when deletion is disabled", async () => {
    render(
      <MantineProvider>
        <FileActions
          isDirectory
          canPreview={false}
          onDelete={vi.fn()}
          onMove={vi.fn()}
          disabled
        />
        <BulkActionBar
          count={2}
          onClear={vi.fn()}
          onCopyUrls={vi.fn()}
          onDelete={vi.fn()}
          onMove={vi.fn()}
          disableDeletion
        />
      </MantineProvider>,
    );
    await screen.findByRole("region", {
      name: "Bulk actions for selected files",
    });
    for (const button of screen.getAllByRole("button", { name: "Move to…" }))
      expect(button).toBeDisabled();
  });
  it("does not start before confirmation and preserves UUID on an ambiguous retry", async () => {
    vi.spyOn(api, "movePreflight").mockResolvedValue({
      objects: 3,
      bytes: 10,
      largest: 5,
      conflicts: [],
      blocked_reason: null,
    });
    const start = vi
      .spyOn(api, "startMove")
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValue({ job_id: "j" });
    const { result } = renderHook(() =>
      useFolderOperations("b", "r", "", false),
    );
    await act(async () =>
      result.current.choose({
        items: [{ path: "x", kind: "file" }],
        destination: "target",
      }),
    );
    expect(result.current.confirmation?.preflight.objects).toBe(3);
    expect(start).not.toHaveBeenCalled();
    await act(async () => result.current.confirm());
    expect(result.current.error).toContain("app isn't responding");
    await act(async () => result.current.confirm());
    expect(start.mock.calls[0][2].operation_id).toBe(
      start.mock.calls[1][2].operation_id,
    );
    await waitFor(() => expect(result.current.confirmation).toBeNull());
  });
  it("ignores a stale preflight after closing", async () => {
    let resolve!: (value: apiReturn) => void;
    type apiReturn = Awaited<ReturnType<typeof api.movePreflight>>;
    vi.spyOn(api, "movePreflight").mockImplementation(
      () =>
        new Promise((r) => {
          resolve = r;
        }),
    );
    const { result } = renderHook(() =>
      useFolderOperations("b", "r", "", false),
    );
    let pending: Promise<void>;
    act(() => {
      pending = result.current.choose({
        items: [{ path: "x", kind: "file" }],
        destination: "target",
      });
    });
    act(() => result.current.close());
    await act(async () => {
      resolve({
        objects: 1,
        bytes: 1,
        largest: 1,
        conflicts: [],
        blocked_reason: null,
      });
      await pending;
    });
    expect(result.current.confirmation).toBeNull();
  });
});
