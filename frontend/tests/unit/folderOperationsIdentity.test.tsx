import { describe, expect, it, vi, afterEach } from "vitest";
import {
  act,
  renderHook,
  render,
  screen,
  within,
  fireEvent,
  cleanup,
  waitFor,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { FileBrowser } from "@/components/FileBrowser/FileBrowser";
import { MoveJobsProvider } from "@/features/files/jobs/MoveJobsProvider";
import * as api from "@/features/files/api/filesApi";
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        start: index * 44,
        end: (index + 1) * 44,
        size: 44,
      })),
    getTotalSize: () => count * 44,
    measureElement: () => {},
  }),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { username: "alice", disable_deletion: false } }),
  meQueryKey: ["auth", "me"],
}));
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: { enable_lazy_loading: false, max_file_size: 1000 },
  }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: () => ({}),
}));
vi.mock("@/utils/toast", () => ({
  showToast: vi.fn(),
  TOAST_DURATIONS: { success: 100, error: 100, infoLong: 100 },
}));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});
import {
  INTERNAL_DRAG_TYPE,
  entryIdentity,
  itemIdentity,
  targetError,
  validateName,
} from "@/features/files/utils/folderOperations";
import { ApiError } from "@/utils/apiError";
import { useShiftSelect } from "@/components/FileBrowser/useShiftSelect";
describe("exact object identity and move rules", () => {
  function browser() {
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MantineProvider>
          <MoveJobsProvider>
            <MemoryRouter initialEntries={["/r/r/b/b/p/a"]}>
              <Routes>
                <Route
                  path="/r/:roleId/b/:bucket/p/*"
                  element={<FileBrowser />}
                />
              </Routes>
            </MemoryRouter>
          </MoveJobsProvider>
        </MantineProvider>
      </QueryClientProvider>,
    );
  }
  function transfer() {
    const data: Record<string, string> = {};
    return {
      types: [INTERNAL_DRAG_TYPE],
      effectAllowed: "none",
      dropEffect: "none",
      setData: (type: string, value: string) => {
        data[type] = value;
      },
      getData: (type: string) => data[type] ?? "",
    };
  }
  it.each(["dialog", "drag"])(
    "keeps hidden server-search selections for %s moves",
    async (mode) => {
      vi.spyOn(window, "matchMedia").mockReturnValue({
        matches: true,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      } as unknown as MediaQueryList);
      vi.spyOn(api, "listFiles").mockImplementation(
        async (_b, _r, _p, opts) => ({
          directories: opts?.search
            ? []
            : [{ name: "dest", is_directory: true, size: 0 }],
          files: [
            {
              name: opts?.search ? "z.txt" : "a.txt",
              is_directory: false,
              size: 1,
            },
          ],
          truncated: !opts?.search,
          next_token: opts?.search ? null : "more",
        }),
      );
      const preflight = vi.spyOn(api, "movePreflight").mockResolvedValue({
        objects: 2,
        bytes: 2,
        largest: 1,
        conflicts: [],
        blocked_reason: null,
        plan_fingerprint: "a".repeat(64),
      });
      browser();
      await screen.findByLabelText("Select a.txt");
      const input = screen.getByPlaceholderText(/filter|search/i);
      fireEvent.change(input, { target: { value: "z" } });
      fireEvent.click(await screen.findByText(/search "z" on server/i));
      fireEvent.click(await screen.findByLabelText("Select z.txt"));
      fireEvent.click(screen.getByLabelText("Exit server search"));
      fireEvent.change(input, { target: { value: "" } });
      const file = await screen.findByLabelText("Select a.txt");
      fireEvent.click(file);
      expect(screen.getByText("2 selected")).toBeInTheDocument();
      if (mode === "dialog") {
        fireEvent.click(
          within(
            screen.getByRole("region", {
              name: "Bulk actions for selected files",
            }),
          ).getByRole("button", { name: "Move to…" }),
        );
        fireEvent.click(
          await screen.findByRole("button", { name: "Open folder dest" }),
        );
        fireEvent.click(screen.getByRole("button", { name: "Move here" }));
      } else {
        const dataTransfer = transfer();
        fireEvent.dragStart(file.closest("tr")!, { dataTransfer });
        fireEvent.drop(screen.getByLabelText("Select dest").closest("tr")!, {
          dataTransfer,
        });
      }
      await screen.findByRole("dialog", { name: "Confirm move" });
      expect(preflight).toHaveBeenLastCalledWith("b", "r", {
        items: [
          { path: "a/z.txt", kind: "file" },
          { path: "a/a.txt", kind: "file" },
        ],
        destination: "a/dest",
      });
    },
  );
  it.each(["dialog", "drag"])(
    "requires confirmation of changed counts for %s moves",
    async (mode) => {
      vi.spyOn(window, "matchMedia").mockReturnValue({
        matches: true,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
      } as unknown as MediaQueryList);
      vi.spyOn(api, "listFiles").mockResolvedValue({
        directories: [{ name: "dest", is_directory: true, size: 0 }],
        files: [{ name: "file", is_directory: false, size: 1 }],
        truncated: false,
        next_token: null,
      });
      vi.spyOn(api, "movePreflight")
        .mockResolvedValueOnce({
          objects: 1,
          bytes: 1,
          largest: 1,
          conflicts: [],
          blocked_reason: null,
          plan_fingerprint: "a".repeat(64),
        })
        .mockResolvedValueOnce({
          objects: 2,
          bytes: 3,
          largest: 2,
          conflicts: [],
          blocked_reason: null,
          plan_fingerprint: "b".repeat(64),
        });
      const start = vi
        .spyOn(api, "startMove")
        .mockRejectedValueOnce(
          new ApiError(409, "Conflict", { detail: { code: "PLAN_CHANGED" } }),
        )
        .mockResolvedValue({ job_id: "j" });
      vi.spyOn(api, "getJob").mockReturnValue(new Promise(() => {}));
      browser();
      const file = await screen.findByLabelText("Select file");
      if (mode === "drag") {
        const dataTransfer = transfer();
        fireEvent.dragStart(file.closest("tr")!, { dataTransfer });
        fireEvent.drop(screen.getByLabelText("Select dest").closest("tr")!, {
          dataTransfer,
        });
      } else {
        fireEvent.click(file);
        fireEvent.click(
          within(
            await screen.findByRole("region", {
              name: "Bulk actions for selected files",
            }),
          ).getByRole("button", { name: "Move to…" }),
        );
        fireEvent.click(
          await screen.findByRole("button", { name: "Open folder dest" }),
        );
        fireEvent.click(screen.getByRole("button", { name: "Move here" }));
      }
      expect(
        await screen.findByText(/This moves 1 objects/),
      ).toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: "Start move" }));
      expect(
        await screen.findByText(/This moves 2 objects/),
      ).toBeInTheDocument();
      expect(start).toHaveBeenCalledTimes(1);
      fireEvent.click(screen.getByRole("button", { name: "Start move" }));
      await waitFor(() => expect(start).toHaveBeenCalledTimes(2));
      expect(start.mock.calls[1][2]).toEqual(
        expect.objectContaining({
          items: [{ path: "a/file", kind: "file" }],
          destination: "a/dest",
          plan_fingerprint: "b".repeat(64),
        }),
      );
      expect(start.mock.calls[1][2].operation_id).not.toBe(
        start.mock.calls[0][2].operation_id,
      );
    },
  );
  it("keeps a file x and folder x/ independently selected", () => {
    const file = entryIdentity("a", {
      name: "x",
      is_directory: false,
      size: 1,
    });
    const folder = entryIdentity("a", {
      name: "x",
      is_directory: true,
      size: 0,
    });
    expect(file).not.toBe(folder);
    expect(folder).toBe(itemIdentity({ path: "a/x", kind: "folder" }));
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle(file, false, [file, folder]));
    expect([...result.current.selected]).toEqual([file]);
    act(() => result.current.handleToggle(folder, true, [file, folder]));
    expect(result.current.selected.size).toBe(2);
  });
  it("rejects current/self/descendants at segment boundaries", () => {
    const items = [{ path: "a/b", kind: "folder" as const }];
    expect(targetError(items, "a")).toBeTruthy();
    expect(targetError(items, "a/b")).toBeTruthy();
    expect(targetError(items, "a/b/c")).toBeTruthy();
    expect(targetError(items, "a/bc")).toBeNull();
    expect(targetError([{ ...items[0], new_name: "c" }], "a")).toBeNull();
  });
  it.each([
    "",
    ".",
    "..",
    "a/b",
    " x",
    "x ",
    "a\u0000",
    "a\u007f",
    "a".repeat(256),
  ])("rejects invalid new name %j", (name) =>
    expect(validateName(name)).toBeTruthy(),
  );
  it("counts Unicode code points and the complete marker key bytes", () => {
    expect(validateName("😀".repeat(255))).toBeNull();
    expect(validateName("😀".repeat(255), "abcd")).toBeTruthy();
    // New names may not contain ".." (older routes reject such keys); existing keys stay exact.
    expect(validateName("a..b")).toBe("Names cannot contain '..'.");
    expect(validateName("\u0085x")).toBeTruthy();
    expect(validateName("\ufeffx")).toBeNull();
  });
  it("routes actual file/folder row actions and bulk selection by kind, without Rename", async () => {
    vi.spyOn(api, "listFiles").mockResolvedValue({
      directories: [{ name: "x", is_directory: true, size: 0 }],
      files: [{ name: "x", is_directory: false, size: 1 }],
      truncated: false,
      next_token: null,
    });
    const preflight = vi.spyOn(api, "movePreflight").mockResolvedValue({
      objects: 1,
      bytes: 1,
      largest: 1,
      conflicts: [],
      blocked_reason: null,
      plan_fingerprint: "a".repeat(64),
    });
    const start = vi
      .spyOn(api, "startMove")
      .mockResolvedValue({ job_id: "test-job" });
    vi.spyOn(api, "getJob").mockResolvedValue({
      job_id: "test-job",
      state: "running",
      phase: "copy",
      done: 0,
      total: 1,
      bytes_done: 0,
      bytes_total: 1,
      removed: 0,
      failures: [],
      failures_total: 0,
      failures_stored: 0,
      failures_offset: 0,
      next_failures_offset: null,
      result: {},
    });
    const remove = vi.spyOn(api, "deleteFile").mockResolvedValue();
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MantineProvider>
          <MoveJobsProvider>
            <MemoryRouter initialEntries={["/r/r/b/b/p/a"]}>
              <Routes>
                <Route
                  path="/r/:roleId/b/:bucket/p/*"
                  element={<FileBrowser />}
                />
              </Routes>
            </MemoryRouter>
          </MoveJobsProvider>
        </MantineProvider>
      </QueryClientProvider>,
    );
    await screen.findAllByLabelText("Select x");
    const rows = screen.getAllByRole("row");
    fireEvent.click(within(rows[2]).getByRole("button", { name: "Move to…" }));
    fireEvent.change(screen.getByLabelText("New name"), {
      target: { value: "new-x" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Move here" }));
    await screen.findByRole("dialog", { name: "Confirm move" });
    expect(preflight).toHaveBeenCalledWith("b", "r", {
      items: [{ path: "a/x", kind: "file", new_name: "new-x" }],
      destination: "a",
    });
    expect(start).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Start move" }));
    await waitFor(() => expect(start).toHaveBeenCalledOnce());
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(within(rows[1]).getByLabelText("Select x"));
    fireEvent.click(within(rows[2]).getByLabelText("Select x"));
    expect(await screen.findByText("2 selected")).toBeInTheDocument();
    fireEvent.click(
      within(
        screen.getByRole("region", { name: "Bulk actions for selected files" }),
      ).getByRole("button", { name: "Move to…" }),
    );
    expect(screen.queryByLabelText("New name")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /^Rename$/i }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(within(rows[1]).getByRole("button", { name: "Delete" }));
    fireEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Delete",
      }),
    );
    await waitFor(() => expect(remove).toHaveBeenCalledWith("b", "r", "a/x/"));
    expect(remove).not.toHaveBeenCalledWith("b", "r", "a/x");
  });
  it("wires selected table drags to folder targets and breadcrumb confirmation", async () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
    } as unknown as MediaQueryList);
    vi.spyOn(api, "listFiles").mockResolvedValue({
      directories: [
        { name: "x", is_directory: true, size: 0 },
        { name: "dest", is_directory: true, size: 0 },
      ],
      files: [{ name: "y", is_directory: false, size: 1 }],
      truncated: false,
      next_token: null,
    });
    const preflight = vi.spyOn(api, "movePreflight").mockResolvedValue({
      objects: 2,
      bytes: 100,
      largest: 100,
      conflicts: [],
      blocked_reason: null,
      plan_fingerprint: "a".repeat(64),
    });
    const start = vi.spyOn(api, "startMove");
    browser();
    const folder = (await screen.findByLabelText("Select x")).closest("tr")!;
    const file = screen.getByLabelText("Select y").closest("tr")!;
    const destination = screen.getByLabelText("Select dest").closest("tr")!;
    expect(folder).toHaveAttribute("draggable", "true");
    fireEvent.click(within(folder).getByLabelText("Select x"));
    fireEvent.click(within(file).getByLabelText("Select y"));
    const dataTransfer = transfer();
    fireEvent.dragStart(file, { dataTransfer });
    fireEvent.dragOver(folder, { dataTransfer });
    expect(folder).toHaveAttribute("data-move-target", "invalid");
    fireEvent.drop(folder, { dataTransfer });
    expect(preflight).not.toHaveBeenCalled();
    fireEvent.dragOver(destination, { dataTransfer });
    expect(destination).toHaveAttribute("data-move-target", "valid");
    fireEvent.drop(destination, { dataTransfer });
    await screen.findByRole("dialog", { name: "Confirm move" });
    expect(preflight).toHaveBeenLastCalledWith("b", "r", {
      items: [
        { path: "a/x", kind: "folder" },
        { path: "a/y", kind: "file" },
      ],
      destination: "a/dest",
    });
    expect(start).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.dragStart(file, { dataTransfer });
    const root = screen.getByRole("link", { name: "b" });
    fireEvent.dragOver(root, { dataTransfer });
    expect(root).toHaveAttribute("data-move-target", "valid");
    fireEvent.drop(root, { dataTransfer });
    await screen.findByRole("dialog", { name: "Confirm move" });
    expect(preflight).toHaveBeenLastCalledWith(
      "b",
      "r",
      expect.objectContaining({ destination: "" }),
    );
  });
  it("wires grid cards to the same drop confirmation", async () => {
    localStorage.setItem("display:r:b", "grid");
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
    } as unknown as MediaQueryList);
    vi.spyOn(api, "listFiles").mockResolvedValue({
      directories: [{ name: "dest", is_directory: true, size: 0 }],
      files: [{ name: "x", is_directory: false, size: 1 }],
      truncated: false,
      next_token: null,
    });
    const preflight = vi.spyOn(api, "movePreflight").mockResolvedValue({
      objects: 1,
      bytes: 1,
      largest: 1,
      conflicts: [],
      blocked_reason: null,
      plan_fingerprint: "a".repeat(64),
    });
    browser();
    const file = (await screen.findByLabelText("Select x")).closest(
      ".mantine-Card-root",
    )!;
    const destination = screen
      .getByLabelText("Select dest")
      .closest(".mantine-Card-root")!;
    expect(file).toHaveAttribute("draggable", "true");
    const dataTransfer = transfer();
    fireEvent.dragStart(file, { dataTransfer });
    fireEvent.drop(destination, { dataTransfer });
    await screen.findByRole("dialog", { name: "Confirm move" });
    expect(preflight).toHaveBeenCalledWith("b", "r", {
      items: [{ path: "a/x", kind: "file" }],
      destination: "a/dest",
    });
    expect(screen.queryByText("Drop here to upload")).not.toBeInTheDocument();
  });
});

it.each(["a%2Fb", "100%done", "a b", "#", "?", "資料", "😀"])(
  "opens %s through a built link and moves its exact keys",
  async (name) => {
    const list = vi
      .spyOn(api, "listFiles")
      .mockImplementation(async (_b, _r, path) => ({
        directories:
          path === "a"
            ? [
                { name, is_directory: true, size: 0 },
                { name: "a", is_directory: true, size: 0 },
              ]
            : [],
        files:
          path === "a" ? [] : [{ name: "file", is_directory: false, size: 1 }],
        truncated: false,
        next_token: null,
      }));
    vi.spyOn(api, "movePreflight").mockResolvedValue({
      objects: 1,
      bytes: 1,
      largest: 1,
      conflicts: [],
      blocked_reason: null,
      plan_fingerprint: "a".repeat(64),
    });
    const start = vi.spyOn(api, "startMove").mockResolvedValue({ job_id: "j" });
    vi.spyOn(api, "getJob").mockReturnValue(new Promise(() => {}));
    render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { queries: { retry: false } } })
        }
      >
        <MantineProvider>
          <MoveJobsProvider>
            <MemoryRouter initialEntries={["/r/r/b/b/p/a"]}>
              <Routes>
                <Route
                  path="/r/:roleId/b/:bucket/p/*"
                  element={<FileBrowser />}
                />
              </Routes>
            </MemoryRouter>
          </MoveJobsProvider>
        </MantineProvider>
      </QueryClientProvider>,
    );
    fireEvent.doubleClick(
      (await screen.findByLabelText(`Select ${name}`)).closest("tr")!,
    );
    await screen.findByLabelText("Select file");
    expect(list).toHaveBeenLastCalledWith(
      "b",
      "r",
      `a/${name}`,
      expect.anything(),
    );
    fireEvent.click(screen.getByLabelText("Select file"));
    fireEvent.click(
      within(
        await screen.findByRole("region", {
          name: "Bulk actions for selected files",
        }),
      ).getByRole("button", { name: "Move to…" }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "b" }));
    fireEvent.click(screen.getByRole("button", { name: "Move here" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start move" }));
    await waitFor(() =>
      expect(start).toHaveBeenCalledWith(
        "b",
        "r",
        expect.objectContaining({
          items: [{ path: `a/${name}/file`, kind: "file" }],
          destination: "",
        }),
      ),
    );
  },
);
