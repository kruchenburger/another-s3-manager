import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { vi, describe, it, expect, beforeEach } from "vitest";

// Render every item (no windowing) so row ORDER is assertable. Same mock as
// the pagination suite.
const ROW = 40;
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        start: index * ROW,
        size: ROW,
        end: (index + 1) * ROW,
      })),
    getTotalSize: () => count * ROW,
    measureElement: () => {},
  }),
}));

const loadMoreMock = vi.fn();
const loadAllMock = vi.fn();
let mockTruncated = false;
// true = the drain fully completes; false = the user cancelled mid-drain.
let mockLoadAllCompletes = true;
let mockDirectories = [{ name: "zzz-folder", is_directory: true, size: 0 }];
// Deliberately anti-correlated: name-asc order (alpha, beta, gamma) is the
// exact REVERSE of size-asc order (gamma 100 < beta 200 < alpha 300), so a
// size sort produces an unambiguous, fully-reversed row order.
let mockFiles = [
  { name: "alpha.txt", is_directory: false, size: 300, last_modified: "2026-01-03T00:00:00Z" },
  { name: "beta.txt", is_directory: false, size: 200, last_modified: "2026-01-02T00:00:00Z" },
  { name: "gamma.txt", is_directory: false, size: 100, last_modified: "2026-01-01T00:00:00Z" },
];
vi.mock("@/features/files/hooks/useFiles", () => ({
  filesQueryKey: (b: string, r: string, p: string) => ["files", "list", r, b, p],
  useFiles: () => ({
    directories: mockDirectories,
    files: mockFiles,
    truncated: mockTruncated,
    loadMore: (...args: unknown[]) => {
      loadMoreMock(...args);
      return Promise.resolve();
    },
    // Boolean drain contract (Task 2): resolves true only when the level was
    // fully drained. A REAL completed drain also leaves the level
    // un-truncated, so the mock flips mockTruncated before resolving — the
    // re-render triggered by the applied sort then sees the drained state,
    // exactly like production. Without the flip, the effectiveSort honesty
    // guard would (correctly) keep the default order and the reordering
    // assertion could never pass.
    loadAll: () => {
      loadAllMock();
      if (mockLoadAllCompletes) mockTruncated = false;
      return Promise.resolve(mockLoadAllCompletes);
    },
    isFetching: false,
    isFetchingNextPage: false,
    isFetchNextPageError: false,
    error: null,
  }),
}));

vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      // Lazy loading OFF so the near-end auto-load sentinel never fires
      // loadMore in the background of these order assertions.
      enable_lazy_loading: false,
      max_client_load: 10000,
      max_file_size: 100 * 1024 * 1024,
      disable_deletion: false,
      roles: [],
    },
  }),
}));

vi.mock("@/features/files/hooks/useDelete", () => ({
  useDelete: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/features/files/hooks/useUpload", () => ({
  useUpload: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { disable_deletion: false } }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: () => ({ data: undefined, isSuccess: false }),
}));
vi.mock("@/features/files/api/filesApi", () => ({
  buildDownloadUrl: () => "",
  getPresignedDownloadUrl: vi.fn(),
  deleteFile: vi.fn(),
}));

import { FileBrowser } from "@/components/FileBrowser/FileBrowser";

function browserTree(qc: QueryClient) {
  return (
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/r/RoleA/b/my-bucket/p/"]}>
          <Routes>
            <Route path="/r/:roleId/b/:bucket/p/*" element={<FileBrowser />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>
  );
}

// `rerenderTree()` re-renders the SAME tree (stable QueryClient, same route), so
// the mocked useFiles re-runs and picks up a changed `mockTruncated` while the
// FileBrowser instance — and therefore its `sortPreference` useState — stays
// mounted. The cancelled-drain test below needs exactly that.
function renderBrowser() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(browserTree(qc));
  return { ...utils, rerenderTree: () => utils.rerender(browserTree(qc)) };
}

function rowTexts(container: HTMLElement): string[] {
  return Array.from(
    container.querySelectorAll("table tbody tr:not([data-spacer])"),
  ).map((r) => r.textContent ?? "");
}

function rowIndex(rows: string[], name: string): number {
  return rows.findIndex((t) => t.includes(name));
}

describe("FileBrowser sorting — truncated-level gate", () => {
  beforeEach(() => {
    loadMoreMock.mockReset();
    loadAllMock.mockReset();
    mockTruncated = false;
    mockLoadAllCompletes = true;
    window.localStorage.clear(); // useDisplayMode persists table/grid per bucket
    mockDirectories = [{ name: "zzz-folder", is_directory: true, size: 0 }];
    mockFiles = [
      { name: "alpha.txt", is_directory: false, size: 300, last_modified: "2026-01-03T00:00:00Z" },
      { name: "beta.txt", is_directory: false, size: 200, last_modified: "2026-01-02T00:00:00Z" },
      { name: "gamma.txt", is_directory: false, size: 100, last_modified: "2026-01-01T00:00:00Z" },
    ];
  });

  it("sorts client-side with NO drain when the level is fully loaded", async () => {
    mockTruncated = false;
    const { container } = renderBrowser();

    // Default order: folder first, then name-asc.
    let rows = rowTexts(container);
    expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" }));

    await waitFor(() => {
      const after = rowTexts(container);
      expect(rowIndex(after, "gamma.txt")).toBeLessThan(rowIndex(after, "alpha.txt"));
    });
    // Folders stay pinned first even under a size sort.
    rows = rowTexts(container);
    expect(rowIndex(rows, "zzz-folder")).toBe(0);
    expect(loadAllMock).not.toHaveBeenCalled();
  });

  it("clicking the active column again flips the direction", async () => {
    mockTruncated = false;
    const { container } = renderBrowser();

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" })); // size asc
    await waitFor(() => {
      const rows = rowTexts(container);
      expect(rowIndex(rows, "gamma.txt")).toBeLessThan(rowIndex(rows, "alpha.txt"));
    });

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" })); // size desc
    await waitFor(() => {
      const rows = rowTexts(container);
      expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));
    });
    expect(loadAllMock).not.toHaveBeenCalled();
  });

  it("gates a size sort on a truncated level behind a full drain, then applies it", async () => {
    mockTruncated = true;
    mockLoadAllCompletes = true;
    const { container } = renderBrowser();

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);

    // After the drain resolves true, the sort applies over the full level.
    await waitFor(() => {
      const rows = rowTexts(container);
      expect(rowIndex(rows, "gamma.txt")).toBeLessThan(rowIndex(rows, "alpha.txt"));
    });
  });

  it("keeps the prior order when the drain is cancelled — and does not pollute the sort preference", async () => {
    mockTruncated = true;
    mockLoadAllCompletes = false; // the user hits Stop mid-drain
    const { container, rerenderTree } = renderBrowser();

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);

    // Flush the resolved-false promise chain, then assert nothing reordered.
    await act(async () => {
      await Promise.resolve();
    });
    let rows = rowTexts(container);
    expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));
    expect(loadAllMock).toHaveBeenCalledTimes(1);

    // DISCRIMINATOR — do not drop this half of the test. While the level stays
    // truncated, the effectiveSort honesty guard ALONE keeps the default order
    // even if the gate had wrongly stored the size preference, so the assertion
    // above cannot tell a correct gate from a broken one. Drop `truncated` (as a
    // later Load-all, or navigating to a smaller folder, would) and re-render:
    // only an UNPOLLUTED preference still renders name-order here. This is what
    // makes the gate's `completed` check load-bearing — a `setSortPreference(next)`
    // that ignores `completed` fails exactly here.
    mockTruncated = false;
    act(() => {
      rerenderTree();
    });
    rows = rowTexts(container);
    expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));
  });

  it("selecting the default {name, asc} sort on a truncated level does NOT drain", async () => {
    mockTruncated = true;
    renderBrowser();

    // The only UI path that requests the exact default while truncated is the
    // grid Select (a header click on Name would flip to desc). Switch to grid
    // and re-select "Name": same column keeps direction asc → default sort.
    await userEvent.click(screen.getByRole("button", { name: "Grid view" }));
    // Mantine 9 Select's Combobox dropdown opens unreliably under
    // userEvent.click in jsdom; fireEvent.click is the repo's established
    // workaround (see tests/component/SettingsPresignedTtl.test.tsx).
    fireEvent.click(screen.getByRole("combobox", { name: "Sort by" }));
    fireEvent.click(await screen.findByRole("option", { name: "Name" }));

    expect(loadAllMock).not.toHaveBeenCalled();

    // Positive control — the Select alone can't prove the header→requestSort
    // wire is live: FileBrowserHeader's sortState/onSortChange props are both
    // OPTIONAL, so even if FileBrowser never passed `onSortChange={requestSort}`
    // at all, selecting "Name" above would still no-op silently and the
    // assertion above would still pass. Click the direction toggle — that
    // requests {name, desc}, which IS non-default on a still-truncated level —
    // and confirm it DOES drain. This proves the wire is actually connected,
    // not just that a same-default selection correctly avoided draining.
    fireEvent.click(screen.getByRole("button", { name: "Sort ascending" }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);

    // Flush the resolved-drain promise chain so requestSort's pending
    // `.then()` (which calls setSortPreference) doesn't fire outside of
    // act() after this test ends (same pattern as the cancelled-drain test).
    await act(async () => {
      await Promise.resolve();
    });

    // REFLECTION check (not just RECEIVES-a-click) — the drain above
    // completed (mockLoadAllCompletes defaults true) and applied {name, desc}
    // via setSortPreference, so the direction is now genuinely desc. The
    // toggle button's accessible name is state-driven ("Sort ascending" while
    // asc, "Sort descending" while desc — see FileBrowserHeader), so this
    // only passes if FileBrowserHeader actually renders the LIVE
    // effectiveSort it was just handed, not a stale/default one. If
    // FileBrowser dropped `sortState={effectiveSort}` on the
    // FileBrowserHeader call site, the optional prop's own DEFAULT_SORT
    // fallback (name, asc) would keep this button labelled "Sort ascending"
    // forever regardless of what requestSort resolved to — this assertion
    // is what catches that silently-disconnected wire.
    expect(
      screen.getByRole("button", { name: "Sort descending" }),
    ).toBeInTheDocument();
  });
});
