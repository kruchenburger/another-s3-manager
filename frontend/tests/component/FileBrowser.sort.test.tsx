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
const stopLoadAllMock = vi.fn();
let mockTruncated = false;
// true = the drain fully completes; false = the user cancelled mid-drain.
let mockLoadAllCompletes = true;
// true = the drain rejects (network/S3 failure mid-drain), exercised by the
// error-toast test below. Takes priority over mockLoadAllCompletes.
let mockLoadAllRejects = false;
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
      if (mockLoadAllRejects) return Promise.reject(new Error("network error"));
      if (mockLoadAllCompletes) mockTruncated = false;
      return Promise.resolve(mockLoadAllCompletes);
    },
    // Finding 1 spy: FileBrowser must abort any drain still running against
    // the folder it's leaving on navigation (contextKey change) — see the
    // "stops a running drain" test below.
    stopLoadAll: stopLoadAllMock,
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
    stopLoadAllMock.mockReset();
    mockTruncated = false;
    mockLoadAllCompletes = true;
    mockLoadAllRejects = false;
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
    // wire is live: a no-op onSortChange would make "selecting 'Name' above"
    // look identical (nothing reorders, loadAll never called) to a correctly
    // gated same-default selection. Click the direction toggle — that
    // requests {name, desc}, which IS non-default on a still-truncated level —
    // and confirm it DOES drain. This proves the wire is actually connected,
    // not just that a same-default selection correctly avoided draining.
    // Current sortState is still the default {name, asc}, so per Finding 6
    // the toggle's accessible name is the ACTION it performs: "Sort descending".
    fireEvent.click(screen.getByRole("button", { name: "Sort descending" }));
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
    // toggle's accessible name is the ACTION a click performs, not the
    // current state (Finding 6) — now that the sort is genuinely descending,
    // clicking again would sort ascending, so the button reads
    // "Sort ascending". This only passes if FileBrowserHeader actually
    // renders the LIVE effectiveSort it was just handed, not a stale one —
    // this assertion is what catches a silently-disconnected wire (e.g. the
    // gate's `completed` check dropped, or `sortState={effectiveSort}`
    // removed from the FileBrowserHeader call site).
    expect(
      screen.getByRole("button", { name: "Sort ascending" }),
    ).toBeInTheDocument();
  });

  // Finding 1: FileBrowser never unmounts across folder navigation (only the
  // route params change), so a drain running against the folder being LEFT
  // must be aborted explicitly — clientLoadInfinite's own unmount-only cancel
  // can't catch this, and fetchNextPage is bound to the query observer whose
  // options are re-set on every render, so a surviving loop would silently
  // re-target the folder the user just navigated TO.
  it("stops a running drain when the user navigates to a different folder", async () => {
    mockTruncated = false;
    renderBrowser();

    expect(stopLoadAllMock).not.toHaveBeenCalled();

    // Navigate by clicking the directory row — pathFromUrl changes but
    // FileBrowser stays mounted (react-router matches the same Route
    // element for both URLs), exactly the scenario Finding 1 covers.
    fireEvent.click(screen.getByText("zzz-folder"));

    await waitFor(() => {
      expect(stopLoadAllMock).toHaveBeenCalled();
    });
  });

  // Finding 2: nothing else in this suite ever renders truncated===true with
  // a non-default sortPreference AT THE SAME TIME as a completed drain — the
  // mock flips mockTruncated=false on every completed loadAll, so the one
  // state effectiveSort exists for was never actually exercised. Without this
  // test, `effectiveSort` could be replaced by `sortPreference` at all four
  // FileBrowser call sites and the rest of the suite would still pass.
  it("honesty guard: rows AND controls fall back to the default sort when the level is truncated again after a custom sort was applied", async () => {
    mockTruncated = false;
    const { container, rerenderTree } = renderBrowser();

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" }));
    await waitFor(() => {
      const rows = rowTexts(container);
      expect(rowIndex(rows, "gamma.txt")).toBeLessThan(rowIndex(rows, "alpha.txt"));
    });

    // The level becomes truncated again (e.g. a later partial load) while
    // sortPreference still holds the custom {size, asc} chosen above — this
    // is the exact state the honesty guard exists for: truncated===true with
    // a non-default sortPreference. rerenderTree keeps FileBrowser mounted so
    // sortPreference survives, matching what a real re-render would do.
    mockTruncated = true;
    act(() => {
      rerenderTree();
    });

    // ROWS: back to name-ascending — the guard suppressed the now-unsafe
    // size sort rather than ordering a partially-loaded level by it.
    const rows = rowTexts(container);
    expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));

    // CONTROLS: agree with the rows — the honesty guard feeds the SAME
    // effectiveSort to both, so the headers can never advertise a sort the
    // rows don't actually have.
    const nameHeader = screen
      .getByRole("button", { name: "Sort by name" })
      .closest("th");
    const sizeHeader = screen
      .getByRole("button", { name: "Sort by size" })
      .closest("th");
    expect(nameHeader).toHaveAttribute("aria-sort", "ascending");
    expect(sizeHeader).toHaveAttribute("aria-sort", "none");
  });

  // Finding 1: the default (untouched) sort must not run the collator over
  // the merged array — it must render the backend's arrival/concatenation
  // order unchanged. Discriminator: S3/byte order sorts '1' (0x31) before
  // '_' (0x5F), so file1.txt arrives before file_2.txt — but Intl.Collator
  // (UCA primary weights, per the sortEntries.ts comment) sorts punctuation
  // before digits, so it would place file_2.txt FIRST. A regression that
  // re-introduces an unconditional sortEntries() call on every render would
  // flip these two rows.
  it("does not collator-sort the default view — arrival order survives", async () => {
    mockTruncated = false;
    mockDirectories = [];
    mockFiles = [
      {
        name: "file1.txt",
        is_directory: false,
        size: 100,
        last_modified: "2026-01-01T00:00:00Z",
      },
      {
        name: "file_2.txt",
        is_directory: false,
        size: 100,
        last_modified: "2026-01-01T00:00:00Z",
      },
    ];
    const { container } = renderBrowser();

    const rows = rowTexts(container);
    expect(rowIndex(rows, "file1.txt")).toBeLessThan(rowIndex(rows, "file_2.txt"));
  });

  // Finding 3: requestSort's drain can reject (realistic network/S3 failure
  // mid-drain) — nothing previously exercised that branch. Assert both that
  // the error toast surfaces AND that the sort was never applied (the rows
  // keep their prior, pre-sort-attempt order).
  it("shows an error toast and keeps the prior order when the drain rejects", async () => {
    mockTruncated = true;
    mockLoadAllRejects = true;
    const { container } = renderBrowser();

    fireEvent.click(screen.getByRole("button", { name: "Sort by size" }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);

    expect(await screen.findByText("Couldn't load all files")).toBeInTheDocument();

    const rows = rowTexts(container);
    expect(rowIndex(rows, "alpha.txt")).toBeLessThan(rowIndex(rows, "gamma.txt"));
  });
});
