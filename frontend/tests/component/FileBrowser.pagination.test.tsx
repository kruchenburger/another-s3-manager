import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { vi, describe, it, expect, beforeEach } from "vitest";

// Render every item — windowing itself is covered by Playwright E2E. This keeps
// the integration assertions (content, filter, selection) layout-independent.
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
let mockError: Error | null = null;
let mockIsFetchNextPageError = false;
let mockDirectories = [{ name: "logs", is_directory: true, size: 0 }];
let mockFiles = [
  { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
  { name: "b.txt", is_directory: false, size: 1, last_modified: "" },
];
vi.mock("@/features/files/hooks/useFiles", () => ({
  filesQueryKey: (b: string, r: string, p: string) => ["files", "list", r, b, p],
  useFiles: () => ({
    directories: mockDirectories,
    files: mockFiles,
    truncated: mockTruncated,
    // Wrap so the spy records the call but the component's `.catch()` has a real
    // promise to chain on (the real loadMore/loadAll are async).
    loadMore: (...args: unknown[]) => {
      loadMoreMock(...args);
      return Promise.resolve();
    },
    loadAll: (...args: unknown[]) => {
      loadAllMock(...args);
      return Promise.resolve();
    },
    isFetching: false,
    isFetchingNextPage: false,
    isFetchNextPageError: mockIsFetchNextPageError,
    error: mockError,
  }),
}));

let mockLazy = true;
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      items_per_page: 200,
      enable_lazy_loading: mockLazy,
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

function browserTree() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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

function renderBrowser() {
  return render(browserTree());
}

describe("FileBrowser hybrid pagination", () => {
  beforeEach(() => {
    loadMoreMock.mockReset();
    loadAllMock.mockReset();
    mockLazy = true;
    mockTruncated = false;
    mockError = null;
    mockIsFetchNextPageError = false;
    mockDirectories = [{ name: "logs", is_directory: true, size: 0 }];
    mockFiles = [
      { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
      { name: "b.txt", is_directory: false, size: 1, last_modified: "" },
    ];
  });

  it("renders directories + files from the loaded set", () => {
    renderBrowser();
    expect(screen.getByText("logs")).toBeInTheDocument();
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(screen.getByText("b.txt")).toBeInTheDocument();
  });

  it("shows honest count when not truncated", () => {
    renderBrowser();
    expect(screen.getByText(/3 objects/)).toBeInTheDocument();
  });

  it("shows N+ count and Load more/all when truncated", () => {
    mockTruncated = true;
    renderBrowser();
    expect(screen.getByText(/3\+ objects/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /load more/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /load all/i })).toBeInTheDocument();
  });

  it("Load more triggers the server continuation", () => {
    mockTruncated = true;
    renderBrowser();
    // Reset after initial render so the auto-load-near-end hook's initial
    // fire (triggered by the virtualizer mock rendering all items at the end)
    // does not inflate the count before the user click under test.
    loadMoreMock.mockReset();
    fireEvent.click(screen.getByRole("button", { name: /load more/i }));
    expect(loadMoreMock).toHaveBeenCalledTimes(1);
  });

  it("Load all triggers a full drain", () => {
    mockTruncated = true;
    renderBrowser();
    fireEvent.click(screen.getByRole("button", { name: /load all/i }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);
  });

  it("plays the entry stagger only on the first screenful, not on every loaded row", () => {
    // Regression: the per-row fadeIn delay (--row-index * 30ms) grew unbounded,
    // so lazy-revealed rows sat invisible (opacity 0) for 1.6–3.5s waiting on
    // their delay. The stagger must be capped to the first screenful; rows past
    // it — the tail of a big page AND every lazy-revealed row — render instantly.
    mockTruncated = false;
    mockFiles = Array.from({ length: 25 }, (_, i) => ({
      name: `f${String(i).padStart(2, "0")}.txt`,
      is_directory: false,
      size: 1,
      last_modified: "",
    }));
    const { container } = renderBrowser();
    const rows = Array.from(
      container.querySelectorAll("table tbody tr:not([data-spacer])"),
    );
    const animated = rows.filter((r) => r.className.includes("animateIn"));
    // Some rows animate in (cold-load delight) but the count is capped — the
    // tail rows render instantly.
    expect(animated.length).toBeGreaterThan(0);
    expect(animated.length).toBeLessThan(rows.length);
    // The very last row (well past the first screen) must not animate.
    expect(rows[rows.length - 1].className).not.toContain("animateIn");
  });

  it("shows filter banner when searching and truncated", async () => {
    mockTruncated = true;
    renderBrowser();
    let input: HTMLElement;
    try {
      input = screen.getByPlaceholderText(/filter|search/i);
    } catch {
      input = screen.getByRole("searchbox");
    }
    fireEvent.change(input, { target: { value: "a" } });
    expect(
      await screen.findByText(/load more to search the rest/i),
    ).toBeInTheDocument();
  });

  it("keeps the loaded table visible on a continuation error (does not blank)", () => {
    // A failed loadMore/loadAll populates query.error while the already-loaded
    // pages stay cached. Per the design ("continuation error -> toast + keep the
    // loaded items, never blank the table"), the table must remain; only an
    // initial / refetch error may show the full-page error state.
    mockError = new Error("network");
    mockIsFetchNextPageError = true; // the error came from fetchNextPage
    renderBrowser();
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(
      screen.queryByText(/couldn't load files/i),
    ).not.toBeInTheDocument();
  });

  it("shows the full-page error state when the initial load fails with no items", () => {
    mockError = new Error("network");
    mockDirectories = [];
    mockFiles = [];
    renderBrowser();
    expect(screen.getByText(/couldn't load files/i)).toBeInTheDocument();
  });

  it("clears the selection when the search query changes (no ghost selection)", async () => {
    // While searching, the slice is disabled and every match renders, so a row
    // can be selected that falls outside the slice once the filter clears —
    // then it stays selected but off-screen, and "Delete (N)" would delete an
    // invisible file. Changing the search must drop the selection.
    renderBrowser();
    const checkbox = screen.getByLabelText("Select a.txt");
    fireEvent.click(checkbox);
    expect(screen.getByLabelText("Select a.txt")).toBeChecked();
    const input = screen.getByPlaceholderText(/filter/i);
    fireEvent.change(input, { target: { value: "a" } }); // a.txt still matches
    await waitFor(() =>
      expect(screen.getByLabelText("Select a.txt")).not.toBeChecked(),
    );
  });

  it("debounces the search filter (input is instant, filter applies after the delay)", async () => {
    mockFiles = [
      { name: "apple.txt", is_directory: false, size: 1, last_modified: "" },
      { name: "banana.txt", is_directory: false, size: 1, last_modified: "" },
    ];
    mockDirectories = [];
    renderBrowser();
    const input = screen.getByPlaceholderText(/filter/i);
    fireEvent.change(input, { target: { value: "apple" } });
    expect(input).toHaveValue("apple");
    await waitFor(() =>
      expect(screen.queryByText("banana.txt")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("apple.txt")).toBeInTheDocument();
  });
});
