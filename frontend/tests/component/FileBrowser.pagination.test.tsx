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
let mockIsFetchingNextPage = false;
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
    // FileBrowser's Finding-1 cleanup effect calls this on every unmount/route
    // change; the mock must supply a callable or that effect throws.
    stopLoadAll: vi.fn(),
    isFetching: false,
    isFetchingNextPage: mockIsFetchingNextPage,
    isFetchNextPageError: mockIsFetchNextPageError,
    error: mockError,
  }),
}));

let mockLazy = true;
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
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
    mockIsFetchingNextPage = false;
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

  it("shows N+ count and Load more/all controls when truncated", () => {
    mockTruncated = true;
    renderBrowser();
    expect(screen.getByText(/3\+ objects/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /load more/i })).toBeInTheDocument();
    // "Load all" now lives in the LoadSplitButton overflow menu — its trigger is
    // the "More load options" chevron next to "Load more".
    expect(
      screen.getByRole("button", { name: /more load options/i }),
    ).toBeInTheDocument();
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

  it("Load all (from the overflow menu) triggers a full drain", async () => {
    mockTruncated = true;
    renderBrowser();
    fireEvent.click(screen.getByRole("button", { name: /more load options/i }));
    fireEvent.click(
      await screen.findByRole("menuitem", { name: /load all/i }),
    );
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
    // The banner now shows a "Filtering N loaded items." text and a server-search
    // affordance anchor. Assert on the affordance (the most stable signal).
    expect(
      await screen.findByText(/search "a" on server \(starts-with\)/i),
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

  // Bottom-of-list "Load more" footer — only when lazy loading is OFF (with lazy
  // on, the near-end sentinel auto-loads, so a manual bottom button is redundant).
  it("does not render the bottom Load more footer when lazy loading is ON", () => {
    mockLazy = true;
    mockTruncated = true;
    renderBrowser();
    // Only the header Load more exists; the footer is suppressed under lazy auto-load.
    expect(screen.getAllByRole("button", { name: /load more/i })).toHaveLength(1);
  });

  it("renders a bottom Load more footer when lazy loading is OFF and truncated", () => {
    mockLazy = false;
    mockTruncated = true;
    renderBrowser();
    // Header + footer, both labelled "Load more".
    expect(screen.getAllByRole("button", { name: /load more/i })).toHaveLength(2);
  });

  it("hides the bottom footer when lazy is OFF but nothing more to load", () => {
    mockLazy = false;
    mockTruncated = false;
    renderBrowser();
    expect(
      screen.queryByRole("button", { name: /load more/i }),
    ).not.toBeInTheDocument();
  });

  it("the bottom Load more footer triggers the server continuation", () => {
    mockLazy = false;
    mockTruncated = true;
    renderBrowser();
    loadMoreMock.mockReset();
    const buttons = screen.getAllByRole("button", { name: /load more/i });
    // The footer renders after the header in the DOM, so it's the last match.
    fireEvent.click(buttons[buttons.length - 1]);
    expect(loadMoreMock).toHaveBeenCalledTimes(1);
  });

  it("disables the bottom Load more footer while a continuation fetch is in flight", () => {
    mockLazy = false;
    mockTruncated = true;
    mockIsFetchingNextPage = true;
    renderBrowser();
    const buttons = screen.getAllByRole("button", { name: /load more/i });
    // Footer is the last "Load more"; it must be disabled to block double-submit
    // (Mantine `loading` shows a spinner but does not block clicks).
    expect(buttons[buttons.length - 1]).toBeDisabled();
  });
});
