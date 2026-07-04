import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { vi, describe, it, expect, beforeEach } from "vitest";

// Render all items — virtualizer is mocked at the same granularity as the
// pagination test to keep assertions layout-independent.
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

// ---------------------------------------------------------------------------
// useFiles mock — folder source
// ---------------------------------------------------------------------------
let mockTruncated = false;
let mockDirectories = [{ name: "logs", is_directory: true, size: 0 }];
let mockFiles = [
  { name: "aaa.txt", is_directory: false, size: 1, last_modified: "" },
  { name: "bbb.txt", is_directory: false, size: 1, last_modified: "" },
];
vi.mock("@/features/files/hooks/useFiles", () => ({
  filesQueryKey: (b: string, r: string, p: string) => ["files", "list", r, b, p],
  useFiles: () => ({
    directories: mockDirectories,
    files: mockFiles,
    truncated: mockTruncated,
    loadMore: () => Promise.resolve(),
    loadAll: () => Promise.resolve(),
    isFetching: false,
    isFetchingNextPage: false,
    isFetchNextPageError: false,
    error: null,
  }),
}));

// ---------------------------------------------------------------------------
// useFileSearch mock — server search source
// ---------------------------------------------------------------------------
let mockSearchDirectories: { name: string; is_directory: boolean; size: number }[] = [];
let mockSearchFiles: { name: string; is_directory: boolean; size: number; last_modified?: string }[] = [];
let mockSearchTruncated = false;
vi.mock("@/features/files/hooks/useFileSearch", () => ({
  fileSearchQueryKey: (b: string, r: string, p: string, t: string) => [
    "files",
    "search",
    r,
    b,
    p,
    t,
  ],
  useFileSearch: () => ({
    directories: mockSearchDirectories,
    files: mockSearchFiles,
    truncated: mockSearchTruncated,
    loadMore: () => Promise.resolve(),
    loadAll: () => Promise.resolve(),
    isFetching: false,
    isFetchingNextPage: false,
    isFetchNextPageError: false,
    error: null,
  }),
}));

vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      enable_lazy_loading: true,
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

// Resolve the filter input regardless of placeholder wording.
function getFilterInput() {
  try {
    return screen.getByPlaceholderText(/filter|search/i);
  } catch {
    return screen.getByRole("searchbox");
  }
}

describe("FileBrowser server-search mode", () => {
  beforeEach(() => {
    mockTruncated = false;
    mockDirectories = [{ name: "logs", is_directory: true, size: 0 }];
    mockFiles = [
      { name: "aaa.txt", is_directory: false, size: 1, last_modified: "" },
      { name: "bbb.txt", is_directory: false, size: 1, last_modified: "" },
    ];
    mockSearchDirectories = [];
    mockSearchFiles = [];
    mockSearchTruncated = false;
  });

  it("hides the server-search affordance when the folder is not truncated", async () => {
    mockTruncated = false;
    renderBrowser();
    fireEvent.change(getFilterInput(), { target: { value: "4f2a" } });
    // Wait for debounce — the affordance must NOT appear.
    await new Promise((r) => setTimeout(r, 250));
    expect(
      screen.queryByText(/search.*on server/i),
    ).not.toBeInTheDocument();
  });

  it("hides the server-search affordance when no term is typed", async () => {
    mockTruncated = true;
    renderBrowser();
    // No typing — affordance should be absent.
    await new Promise((r) => setTimeout(r, 50));
    expect(
      screen.queryByText(/search.*on server/i),
    ).not.toBeInTheDocument();
  });

  it("shows the affordance when folder is truncated AND a term is typed", async () => {
    mockTruncated = true;
    renderBrowser();
    fireEvent.change(getFilterInput(), { target: { value: "4f2a" } });
    expect(
      await screen.findByText(/search "4f2a" on server/i),
    ).toBeInTheDocument();
  });

  it("switches to the search source after clicking the affordance", async () => {
    mockTruncated = true;
    mockSearchFiles = [
      { name: "4f2a1c", is_directory: false, size: 1, last_modified: "" },
    ];
    renderBrowser();
    fireEvent.change(getFilterInput(), { target: { value: "4f2a" } });
    const affordance = await screen.findByText(/search "4f2a" on server/i);
    fireEvent.click(affordance);

    // The folder items (aaa.txt, bbb.txt) come from folder source; after
    // switching, the search source (4f2a1c) should be visible instead.
    expect(await screen.findByText("4f2a1c")).toBeInTheDocument();
    // The chip indicating server-search mode must be present.
    expect(
      screen.getByText(/server search \(starts-with, case-sensitive\):/i),
    ).toBeInTheDocument();
    expect(screen.getByText("4f2a")).toBeInTheDocument();
  });

  it("exits server-search and returns to the folder list when the chip is closed", async () => {
    mockTruncated = true;
    mockSearchFiles = [
      { name: "4f2a1c", is_directory: false, size: 1, last_modified: "" },
    ];
    renderBrowser();
    // Enter server search.
    fireEvent.change(getFilterInput(), { target: { value: "4f2a" } });
    const affordance = await screen.findByText(/search "4f2a" on server/i);
    fireEvent.click(affordance);
    await screen.findByText("4f2a1c");

    // Click the CloseButton on the chip.
    fireEvent.click(screen.getByLabelText("Exit server search"));

    // Chip is gone — the mode has been exited.
    await waitFor(() =>
      expect(
        screen.queryByText(/server search \(starts-with, case-sensitive\):/i),
      ).not.toBeInTheDocument(),
    );
    // Search box still holds "4f2a" — client-side filter is active again.
    // The search-source result (4f2a1c) should be gone from the display.
    expect(screen.queryByText("4f2a1c")).not.toBeInTheDocument();

    // Clearing the search input restores the full folder listing.
    fireEvent.change(getFilterInput(), { target: { value: "" } });
    expect(await screen.findByText("aaa.txt")).toBeInTheDocument();
    expect(screen.getByText("bbb.txt")).toBeInTheDocument();
  });

  it("shows the empty-state message when the search source returns no results", async () => {
    mockTruncated = true;
    // Leave mockSearchFiles = [] (empty by default in beforeEach).
    renderBrowser();
    fireEvent.change(getFilterInput(), { target: { value: "4f2a" } });
    const affordance = await screen.findByText(/search "4f2a" on server/i);
    fireEvent.click(affordance);

    expect(
      await screen.findByText(/no items start with "4f2a" here/i),
    ).toBeInTheDocument();
  });
});
