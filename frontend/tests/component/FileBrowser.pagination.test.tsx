import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { vi, describe, it, expect, beforeEach } from "vitest";

// Mock the IntersectionObserver-based hook so we can trigger inView=true on demand.
let mockInView = false;
vi.mock("react-intersection-observer", () => ({
  useInView: () => ({ ref: () => {}, inView: mockInView }),
}));

// Mock useFiles to control pages + hasNextPage.
const fetchNextPageMock = vi.fn();
vi.mock("@/features/files/hooks/useFiles", () => ({
  filesQueryKey: (b: string, r: string, p: string) =>
    ["files", "list", r, b, p] as const,
  filesQueryKeyFull: (b: string, r: string, p: string, s: number) =>
    ["files", "list", r, b, p, s] as const,
  useFiles: () => ({
    data: {
      pages: [
        {
          directories: [{ name: "logs", is_directory: true, size: 0 }],
          files: [
            { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
            { name: "b.txt", is_directory: false, size: 1, last_modified: "" },
          ],
          next_token: "tok-1",
          has_more: true,
        },
      ],
    },
    isFetching: false,
    isFetchingNextPage: false,
    hasNextPage: true,
    fetchNextPage: fetchNextPageMock,
    error: null,
  }),
}));

// Mock useConfig — controls items_per_page + enable_lazy_loading.
let mockLazy = true;
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      items_per_page: 50,
      enable_lazy_loading: mockLazy,
      max_file_size: 100 * 1024 * 1024,
      disable_deletion: false,
      roles: [],
    },
  }),
}));

// Adjacent mocks (mirror sibling FileBrowser tests).
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

function renderBrowser() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/r/RoleA/b/my-bucket/p/"]}>
          <Routes>
            <Route
              path="/r/:roleId/b/:bucket/p/*"
              element={<FileBrowser />}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("FileBrowser pagination", () => {
  beforeEach(() => {
    fetchNextPageMock.mockReset();
    mockInView = false;
    mockLazy = true;
  });

  it("renders directories from page 0 + files flat-mapped", () => {
    renderBrowser();
    expect(screen.getByText("logs")).toBeInTheDocument();
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(screen.getByText("b.txt")).toBeInTheDocument();
  });

  it("auto-fires fetchNextPage when sentinel scrolls into view (lazy=true)", async () => {
    mockInView = true;
    renderBrowser();
    await waitFor(() => expect(fetchNextPageMock).toHaveBeenCalledTimes(1));
  });

  it("renders Load more button instead of sentinel when lazy=false", async () => {
    mockLazy = false;
    renderBrowser();
    const btn = await screen.findByRole("button", { name: /load more/i });
    fireEvent.click(btn);
    expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
  });

  it("shows filter banner when search is active and has_more is true", async () => {
    renderBrowser();
    // Find the search input — placeholder text comes from FileBrowserHeader.
    // Be defensive: try common labels; if neither matches, find by role=searchbox.
    let filterInput: HTMLElement | null = null;
    try {
      filterInput = screen.getByPlaceholderText(/filter|search/i);
    } catch {
      filterInput = screen.getByRole("searchbox");
    }
    fireEvent.change(filterInput, { target: { value: "a" } });
    expect(
      await screen.findByText(/load more to search the rest/i),
    ).toBeInTheDocument();
  });
});
