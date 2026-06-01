import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { vi, describe, it, expect, beforeEach } from "vitest";

let mockInView = false;
vi.mock("react-intersection-observer", () => ({
  useInView: () => ({ ref: () => {}, inView: mockInView }),
}));

const loadMoreMock = vi.fn();
const loadAllMock = vi.fn();
let mockTruncated = false;
let mockFiles = [
  { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
  { name: "b.txt", is_directory: false, size: 1, last_modified: "" },
];
vi.mock("@/features/files/hooks/useFiles", () => ({
  filesQueryKey: (b: string, r: string, p: string) => ["files", "list", r, b, p],
  useFiles: () => ({
    directories: [{ name: "logs", is_directory: true, size: 0 }],
    files: mockFiles,
    truncated: mockTruncated,
    loadMore: loadMoreMock,
    loadAll: loadAllMock,
    isFetching: false,
    isFetchingNextPage: false,
    error: null,
  }),
}));

let mockLazy = true;
let mockItemsPerPage = 200;
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      items_per_page: mockItemsPerPage,
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

function renderBrowser() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/r/RoleA/b/my-bucket/p/"]}>
          <Routes>
            <Route path="/r/:roleId/b/:bucket/p/*" element={<FileBrowser />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("FileBrowser hybrid pagination", () => {
  beforeEach(() => {
    loadMoreMock.mockReset();
    loadAllMock.mockReset();
    mockInView = false;
    mockLazy = true;
    mockTruncated = false;
    mockItemsPerPage = 200;
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
    fireEvent.click(screen.getByRole("button", { name: /load more/i }));
    expect(loadMoreMock).toHaveBeenCalledTimes(1);
  });

  it("Load all triggers a full drain", () => {
    mockTruncated = true;
    renderBrowser();
    fireEvent.click(screen.getByRole("button", { name: /load all/i }));
    expect(loadAllMock).toHaveBeenCalledTimes(1);
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
});
