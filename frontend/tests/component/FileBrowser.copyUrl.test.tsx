import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Render every item — windowing itself is covered by Playwright E2E.
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

vi.mock("@/features/files/api/filesApi", () => ({
  listBuckets: vi.fn(),
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  deleteFile: vi.fn(),
  buildDownloadUrl: (b: string, r: string, p: string) =>
    `/api/buckets/${b}/download?role=${r}&path=${encodeURIComponent(p)}`,
  getPresignedDownloadUrl: vi.fn(),
}));
vi.mock("@/features/files/hooks/useFiles", () => ({
  // 3-arg key — used by useDelete/useUpload/FileBrowser invalidateQueries.
  filesQueryKey: (b: string, r: string, p: string) =>
    ["files", "list", r, b, p] as const,
  useFiles: () => ({
    directories: [],
    files: [{ name: "photo.jpg", is_directory: false, size: 1234, last_modified: "" }],
    truncated: false,
    loadMore: vi.fn(),
    loadAll: vi.fn(),
    // FileBrowser's Finding-1 cleanup effect calls this on every unmount/route
    // change; the mock must supply a callable or that effect throws.
    stopLoadAll: vi.fn(),
    isFetching: false,
    isFetchingNextPage: false,
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
      presigned_url_default_ttl: 3600,
      presigned_url_max_ttl: 604800,
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

import { FileBrowser } from "@/components/FileBrowser/FileBrowser";
import { getPresignedDownloadUrl } from "@/features/files/api/filesApi";

function renderBrowser() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
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

describe("FileBrowser Copy URL", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("copies the presigned URL (not the proxy URL) for a single file", async () => {
    vi.mocked(getPresignedDownloadUrl).mockResolvedValueOnce({
      url: "https://signed.example/photo.jpg?X-Amz-Signature=abc",
      expires_at: "2026-05-05T12:00:00+00:00",
      expires_in: 3600,
    });
    renderBrowser();
    fireEvent.click(screen.getByLabelText("Copy URL"));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        "https://signed.example/photo.jpg?X-Amz-Signature=abc",
      ),
    );
    expect(getPresignedDownloadUrl).toHaveBeenCalledWith(
      "my-bucket",
      "RoleA",
      "photo.jpg",
      undefined,
    );
  });

  it("shows a yellow warning toast when the response carries a warning", async () => {
    vi.mocked(getPresignedDownloadUrl).mockResolvedValueOnce({
      url: "https://signed.example/photo.jpg?X-Amz-Signature=xyz",
      expires_at: "2026-06-11T18:42:00Z",
      expires_in: 86400,
      warning:
        "This role uses temporary credentials — the link may stop working earlier, when the role's session expires.",
    });
    renderBrowser();
    fireEvent.click(screen.getByLabelText("Copy URL"));
    expect(
      await screen.findByText(/temporary credentials/i),
    ).toBeInTheDocument();
  });
});
