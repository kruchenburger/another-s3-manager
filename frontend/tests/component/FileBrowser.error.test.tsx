import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "@/utils/apiError";

const useFilesMock = vi.fn();
vi.mock("@/features/files/hooks/useFiles", () => ({
  useFiles: (...args: unknown[]) => useFilesMock(...args),
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
vi.mock("@/features/files/api/filesApi", () => ({
  buildDownloadUrl: () => "/api/buckets/x/download",
  getPresignedDownloadUrl: vi.fn(),
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

describe("FileBrowser error rendering", () => {
  beforeEach(() => useFilesMock.mockReset());

  it("renders QueryErrorState when useFiles returns an error", () => {
    useFilesMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(400, "Bad Request", {
        detail: { code: "InvalidRegion", message: "Region is invalid for R2" },
      }),
    });
    renderBrowser();
    expect(screen.getByText(/couldn't load files/i)).toBeInTheDocument();
    expect(screen.getByText("Region is invalid for R2")).toBeInTheDocument();
    // The "empty folder" state must NOT appear when there is an error.
    expect(screen.queryByText(/this folder is empty/i)).not.toBeInTheDocument();
  });

  it("does NOT render the file table when stale data coexists with a fresh error", () => {
    // Stale-data race: cache returns data while a concurrent refetch fails.
    useFilesMock.mockReturnValue({
      data: { files: [{ name: "ghost.txt", is_directory: false, size: 1 }], path: "", total_count: 1 },
      isLoading: false,
      error: new ApiError(403, "Forbidden", { detail: "Access denied" }),
    });
    renderBrowser();
    expect(screen.getByText(/couldn't load files/i)).toBeInTheDocument();
    expect(screen.getByText("Access denied")).toBeInTheDocument();
    expect(screen.queryByText("ghost.txt")).not.toBeInTheDocument();
  });
});
