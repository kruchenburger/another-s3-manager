import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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
    files: [{ name: "report.pdf", is_directory: false, size: 1234, last_modified: "" }],
    truncated: false,
    loadMore: vi.fn(),
    loadAll: vi.fn(),
    isFetching: false,
    isFetchingNextPage: false,
    error: null,
  }),
}));
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({
    data: {
      items_per_page: 200,
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

describe("FileBrowser handleDownload", () => {
  let originalCreate: typeof URL.createObjectURL;
  let originalRevoke: typeof URL.revokeObjectURL;

  beforeEach(() => {
    vi.restoreAllMocks();
    originalCreate = URL.createObjectURL;
    originalRevoke = URL.revokeObjectURL;
    // jsdom doesn't implement these — stub them so the success path doesn't blow up
    URL.createObjectURL = vi.fn().mockReturnValue("blob:mock-url");
    URL.revokeObjectURL = vi.fn();
  });

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it("triggers a blob download on 2xx — does not navigate", async () => {
    const blob = new Blob(["pdf-bytes"], { type: "application/pdf" });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      blob: () => Promise.resolve(blob),
      headers: new Headers({ "Content-Disposition": 'attachment; filename="report.pdf"' }),
    });
    vi.stubGlobal("fetch", fetchMock);
    renderBrowser();
    fireEvent.click(screen.getByLabelText(/download report\.pdf/i));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    await waitFor(() => expect(URL.createObjectURL).toHaveBeenCalled());
  });

  it("shows a red toast on 403 and does not navigate", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      json: () => Promise.resolve({ detail: "You don't have access to this object" }),
      headers: new Headers(),
    });
    vi.stubGlobal("fetch", fetchMock);
    renderBrowser();
    fireEvent.click(screen.getByLabelText(/download report\.pdf/i));
    await waitFor(() =>
      expect(screen.getByText(/you don't have access to this object/i)).toBeInTheDocument(),
    );
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it("prefers the RFC 5987 filename*= UTF-8 variant over the ASCII fallback", async () => {
    // Spy on createElement to capture the anchor and read its `download` prop.
    // The backend emits BOTH params per RFC 5987; the ASCII `filename=` comes
    // first with non-ASCII bytes replaced by `_`. Without picking the starred
    // variant, the saved filename loses Cyrillic/CJK characters.
    const realCreate = document.createElement.bind(document);
    const createSpy = vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      const el = realCreate(tag) as HTMLElement;
      return el;
    });

    const blob = new Blob(["pdf-bytes"], { type: "application/pdf" });
    const cyrillicHeader =
      "attachment; filename=\"_____.pdf\"; filename*=UTF-8''%D1%82%D0%B5%D1%81%D1%82.pdf";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        blob: () => Promise.resolve(blob),
        headers: new Headers({ "Content-Disposition": cyrillicHeader }),
      }),
    );
    renderBrowser();
    fireEvent.click(screen.getByLabelText(/download report\.pdf/i));
    await waitFor(() => expect(URL.createObjectURL).toHaveBeenCalled());

    const anchors = createSpy.mock.results
      .map((r) => r.value as HTMLElement)
      .filter((el): el is HTMLAnchorElement => el instanceof HTMLAnchorElement);
    const downloadAnchor = anchors.find((a) => a.download.length > 0);
    expect(downloadAnchor).toBeDefined();
    // The UTF-8 variant decodes to "тест.pdf"; the ASCII fallback is "_____.pdf".
    expect(downloadAnchor!.download).toBe("тест.pdf");
  });
});
