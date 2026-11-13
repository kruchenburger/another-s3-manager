import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  render,
  fireEvent,
  waitFor,
  screen,
  act,
  within,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Mock the files API layer — only `buildDownloadUrl` is invoked synchronously
// on render via FileRow; everything else is stubbed so we never hit network.
vi.mock("@/features/files/api/filesApi", () => ({
  listBuckets: vi.fn(),
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  deleteFile: vi.fn(),
  buildDownloadUrl: (b: string, r: string, p: string) =>
    `/api/buckets/${b}/download?role=${r}&path=${encodeURIComponent(p)}`,
  getPresignedDownloadUrl: vi.fn(),
}));

// `useUpload` is the spy under test — declare a module-scoped mock fn so the
// test body can re-bind its return value per case.
const mutateAsyncMock = vi.fn();
const { fileList } = vi.hoisted(() => ({
  fileList: [] as Array<{
    name: string;
    is_directory: boolean;
    size: number;
    last_modified: string;
  }>,
}));

vi.mock("@/features/files/hooks/useFiles", () => ({
  useFiles: () => ({
    directories: [],
    files: fileList,
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
  // FileBrowser invalidates the files query once at the end of a bulk
  // upload (see skipInvalidation pattern in useUpload). The mock has to
  // expose the same query-key helper the real module does, otherwise the
  // post-batch invalidateQueries call throws "No filesQueryKey export".
  // Preserve the original shape — mocks don't trigger real invalidations,
  // so the exact tuple ordering is irrelevant.
  filesQueryKey: (bucket: string, role: string, path: string) => [
    "files",
    bucket,
    role,
    path,
  ],
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
  useUpload: () => ({ mutateAsync: mutateAsyncMock }),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({
    data: {
      is_admin: true,
      disable_deletion: false,
      allowed_roles: ["my-role"],
      role_permissions: { "my-role": { delete: true } },
    },
  }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: () => ({ data: undefined, isSuccess: false }),
}));

import { FileBrowser } from "@/components/FileBrowser/FileBrowser";
import { sessionCoordinator } from "@/features/auth/hooks/useSessionIdentity";
import { deleteFile } from "@/features/files/api/filesApi";
import type { MeResponse } from "@/types/api";

async function renderBrowser() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const coordinator = sessionCoordinator(qc);
  await coordinator.accept(
    {
      username: "a",
      session_identity: "a",
      csrf_token: "csrf-a",
    } as MeResponse,
    coordinator.generation,
  );
  const view = render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter
          initialEntries={["/r/my-role/b/my-bucket/p/existing/folder"]}
        >
          <Routes>
            <Route path="/r/:roleId/b/:bucket/p/*" element={<FileBrowser />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
  return { ...view, coordinator };
}

describe("FileBrowser — folder upload", () => {
  beforeEach(() => {
    fileList.length = 0;
    vi.mocked(deleteFile).mockReset();
    mutateAsyncMock.mockReset();
    mutateAsyncMock.mockResolvedValue(undefined);
  });

  it("uploads each file via webkitdirectory FileList with currentPath-prefixed key", async () => {
    await renderBrowser();

    // The folder-upload input is hidden (display: none) and has no a11y role —
    // selecting it via DOM query is the pragmatic choice. The component renders
    // exactly one input with webkitdirectory set.
    const folderInput = document.querySelector(
      'input[type="file"][webkitdirectory]',
    ) as HTMLInputElement | null;
    expect(folderInput).not.toBeNull();

    // Synthesize two File entries with webkitRelativePath populated, mimicking
    // what the browser produces when the user picks a directory.
    const f1 = new File(["a"], "a.txt", { type: "text/plain" });
    Object.defineProperty(f1, "webkitRelativePath", { value: "docs/a.txt" });
    const f2 = new File(["b"], "b.txt", { type: "text/plain" });
    Object.defineProperty(f2, "webkitRelativePath", {
      value: "docs/sub/b.txt",
    });

    // jsdom's HTMLInputElement.files is normally read-only; override via
    // defineProperty so the change handler sees our synthetic FileList.
    Object.defineProperty(folderInput, "files", {
      value: [f1, f2],
      configurable: true,
    });

    fireEvent.change(folderInput!);

    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(2));

    // Assert that each call carries the expected S3 key shape:
    // `${currentPath}/${webkitRelativePath}` — order isn't guaranteed across
    // the async loop, so sort before comparing.
    const keys = mutateAsyncMock.mock.calls.map((c) => c[0].key).sort();
    expect(keys).toEqual([
      "existing/folder/docs/a.txt",
      "existing/folder/docs/sub/b.txt",
    ]);

    // Sanity-check the rest of the upload payload shape on the first call.
    const firstArg = mutateAsyncMock.mock.calls[0][0];
    expect(firstArg.bucket).toBe("my-bucket");
    expect(firstArg.role).toBe("my-role");
    expect(firstArg.currentPath).toBe("existing/folder");
    expect(firstArg.file).toBeInstanceOf(File);
  });

  it("test_bulk_upload_stops_after_session_change", async () => {
    const { coordinator } = await renderBrowser();
    let finish!: () => void;
    mutateAsyncMock.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const input = document.querySelector(
      'input[type="file"][webkitdirectory]',
    )!;
    Object.defineProperty(input, "files", {
      value: [new File(["a"], "a.txt"), new File(["b"], "b.txt")],
    });
    fireEvent.change(input);
    await waitFor(() => expect(mutateAsyncMock).toHaveBeenCalledTimes(1));
    await act(async () => {
      await coordinator.accept(
        {
          username: "b",
          session_identity: "b",
          csrf_token: "csrf-b",
        } as MeResponse,
        coordinator.generation,
      );
      finish();
    });
    expect(mutateAsyncMock.mock.calls[0][0].signal.aborted).toBe(true);
    expect(mutateAsyncMock).toHaveBeenCalledTimes(1);
  });

  it("test_bulk_delete_stops_after_session_change", async () => {
    fileList.push(
      ...["a.txt", "b.txt"].map((name) => ({
        name,
        is_directory: false,
        size: 1,
        last_modified: "",
      })),
    );
    const { coordinator } = await renderBrowser();
    let finish!: () => void;
    vi.mocked(deleteFile).mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleteFile).toHaveBeenCalledTimes(1));
    await act(async () => {
      await coordinator.accept(
        {
          username: "b",
          session_identity: "b",
          csrf_token: "csrf-b",
        } as MeResponse,
        coordinator.generation,
      );
      finish();
    });
    expect(vi.mocked(deleteFile).mock.calls[0][3]?.aborted).toBe(true);
    expect(deleteFile).toHaveBeenCalledTimes(1);
  });
});
