import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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
let mockFetchingNextPage = false;
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
    isFetchingNextPage: mockFetchingNextPage,
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
    mockInView = false;
    mockLazy = true;
    mockTruncated = false;
    mockFetchingNextPage = false;
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

  it("Show more reveals the next in-memory slice (non-lazy)", async () => {
    mockLazy = false;
    mockItemsPerPage = 2;
    mockTruncated = false;
    mockFiles = Array.from({ length: 5 }, (_, i) => ({
      name: `f${i}.txt`,
      is_directory: false,
      size: 1,
      last_modified: "",
    }));
    renderBrowser();
    // visibleCount starts at 2 → [logs, f0]. f1 hidden behind the slice.
    expect(screen.queryByText("f1.txt")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /show more/i }));
    expect(await screen.findByText("f1.txt")).toBeInTheDocument();
  });

  it("reveals more in-memory items when the sentinel scrolls into view (lazy)", async () => {
    // 5 files + 1 dir = 6 items, page size 2 → first slice [logs, f0]. The
    // sentinel starts out of view, then scrolls in (re-render with inView=true),
    // which fires the reveal effect — mirroring how IntersectionObserver fires
    // its callback AFTER mount in the real browser. The full multi-step cascade
    // is exercised live (Playwright); here we assert the lazy effect reveals
    // beyond the initial slice (the stall bug left exactly itemsPerPage rows).
    mockItemsPerPage = 2;
    mockInView = false;
    mockTruncated = false;
    mockFiles = Array.from({ length: 5 }, (_, i) => ({
      name: `f${i}.txt`,
      is_directory: false,
      size: 1,
      last_modified: "",
    }));
    const { rerender } = renderBrowser();
    expect(screen.queryByText("f1.txt")).not.toBeInTheDocument();
    // Sentinel scrolls into view → effect reveals the next slice.
    mockInView = true;
    rerender(browserTree());
    await waitFor(() => expect(screen.getByText("f1.txt")).toBeInTheDocument());
  });

  it("reveals exactly one slice per sentinel hit — no cascade through the whole set", async () => {
    // Regression for af71e9e: the reveal effect was made to depend on
    // files.length plus an unstable handler, so a single sentinel-in-view
    // cascaded synchronously through every remaining slice (observed live:
    // one scroll jumped a 239-object folder from 30 rendered rows to all 239
    // in a single frame). Per the hybrid design the in-memory slice must grow
    // by exactly itemsPerPage per sentinel hit. The sentinel scrolls in via an
    // inView false→true re-render, mirroring how IntersectionObserver fires
    // its callback after mount in the real browser.
    mockItemsPerPage = 2;
    mockInView = false;
    mockTruncated = false;
    mockFiles = Array.from({ length: 5 }, (_, i) => ({
      name: `f${i}.txt`,
      is_directory: false,
      size: 1,
      last_modified: "",
    }));
    const { rerender } = renderBrowser();
    // items = [logs, f0, f1, f2, f3, f4]; initial slice = 2 → [logs, f0].
    expect(screen.queryByText("f2.txt")).not.toBeInTheDocument();
    mockInView = true;
    rerender(browserTree());
    // One reveal grows the slice to 4 → [logs, f0, f1, f2]; f2 becomes visible.
    await waitFor(() => expect(screen.getByText("f2.txt")).toBeInTheDocument());
    // The cascade bug would have revealed the entire set in one go, so the
    // last item is the discriminator — it must stay behind the slice.
    expect(screen.queryByText("f4.txt")).not.toBeInTheDocument();
  });

  it("plays the entry stagger only on the first screenful, not on every loaded row", () => {
    // Regression: the per-row fadeIn delay (--row-index * 30ms) grew unbounded,
    // so lazy-revealed rows sat invisible (opacity 0) for 1.6–3.5s waiting on
    // their delay. The stagger must be capped to the first screenful; rows past
    // it — the tail of a big page AND every lazy-revealed row — render instantly.
    mockItemsPerPage = 100; // show everything, no lazy slice involved
    mockTruncated = false;
    mockFiles = Array.from({ length: 25 }, (_, i) => ({
      name: `f${String(i).padStart(2, "0")}.txt`,
      is_directory: false,
      size: 1,
      last_modified: "",
    }));
    const { container } = renderBrowser();
    const rows = Array.from(container.querySelectorAll("table tbody tr"));
    const animated = rows.filter((r) => r.className.includes("animateIn"));
    // Some rows animate in (cold-load delight) but the count is capped — the
    // tail rows render instantly.
    expect(animated.length).toBeGreaterThan(0);
    expect(animated.length).toBeLessThan(rows.length);
    // The very last row (well past the first screen) must not animate.
    expect(rows[rows.length - 1].className).not.toContain("animateIn");
  });

  it("does not auto-fetch a server chunk from the scroll sentinel (header-only continuation)", async () => {
    // Per the hybrid design, server continuation ("Load more" / "Load all") is
    // ALWAYS an explicit header button — the lazy-scroll sentinel only grows
    // the in-memory slice and must never trigger a network fetch. af71e9e wired
    // the sentinel to loadMore() once the slice was exhausted; this pins it shut.
    mockItemsPerPage = 200; // slice already covers every loaded item
    mockInView = false;
    mockTruncated = true; // server has more, but only the header may pull it
    const { rerender } = renderBrowser();
    await screen.findByText("a.txt");
    mockInView = true; // sentinel scrolls into view
    rerender(browserTree());
    expect(loadMoreMock).not.toHaveBeenCalled();
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
