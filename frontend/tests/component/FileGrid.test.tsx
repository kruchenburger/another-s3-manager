import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRef } from "react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { FileEntry } from "@/types/api";

const ROW = 180;
// 12 items, 4 columns => 3 grid rows. Mock a window of grid-rows 0..1.
let windowEnd = 1;
let lastIndexForAutoload = 1;
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: windowEnd + 1 }, (_, index) => ({
        index: index === windowEnd ? lastIndexForAutoload : index,
        key: index,
        start: index * ROW,
        size: ROW,
        end: (index + 1) * ROW,
      })),
    getTotalSize: () => count * ROW,
    measureElement: () => {},
  }),
}));

// 4 columns regardless of width in jsdom (useElementSize returns 0 width there;
// the component falls back to the `base` cols — override via mock so the test
// is deterministic).
vi.mock("@mantine/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mantine/hooks")>();
  return {
    ...actual,
    useElementSize: () => ({ ref: () => {}, width: 1000, height: 0 }),
  };
});

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { disable_deletion: false } }),
}));
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({ data: { auto_inline_extensions: [] } }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: () => ({ data: undefined }),
}));

import { FileGrid } from "@/components/FileBrowser/FileGrid";

const files: FileEntry[] = Array.from({ length: 12 }, (_, i) => ({
  name: `g${i}.txt`,
  is_directory: false,
  size: 1,
  last_modified: "",
}));

const onLoadMore = vi.fn();

function Harness(props: Partial<React.ComponentProps<typeof FileGrid>> = {}) {
  const ref = useRef<HTMLDivElement>(null);
  const qc = new QueryClient();
  return (
    <MantineProvider>
      <QueryClientProvider client={qc}>
        <div ref={ref}>
          <FileGrid
            files={files}
            selected={new Set()}
            onToggleSelect={() => {}}
            onNavigate={() => {}}
            onDownload={() => {}}
            onCopyUrl={() => {}}
            onPreview={() => {}}
            onDelete={() => {}}
            bucket="b"
            roleId="r"
            path=""
            scrollRef={ref}
            autoLoadEnabled={false}
            onLoadMore={onLoadMore}
            {...props}
          />
        </div>
      </QueryClientProvider>
    </MantineProvider>
  );
}

describe("FileGrid virtualization", () => {
  beforeEach(() => {
    onLoadMore.mockReset();
    windowEnd = 1;
    lastIndexForAutoload = 1;
  });

  it("renders only cards in the virtual grid-row window", () => {
    render(<Harness />);
    // 4 cols, rows 0..1 => items g0..g7 visible; g8.. hidden.
    expect(screen.getByText("g0.txt")).toBeInTheDocument();
    expect(screen.getByText("g7.txt")).toBeInTheDocument();
    expect(screen.queryByText("g8.txt")).not.toBeInTheDocument();
  });

  it("auto-loads when enabled and the grid-row window is at the end", () => {
    lastIndexForAutoload = 2; // last grid row (12 items / 4 cols = 3 rows -> idx 2)
    render(<Harness autoLoadEnabled />);
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("does not auto-load when disabled", () => {
    lastIndexForAutoload = 2;
    render(<Harness autoLoadEnabled={false} />);
    expect(onLoadMore).not.toHaveBeenCalled();
  });
});
