import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRef } from "react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { FileEntry } from "@/types/api";

// Mock the virtualizer to a deterministic WINDOW (indices 2..4 of a 10-row set)
// so the test asserts windowed rendering + spacer math without browser layout.
const ROW = 40;
let windowStart = 2;
let windowEnd = 4;
let lastIndexForAutoload = 4;
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: windowEnd - windowStart + 1 }, (_, k) => {
        const index = windowStart + k;
        return { index, key: index, start: index * ROW, size: ROW, end: (index + 1) * ROW };
      }).map((item) =>
        item.index === windowEnd ? { ...item, index: lastIndexForAutoload } : item,
      ),
    getTotalSize: () => count * ROW,
    measureElement: () => {},
  }),
}));

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { disable_deletion: false } }),
}));
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({ data: { preview_text_extensions: [] } }),
}));

import { FileTable } from "@/components/FileBrowser/FileTable";

const files: FileEntry[] = Array.from({ length: 10 }, (_, i) => ({
  name: `f${i}.txt`,
  is_directory: false,
  size: 1,
  last_modified: "",
}));

const onLoadMore = vi.fn();

function Harness(props: Partial<React.ComponentProps<typeof FileTable>> = {}) {
  const ref = useRef<HTMLDivElement>(null);
  const qc = new QueryClient();
  return (
    <MantineProvider>
      <QueryClientProvider client={qc}>
        <div ref={ref}>
          <FileTable
            files={files}
            selected={new Set()}
            onToggleSelect={() => {}}
            onToggleSelectAll={() => {}}
            onNavigate={() => {}}
            onDownload={() => {}}
            onCopyUrl={() => {}}
            onPreview={() => {}}
            onDelete={() => {}}
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

describe("FileTable virtualization", () => {
  beforeEach(() => {
    onLoadMore.mockReset();
    windowStart = 2;
    windowEnd = 4;
    lastIndexForAutoload = 4;
  });

  it("renders only the virtual window of rows", () => {
    render(<Harness />);
    expect(screen.getByText("f2.txt")).toBeInTheDocument();
    expect(screen.getByText("f4.txt")).toBeInTheDocument();
    expect(screen.queryByText("f0.txt")).not.toBeInTheDocument();
    expect(screen.queryByText("f9.txt")).not.toBeInTheDocument();
  });

  it("renders a sticky header with the select-all checkbox", () => {
    render(<Harness />);
    expect(screen.getByLabelText("Select all")).toBeInTheDocument();
  });

  it("uses spacer rows to offset the window (aria-hidden, data-spacer)", () => {
    const { container } = render(<Harness />);
    const spacers = container.querySelectorAll("tr[data-spacer]");
    expect(spacers.length).toBe(2); // top + bottom
  });

  it("auto-loads when enabled and the window is at the end", () => {
    lastIndexForAutoload = 9; // last row of the 10-row set
    render(<Harness autoLoadEnabled />);
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("does not auto-load when disabled", () => {
    lastIndexForAutoload = 9;
    render(<Harness autoLoadEnabled={false} />);
    expect(onLoadMore).not.toHaveBeenCalled();
  });
});
