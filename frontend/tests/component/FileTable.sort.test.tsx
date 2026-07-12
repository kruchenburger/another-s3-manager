import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRef } from "react";
import { vi, describe, it, expect } from "vitest";
import type { FileEntry } from "@/types/api";

// Sort-header tests only need the <thead>: render ZERO body rows so no
// FileRow (and none of its data hooks) ever mounts.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: () => ({
    getVirtualItems: () => [],
    getTotalSize: () => 0,
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
import { DEFAULT_SORT, type SortColumn, type SortState } from "@/utils/sortEntries";

const files: FileEntry[] = [
  { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
];

function Harness({
  sortState = DEFAULT_SORT,
  onSortColumn = () => {},
}: {
  sortState?: SortState;
  onSortColumn?: (column: SortColumn) => void;
}) {
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
            onLoadMore={() => {}}
            sortState={sortState}
            onSortColumn={onSortColumn}
          />
        </div>
      </QueryClientProvider>
    </MantineProvider>
  );
}

// The <th>'s accessible name is "Size" (name-from-content), not "Sort by size"
// — dom-accessibility-api does not fold a nested button's aria-label into its
// ancestor. Reach the header cell through its button instead of renaming the
// column for screen readers just to satisfy a query.
const headerCellFor = (buttonName: string): HTMLElement =>
  screen.getByRole("button", { name: buttonName }).closest("th") as HTMLElement;

describe("FileTable sortable headers", () => {
  it("reports the clicked column for Name, Size, and Modified", async () => {
    const onSortColumn = vi.fn();
    render(<Harness onSortColumn={onSortColumn} />);
    await userEvent.click(screen.getByRole("button", { name: "Sort by name" }));
    await userEvent.click(screen.getByRole("button", { name: "Sort by size" }));
    await userEvent.click(
      screen.getByRole("button", { name: "Sort by modified" }),
    );
    expect(onSortColumn.mock.calls).toEqual([["name"], ["size"], ["modified"]]);
  });

  it("marks the active column with aria-sort and the others with 'none'", () => {
    render(<Harness sortState={{ column: "size", direction: "desc" }} />);
    expect(headerCellFor("Sort by size")).toHaveAttribute(
      "aria-sort",
      "descending",
    );
    expect(headerCellFor("Sort by name")).toHaveAttribute("aria-sort", "none");
    expect(headerCellFor("Sort by modified")).toHaveAttribute(
      "aria-sort",
      "none",
    );
  });

  it("uses 'ascending' for asc on the active column", () => {
    render(<Harness sortState={{ column: "name", direction: "asc" }} />);
    expect(headerCellFor("Sort by name")).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
  });

  it("shows a direction chevron only on the active column", () => {
    render(<Harness sortState={{ column: "modified", direction: "asc" }} />);
    const active = screen.getByRole("button", { name: "Sort by modified" });
    const inactive = screen.getByRole("button", { name: "Sort by name" });
    expect(active.querySelector("svg")).not.toBeNull();
    expect(inactive.querySelector("svg")).toBeNull();
  });

  it("does not make the Actions header sortable", () => {
    render(<Harness />);
    expect(
      screen.queryByRole("button", { name: /sort by actions/i }),
    ).toBeNull();
    expect(
      screen.getByRole("columnheader", { name: /actions/i }),
    ).not.toHaveAttribute("aria-sort");
  });
});
