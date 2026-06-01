import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { FileBrowserHeader } from "@/components/FileBrowser/FileBrowserHeader";

function renderHeader(
  overrides: Partial<React.ComponentProps<typeof FileBrowserHeader>> = {},
) {
  return render(
    <MantineProvider>
      <MemoryRouter>
        <FileBrowserHeader
          bucket="b"
          roleId="r"
          path=""
          searchQuery=""
          onSearchChange={vi.fn()}
          mode="table"
          onModeChange={vi.fn()}
          selectedCount={0}
          onBulkDelete={vi.fn()}
          onBulkCopyUrl={vi.fn()}
          onUploadClick={vi.fn()}
          onUploadFolderClick={vi.fn()}
          objectCount={0}
          truncated={false}
          isLoadingMore={false}
          onLoadMore={vi.fn()}
          onLoadAll={vi.fn()}
          {...overrides}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("FileBrowserHeader object count", () => {
  it("renders '0 objects' when count is zero", () => {
    renderHeader({ objectCount: 0 });
    expect(screen.getByText("0 objects")).toBeInTheDocument();
  });

  it("renders '1 object' (singular)", () => {
    renderHeader({ objectCount: 1 });
    expect(screen.getByText("1 object")).toBeInTheDocument();
  });

  it("renders 'N objects' when count > 1", () => {
    renderHeader({ objectCount: 5 });
    expect(screen.getByText("5 objects")).toBeInTheDocument();
  });

  it("renders 'N+ objects' and Load more/Load all buttons when truncated", () => {
    renderHeader({ objectCount: 5, truncated: true });
    expect(screen.getByText("5+ objects")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /load more/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /load all/i }),
    ).toBeInTheDocument();
  });

  it("hides Load more/Load all when not truncated", () => {
    renderHeader({ objectCount: 5, truncated: false });
    expect(
      screen.queryByRole("button", { name: /load more/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /load all/i }),
    ).not.toBeInTheDocument();
  });

  it("calls onLoadMore / onLoadAll when their buttons are clicked", async () => {
    const onLoadMore = vi.fn();
    const onLoadAll = vi.fn();
    renderHeader({ objectCount: 5, truncated: true, onLoadMore, onLoadAll });
    await userEvent.click(screen.getByRole("button", { name: /load more/i }));
    expect(onLoadMore).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: /load all/i }));
    expect(onLoadAll).toHaveBeenCalledTimes(1);
  });

  it("renders SegmentedControl for view picker (Task 13 — verifying §4.4 already done)", () => {
    const { container } = renderHeader();
    // Mantine's SegmentedControl exposes role="radiogroup".
    expect(container.querySelector('[role="radiogroup"]')).not.toBeNull();
  });
});

describe("FileBrowserHeader — Upload folder button", () => {
  it("renders the 'Upload folder' button and calls onUploadFolderClick when clicked", async () => {
    const onUploadFolderClick = vi.fn();
    renderHeader({ onUploadFolderClick });
    const button = screen.getByRole("button", { name: /upload folder/i });
    expect(button).toBeInTheDocument();
    await userEvent.click(button);
    expect(onUploadFolderClick).toHaveBeenCalledTimes(1);
  });
});
