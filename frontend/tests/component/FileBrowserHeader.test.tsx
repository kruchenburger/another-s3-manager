import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { FileBrowserHeader } from "@/components/FileBrowser/FileBrowserHeader";
import { DEFAULT_SORT } from "@/utils/sortEntries";

// Object-count rendering moved to BucketPageHeader (see its test file); this
// suite covers the pure controls toolbar: filter, view toggle, Load, Upload.
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
          onUploadClick={vi.fn()}
          onUploadFolderClick={vi.fn()}
          truncated={false}
          isLoadingMore={false}
          onLoadMore={vi.fn()}
          onLoadAll={vi.fn()}
          loadingAll={false}
          onStopLoadAll={vi.fn()}
          sortState={DEFAULT_SORT}
          onSortChange={vi.fn()}
          {...overrides}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("FileBrowserHeader — load controls", () => {
  it("renders a Load more control when truncated", () => {
    renderHeader({ truncated: true });
    expect(screen.getByRole("button", { name: "Load more" })).toBeInTheDocument();
  });

  it("hides the Load more control when not truncated", () => {
    renderHeader({ truncated: false });
    expect(
      screen.queryByRole("button", { name: "Load more" }),
    ).not.toBeInTheDocument();
  });

  it("delegates onLoadMore when the primary Load more button is clicked", async () => {
    const onLoadMore = vi.fn();
    renderHeader({ truncated: true, onLoadMore });
    await userEvent.click(screen.getByRole("button", { name: "Load more" }));
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("disables the Load more control while a continuation fetch is in flight", () => {
    renderHeader({ truncated: true, isLoadingMore: true });
    expect(screen.getByRole("button", { name: "Load more" })).toBeDisabled();
  });

  it("does not render 'Load all' as a top-level button (it lives in the menu)", () => {
    renderHeader({ truncated: true });
    expect(
      screen.queryByRole("button", { name: "Load all" }),
    ).not.toBeInTheDocument();
  });

  it("renders the view toggle as pressed icon buttons", async () => {
    const onModeChange = vi.fn();
    renderHeader({ mode: "table", onModeChange });
    const tableBtn = screen.getByRole("button", { name: "Table view" });
    const gridBtn = screen.getByRole("button", { name: "Grid view" });
    expect(tableBtn).toHaveAttribute("aria-pressed", "true");
    expect(gridBtn).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(gridBtn);
    expect(onModeChange).toHaveBeenCalledWith("grid");
  });
});

describe("FileBrowserHeader — upload control", () => {
  it("renders the primary Upload button and calls onUploadClick when clicked", async () => {
    const onUploadClick = vi.fn();
    renderHeader({ onUploadClick });
    const button = screen.getByRole("button", { name: "Upload" });
    expect(button).toBeInTheDocument();
    await userEvent.click(button);
    expect(onUploadClick).toHaveBeenCalledTimes(1);
  });

  it("does not render 'Upload folder' as a top-level button (it lives in the menu)", () => {
    renderHeader();
    expect(
      screen.queryByRole("button", { name: "Upload folder" }),
    ).not.toBeInTheDocument();
  });
});
