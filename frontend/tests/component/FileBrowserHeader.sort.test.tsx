import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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
          mode="grid"
          onModeChange={vi.fn()}
          onUploadClick={vi.fn()}
          onUploadFolderClick={vi.fn()}
          truncated={false}
          isLoadingMore={false}
          onLoadMore={vi.fn()}
          onLoadAll={vi.fn()}
          loadingAll={false}
          onStopLoadAll={vi.fn()}
          sortState={{ column: "name", direction: "asc" }}
          onSortChange={vi.fn()}
          {...overrides}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("FileBrowserHeader — grid sort control", () => {
  it("renders the sort control in grid mode", () => {
    renderHeader({ mode: "grid" });
    expect(
      screen.getByRole("combobox", { name: "Sort by" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sort ascending" }),
    ).toBeInTheDocument();
  });

  it("hides the sort control in table mode (headers serve there)", () => {
    renderHeader({ mode: "table" });
    expect(screen.queryByRole("combobox", { name: "Sort by" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Sort ascending" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Sort descending" })).toBeNull();
  });

  it("selecting a NEW column requests it ascending", async () => {
    const onSortChange = vi.fn();
    renderHeader({
      sortState: { column: "name", direction: "desc" },
      onSortChange,
    });
    // fireEvent.click (not userEvent.click) opens the Mantine 9 Combobox
    // dropdown reliably in jsdom — see SettingsPresignedTtl.test.tsx for the
    // same project-wide gotcha with Mantine Select in this test environment.
    fireEvent.click(screen.getByRole("combobox", { name: "Sort by" }));
    fireEvent.click(await screen.findByRole("option", { name: "Size" }));
    expect(onSortChange).toHaveBeenCalledWith({
      column: "size",
      direction: "asc",
    });
  });

  it("re-selecting the CURRENT column keeps its direction", async () => {
    const onSortChange = vi.fn();
    renderHeader({
      sortState: { column: "size", direction: "desc" },
      onSortChange,
    });
    fireEvent.click(screen.getByRole("combobox", { name: "Sort by" }));
    fireEvent.click(await screen.findByRole("option", { name: "Size" }));
    expect(onSortChange).toHaveBeenCalledWith({
      column: "size",
      direction: "desc",
    });
  });

  it("the direction toggle flips asc → desc", async () => {
    const onSortChange = vi.fn();
    renderHeader({
      sortState: { column: "modified", direction: "asc" },
      onSortChange,
    });
    await userEvent.click(
      screen.getByRole("button", { name: "Sort ascending" }),
    );
    expect(onSortChange).toHaveBeenCalledWith({
      column: "modified",
      direction: "desc",
    });
  });

  it("the direction toggle flips desc → asc", async () => {
    const onSortChange = vi.fn();
    renderHeader({
      sortState: { column: "modified", direction: "desc" },
      onSortChange,
    });
    await userEvent.click(
      screen.getByRole("button", { name: "Sort descending" }),
    );
    expect(onSortChange).toHaveBeenCalledWith({
      column: "modified",
      direction: "asc",
    });
  });
});
