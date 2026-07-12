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

describe("FileBrowserHeader — sort control", () => {
  it("renders the sort control in grid mode", () => {
    renderHeader({ mode: "grid" });
    expect(
      screen.getByRole("combobox", { name: "Sort by" }),
    ).toBeInTheDocument();
    // Default sortState is {name, asc} — the toggle's accessible name is the
    // ACTION a click performs (Finding 6), so while ascending it reads
    // "Sort descending".
    expect(
      screen.getByRole("button", { name: "Sort descending" }),
    ).toBeInTheDocument();
  });

  it("in grid mode, renders the sort control WITHOUT the hidden-from-sm wrapper (always visible)", () => {
    renderHeader({ mode: "grid" });
    const combobox = screen.getByRole("combobox", { name: "Sort by" });
    expect(combobox.closest('[class*="mantine-hidden-from-sm"]')).toBeNull();
  });

  // Finding 4: Size/Modified table headers hide below `sm`, which would
  // otherwise leave Name as the only sortable column on a phone in the
  // default (table) view. The control must still be IN THE DOM in table
  // mode (queryBy* would wrongly report "absent" for a CSS-hidden element —
  // Mantine's hiddenFrom hides via a class, jsdom keeps the node), just
  // wrapped so it's only visible below `sm`.
  it("in table mode, renders the sort control wrapped in Mantine's hidden-from-sm visibility class (present in DOM, hidden at/above sm)", () => {
    renderHeader({ mode: "table" });
    const combobox = screen.getByRole("combobox", { name: "Sort by" });
    expect(combobox).toBeInTheDocument();
    expect(
      combobox.closest('[class*="mantine-hidden-from-sm"]'),
    ).not.toBeNull();

    const toggle = screen.getByRole("button", { name: "Sort descending" });
    expect(
      toggle.closest('[class*="mantine-hidden-from-sm"]'),
    ).not.toBeNull();
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
    // Finding 6: accessible name is the ACTION, not the state — while
    // ascending, the button reads "Sort descending".
    await userEvent.click(
      screen.getByRole("button", { name: "Sort descending" }),
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
    // Finding 6: while descending, the button reads "Sort ascending".
    await userEvent.click(
      screen.getByRole("button", { name: "Sort ascending" }),
    );
    expect(onSortChange).toHaveBeenCalledWith({
      column: "modified",
      direction: "asc",
    });
  });

  it("disables the Select and the direction toggle while sortDisabled is true, and a click does not fire onSortChange", async () => {
    const onSortChange = vi.fn();
    renderHeader({ mode: "grid", sortDisabled: true, onSortChange });

    const combobox = screen.getByRole("combobox", { name: "Sort by" });
    // Default sortState is {name, asc} → toggle reads "Sort descending".
    const toggle = screen.getByRole("button", { name: "Sort descending" });
    expect(combobox).toBeDisabled();
    expect(toggle).toBeDisabled();

    // A native disabled control does not dispatch click at all — this is
    // the behavior the sortDisabled prop relies on to make a busy click a
    // true no-op instead of a silently swallowed one.
    await userEvent.click(toggle);
    expect(onSortChange).not.toHaveBeenCalled();
  });

  it("keeps the Select and the direction toggle enabled when sortDisabled is false or absent", () => {
    // Discriminates against a constant-true assertion: this must be the
    // OPPOSITE outcome of the disabled test above for the same controls.
    renderHeader({ mode: "grid" });
    expect(
      screen.getByRole("combobox", { name: "Sort by" }),
    ).not.toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Sort descending" }),
    ).not.toBeDisabled();
  });
});
