import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
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

  it("omits the label when objectCount is undefined", () => {
    renderHeader();
    expect(screen.queryByText(/object/i)).not.toBeInTheDocument();
  });

  it("renders SegmentedControl for view picker (Task 13 — verifying §4.4 already done)", () => {
    const { container } = renderHeader();
    // Mantine's SegmentedControl exposes role="radiogroup".
    expect(container.querySelector('[role="radiogroup"]')).not.toBeNull();
  });
});
