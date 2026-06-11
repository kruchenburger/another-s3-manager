import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { FileBrowserHeader } from "@/components/FileBrowser/FileBrowserHeader";

function renderHeader(over = {}) {
  const onBulkCopyUrl = vi.fn();
  render(
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
          selectedCount={2}
          onBulkDelete={vi.fn()}
          onBulkCopyUrl={onBulkCopyUrl}
          onUploadClick={vi.fn()}
          onUploadFolderClick={vi.fn()}
          objectCount={2}
          truncated={false}
          isLoadingMore={false}
          onLoadMore={vi.fn()}
          onLoadAll={vi.fn()}
          defaultTtl={3600}
          maxTtl={604800}
          {...over}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
  return { onBulkCopyUrl };
}

describe("FileBrowserHeader bulk Copy URLs TTL", () => {
  it("main button copies with default (no TTL arg)", async () => {
    const { onBulkCopyUrl } = renderHeader();
    await userEvent.click(screen.getByRole("button", { name: /copy urls \(2\)/i }));
    expect(onBulkCopyUrl).toHaveBeenCalledWith();
  });

  it("chevron opens the validity popover, Copy fires with chosen TTL", async () => {
    const { onBulkCopyUrl } = renderHeader();
    await userEvent.click(screen.getByLabelText(/choose link validity/i));
    // Wait for the TtlPopover dropdown to appear.
    const heading = await screen.findByText(/share link validity/i);
    expect(heading).toBeInTheDocument();
    // Find the Copy button by text — getByRole may not pierce the Popover portal ARIA tree.
    const copyBtn = Array.from(document.querySelectorAll("button")).find(
      (b) => b.textContent?.trim() === "Copy",
    );
    expect(copyBtn).toBeDefined();
    await userEvent.click(copyBtn!);
    expect(onBulkCopyUrl).toHaveBeenCalledWith(3600);
  });
});
