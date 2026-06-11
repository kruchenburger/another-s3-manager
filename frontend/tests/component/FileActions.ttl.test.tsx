import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { FileActions } from "@/components/FileBrowser/FileActions";

function renderActions(over = {}) {
  const onCopyUrl = vi.fn();
  const onCopyUrlWithTtl = vi.fn();
  render(
    <MantineProvider>
      <FileActions
        isDirectory={false}
        canPreview={false}
        filename="f.txt"
        onDownload={vi.fn()}
        onCopyUrl={onCopyUrl}
        onCopyUrlWithTtl={onCopyUrlWithTtl}
        onDelete={vi.fn()}
        defaultTtl={3600}
        maxTtl={604800}
        {...over}
      />
    </MantineProvider>,
  );
  return { onCopyUrl, onCopyUrlWithTtl };
}

describe("FileActions TTL override", () => {
  it("plain click copies with default (one-click, no popover)", async () => {
    const { onCopyUrl, onCopyUrlWithTtl } = renderActions();
    await userEvent.click(screen.getByLabelText("Copy URL"));
    expect(onCopyUrl).toHaveBeenCalledTimes(1);
    expect(onCopyUrlWithTtl).not.toHaveBeenCalled();
  });

  it("shift+click opens the popover instead of copying", async () => {
    const { onCopyUrl } = renderActions();
    const icon = screen.getByLabelText("Copy URL");
    // userEvent.click({ shiftKey }) only passes shiftKey to pointer events, not to
    // React's synthetic MouseEvent. fireEvent.click with shiftKey:true reliably sets
    // e.shiftKey on the React handler, which is what the implementation checks.
    fireEvent.click(icon, { shiftKey: true });
    expect(onCopyUrl).not.toHaveBeenCalled();
    expect(await screen.findByText(/share link validity/i)).toBeInTheDocument();
  });
});
