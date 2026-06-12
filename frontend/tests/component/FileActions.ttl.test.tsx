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

  it("shift+click just copies (shift is no longer a popover modifier)", async () => {
    const { onCopyUrl } = renderActions();
    const icon = screen.getByLabelText("Copy URL");
    fireEvent.click(icon, { shiftKey: true });
    expect(onCopyUrl).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/share link validity/i)).not.toBeInTheDocument();
  });

  it("right-click opens the popover instead of copying", async () => {
    const { onCopyUrl } = renderActions();
    const icon = screen.getByLabelText("Copy URL");
    fireEvent.contextMenu(icon);
    expect(onCopyUrl).not.toHaveBeenCalled();
    expect(await screen.findByText(/share link validity/i)).toBeInTheDocument();
  });

  it("without onCopyUrlWithTtl, plain click still copies and no TTL hint shows", async () => {
    const { onCopyUrl } = renderActions({ onCopyUrlWithTtl: undefined });
    await userEvent.click(screen.getByLabelText("Copy URL"));
    expect(onCopyUrl).toHaveBeenCalledTimes(1);
  });
});
