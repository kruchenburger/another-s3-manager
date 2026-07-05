import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { FileActions } from "@/components/FileBrowser/FileActions";

function renderActions(
  overrides: Partial<React.ComponentProps<typeof FileActions>> = {},
) {
  return render(
    <MantineProvider>
      <FileActions
        isDirectory={false}
        canPreview={false}
        onDownload={vi.fn()}
        onCopyUrl={vi.fn()}
        onDelete={vi.fn()}
        {...overrides}
      />
    </MantineProvider>,
  );
}

describe("FileActions delete enable/disable", () => {
  it("Delete is enabled by default", () => {
    renderActions();
    const btn = screen.getByLabelText("Delete");
    expect(btn).not.toBeDisabled();
  });

  it("Delete is disabled when disabled=true", () => {
    renderActions({ disabled: true });
    const btn = screen.getByLabelText("Delete");
    expect(btn).toBeDisabled();
  });

  it("disabled button carries the config-aware reason via data attribute", () => {
    renderActions({ disabled: true });
    const btn = screen.getByLabelText("Delete");
    expect(btn.getAttribute("data-disabled-reason")).toBe(
      "Deletion is disabled in the server config.",
    );
  });
});
