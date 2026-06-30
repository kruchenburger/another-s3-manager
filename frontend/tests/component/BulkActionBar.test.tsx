import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { BulkActionBar } from "@/components/FileBrowser/BulkActionBar";

type Props = React.ComponentProps<typeof BulkActionBar>;

function renderBar(props: Partial<Props> = {}) {
  const onClear = vi.fn();
  const onCopyUrls = vi.fn();
  const onDelete = vi.fn();
  render(
    <MantineProvider>
      <BulkActionBar
        count={3}
        onClear={onClear}
        onCopyUrls={onCopyUrls}
        onDelete={onDelete}
        {...props}
      />
    </MantineProvider>,
  );
  return { onClear, onCopyUrls, onDelete };
}

describe("BulkActionBar", () => {
  it("is hidden when nothing is selected", () => {
    renderBar({ count: 0 });
    expect(
      screen.queryByRole("region", { name: /bulk actions/i }),
    ).not.toBeInTheDocument();
  });

  it("shows the count and actions when items are selected", () => {
    renderBar({ count: 3 });
    expect(
      screen.getByRole("region", { name: /bulk actions/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("3 selected")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy URLs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
  });

  it("calls onClear from the clear (✕) button", () => {
    const { onClear } = renderBar({ count: 2 });
    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("clears the selection on Escape", () => {
    const { onClear } = renderBar({ count: 2 });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it("copies URLs with the server default (no explicit TTL) from the main button", () => {
    const { onCopyUrls } = renderBar({ count: 2 });
    fireEvent.click(screen.getByRole("button", { name: "Copy URLs" }));
    // Main button passes no TTL → server default.
    expect(onCopyUrls).toHaveBeenCalledWith();
  });

  it("opens the TTL popover from the chevron and copies with the chosen TTL", async () => {
    const user = userEvent.setup();
    const { onCopyUrls } = renderBar({ count: 2 }); // defaultTtl falls back to 3600
    await user.click(screen.getByLabelText(/choose link validity/i));
    expect(await screen.findByText(/share link validity/i)).toBeInTheDocument();
    // The TtlPopover's Copy button has no aria-label — only inner text.
    const copyBtn = Array.from(document.querySelectorAll("button")).find(
      (b) => b.textContent?.trim() === "Copy",
    );
    expect(copyBtn).toBeDefined();
    await user.click(copyBtn!);
    expect(onCopyUrls).toHaveBeenCalledWith(3600);
  });

  it("calls onDelete when Delete is clicked", () => {
    const { onDelete } = renderBar({ count: 2 });
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("renders Delete disabled (and inert) when deletion is disabled by config", () => {
    const { onDelete } = renderBar({ count: 2, disableDeletion: true });
    const del = screen.getByRole("button", { name: "Delete" });
    expect(del).toBeDisabled();
    fireEvent.click(del);
    expect(onDelete).not.toHaveBeenCalled();
  });

  it("on Escape closes the TTL popover first and keeps the selection", async () => {
    const user = userEvent.setup();
    const { onClear } = renderBar({ count: 2 });
    // Open the TTL popover via the chevron.
    await user.click(screen.getByLabelText(/choose link validity/i));
    expect(await screen.findByText(/share link validity/i)).toBeInTheDocument();
    // First Escape dismisses the popover — it must NOT clear the selection.
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClear).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.queryByText(/share link validity/i)).not.toBeInTheDocument(),
    );
  });

  it("disables Copy URLs (and the TTL chevron) while a copy is in flight", () => {
    renderBar({ count: 2, busy: true });
    expect(screen.getByRole("button", { name: "Copy URLs" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: /choose link validity/i }),
    ).toBeDisabled();
  });
});
