import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import {
  FolderUploadHintModal,
  hasDismissedFolderUploadHint,
} from "@/components/Upload/FolderUploadHintModal";

const STORAGE_KEY = "upload:folderHintDismissed";

describe("FolderUploadHintModal", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders the two upload methods + cancel + proceed buttons", () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    expect(screen.getByText(/drag and drop/i)).toBeInTheDocument();
    expect(screen.getByText(/browser folder picker/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open folder picker/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("calls onProceed when 'Open folder picker' is clicked", async () => {
    const onProceed = vi.fn();
    render(
      <MantineProvider>
        <FolderUploadHintModal opened onClose={vi.fn()} onProceed={onProceed} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /open folder picker/i }));
    expect(onProceed).toHaveBeenCalledTimes(1);
  });

  it("does NOT persist the dismissed flag if 'Don't show again' is unchecked", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /open folder picker/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(hasDismissedFolderUploadHint()).toBe(false);
  });

  it("persists the dismissed flag when 'Don't show again' is checked + proceed", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByLabelText(/don't show this again/i));
    await userEvent.click(screen.getByRole("button", { name: /open folder picker/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("1");
    expect(hasDismissedFolderUploadHint()).toBe(true);
  });

  it("persists the dismissed flag even when user cancels (their preference still counts)", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByLabelText(/don't show this again/i));
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("1");
  });
});

describe("hasDismissedFolderUploadHint", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("returns false when nothing is stored", () => {
    expect(hasDismissedFolderUploadHint()).toBe(false);
  });

  it("returns true when the flag is '1'", () => {
    window.localStorage.setItem(STORAGE_KEY, "1");
    expect(hasDismissedFolderUploadHint()).toBe(true);
  });

  it("returns false for any other stored value (defensive)", () => {
    window.localStorage.setItem(STORAGE_KEY, "true");
    expect(hasDismissedFolderUploadHint()).toBe(false);
  });
});
