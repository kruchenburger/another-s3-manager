import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import {
  FolderUploadHintModal,
  hasDismissedFolderUploadHint,
} from "@/components/Upload/FolderUploadHintModal";

const STORAGE_KEY = "upload:hintDismissed";

describe("FolderUploadHintModal — folder mode", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders folder-specific title, CTA, and 'don't show' checkbox unchecked by default", () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="folder" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    // Title only — the subtitle also contains "upload a folder" so we scope
    // to the heading role.
    expect(screen.getByRole("heading", { name: /upload a folder/i })).toBeInTheDocument();
    expect(screen.getByText(/browser folder picker/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open folder picker/i })).toBeInTheDocument();

    // Folder mode is the deliberate confirmation step — checkbox unchecked
    // so the modal keeps appearing until the user explicitly opts out.
    const checkbox = screen.getByLabelText(/don't show this again/i) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
  });

  it("calls onProceed when 'Open folder picker' is clicked", async () => {
    const onProceed = vi.fn();
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="folder" onClose={vi.fn()} onProceed={onProceed} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /open folder picker/i }));
    expect(onProceed).toHaveBeenCalledTimes(1);
  });

  it("does NOT persist the dismissed flag if 'Don't show again' is unchecked", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="folder" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /open folder picker/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(hasDismissedFolderUploadHint()).toBe(false);
  });

  it("persists the dismissed flag when 'Don't show again' is checked + proceed", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="folder" onClose={vi.fn()} onProceed={vi.fn()} />
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
        <FolderUploadHintModal opened mode="folder" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByLabelText(/don't show this again/i));
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("1");
  });
});

describe("FolderUploadHintModal — files mode", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders files-specific title, CTA, and 'don't show' checkbox CHECKED by default", () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="files" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    expect(screen.getByText(/upload files/i)).toBeInTheDocument();
    expect(screen.getByText(/browser file picker/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /choose files/i })).toBeInTheDocument();

    // Files mode is high-frequency — pre-check the dismiss so the user
    // sees the modal once and never again unless they explicitly opt back in.
    const checkbox = screen.getByLabelText(/don't show this again/i) as HTMLInputElement;
    expect(checkbox.checked).toBe(true);
  });

  it("persists the dismissed flag by default on proceed (checkbox pre-checked)", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="files" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    // Click proceed WITHOUT touching the checkbox — flag should still be set
    // because files mode pre-checks the dismiss.
    await userEvent.click(screen.getByRole("button", { name: /choose files/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe("1");
  });

  it("does NOT persist if user explicitly unchecks the dismiss (they want the reminder)", async () => {
    render(
      <MantineProvider>
        <FolderUploadHintModal opened mode="files" onClose={vi.fn()} onProceed={vi.fn()} />
      </MantineProvider>,
    );

    await userEvent.click(screen.getByLabelText(/don't show this again/i));
    await userEvent.click(screen.getByRole("button", { name: /choose files/i }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
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
