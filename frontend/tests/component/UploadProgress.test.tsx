import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { UploadProgress } from "@/components/Upload/UploadProgress";

describe("UploadProgress", () => {
  it("shows 'Uploading 3 files'", () => {
    render(
      <MantineProvider>
        <UploadProgress
          items={[
            { name: "a.txt", status: "uploading" },
            { name: "b.txt", status: "pending" },
            { name: "c.txt", status: "pending" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText(/Uploading 3 files/)).toBeInTheDocument();
    expect(screen.getByText(/0\/3/)).toBeInTheDocument();
  });

  it("shows error count when failures occur (settled includes done + errors)", () => {
    render(
      <MantineProvider>
        <UploadProgress
          items={[
            { name: "a.txt", status: "done" },
            { name: "b.txt", status: "error", error: "boom" },
            { name: "c.txt", status: "done" },
          ]}
        />
      </MantineProvider>,
    );
    // The counter shows settled / total, where settled = done + error + cancelled.
    // 2 done + 1 error = 3 settled out of 3 total.
    expect(screen.getByText(/3\/3.*1 failed/)).toBeInTheDocument();
  });

  it("uses singular for one file", () => {
    render(
      <MantineProvider>
        <UploadProgress items={[{ name: "x.txt", status: "uploading" }]} />
      </MantineProvider>,
    );
    expect(screen.getByText(/Uploading 1 file$/)).toBeInTheDocument();
  });

  it("renders the current file's name and percentage while uploading", () => {
    render(
      <MantineProvider>
        <UploadProgress
          items={[
            { name: "big-video.mp4", status: "uploading", progress: 42 },
            { name: "later.txt", status: "pending" },
          ]}
        />
      </MantineProvider>,
    );
    // Per-file progress for the big-video file — answers the user complaint
    // that a single big-file upload "just hangs at 0/1".
    expect(screen.getByText("big-video.mp4")).toBeInTheDocument();
    expect(screen.getByText("42%")).toBeInTheDocument();
  });

  it("renders the cancel button and invokes onCancel when clicked", async () => {
    const onCancel = vi.fn();
    render(
      <MantineProvider>
        <UploadProgress
          items={[{ name: "x.txt", status: "uploading", progress: 10 }]}
          onCancel={onCancel}
        />
      </MantineProvider>,
    );
    const button = screen.getByRole("button", { name: /cancel upload/i });
    expect(button).toBeInTheDocument();
    await userEvent.click(button);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("hides the cancel button when onCancel is not provided (final summary state)", () => {
    render(
      <MantineProvider>
        <UploadProgress items={[{ name: "x.txt", status: "done" }]} />
      </MantineProvider>,
    );
    expect(screen.queryByRole("button", { name: /cancel upload/i })).not.toBeInTheDocument();
  });
});
